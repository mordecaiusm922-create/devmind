from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Mapping, Optional


class Action(str, Enum):
    APPROVE = "approve"
    REVIEW = "review"
    REVISE = "revise"
    REJECT = "reject"
    NEEDS_VERIFICATION = "needs_verification"
    NEEDS_REPAIR = "needs_repair"
    ABSTAIN = "abstain"


class RiskMode(str, Enum):
    FAST = "fast"
    BALANCED = "balanced"
    SECURE = "secure"
    ROBUST = "robust"
    CRITICAL = "critical"


@dataclass(frozen=True)
class ApprovalBands:
    """
    Auto-approval bands.
    These are intentionally conservative for approval, but not so conservative
    that clean benchmark cases get turned into false positives.
    """

    auto_approve_utility: float = 0.70
    auto_approve_security: float = 0.85
    auto_approve_behavior_preservation: float = 0.80
    auto_approve_runtime_confidence: float = 0.80
    auto_approve_max_uncertainty: float = 0.25

    review_min_utility: float = 0.55
    review_min_security: float = 0.70
    review_min_behavior_preservation: float = 0.70
    review_min_runtime_confidence: float = 0.65

    reject_min_utility: float = 0.35
    reject_min_security: float = 0.45

    sensitive_domains: tuple[str, ...] = ("auth", "sql", "secrets", "ci_cd", "infra", "payments")


@dataclass(frozen=True)
class PolicyThresholds:
    approve_utility: float = 0.70
    review_utility: float = 0.55
    reject_utility: float = 0.35

    min_security_approve: float = 0.85
    min_security_review: float = 0.70
    min_security_block: float = 0.45

    min_behavior_approve: float = 0.80
    min_behavior_review: float = 0.70

    min_runtime_confidence_approve: float = 0.80
    min_runtime_confidence_review: float = 0.65

    max_uncertainty_approve: float = 0.30
    max_uncertainty_review: float = 0.45

    max_catastrophic_risk_approve: float = 0.08
    max_catastrophic_risk_review: float = 0.18

    max_regression_risk_approve: float = 0.20
    max_regression_risk_review: float = 0.32

    critical_violation_block: bool = True
    verification_required_for_sensitive_modes: bool = True
    low_security_penalty_threshold: float = 0.45


@dataclass(frozen=True)
class RuntimeConfidenceDetail:
    score: float
    signals: dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"score": round(self.score, 4), "signals": dict(self.signals)}

    @classmethod
    def from_evaluation(cls, ev: Any) -> "RuntimeConfidenceDetail":
        runtime = _get(ev, "runtime_evidence", {}) or _get(ev, "runtime", {}) or {}
        sandbox = _get(ev, "sandbox_evidence", {}) or _get(ev, "sandbox", {}) or {}
        probabilistic = _get(ev, "probabilistic", {}) or {}
        evaluation = _get(ev, "evaluation", ev) or {}

        syntax_valid = bool(_get(runtime, "syntax_valid", _get(sandbox, "syntax_valid", True)))
        imports_resolved = bool(_get(runtime, "imports_resolved", _get(sandbox, "imports_resolved", True)))
        no_new_exceptions = bool(_get(runtime, "no_new_exceptions", _get(sandbox, "no_new_exceptions", True)))
        tests_passed = bool(_get(runtime, "tests_passed", _get(sandbox, "test_passed", False)))
        sandbox_clean = not bool(_get(sandbox, "static_issues", []) or _get(sandbox, "bandit_issues", []))
        dependency_evidence = bool(_get(probabilistic, "dependency_evidence", _get(runtime, "dependency_evidence", False)))
        stable_outputs = bool(_get(runtime, "stable_outputs", _get(evaluation, "stable_outputs", False)))

        signals = {
            "syntax_valid": syntax_valid,
            "imports_resolved": imports_resolved,
            "no_new_exceptions": no_new_exceptions,
            "tests_passed": tests_passed,
            "sandbox_clean": sandbox_clean,
            "dependency_evidence": dependency_evidence,
            "stable_outputs": stable_outputs,
        }

        # Kolmogorov-style compression: only a small number of independent
        # signals should move the posterior materially.
        weights = {
            "syntax_valid": 0.10,
            "imports_resolved": 0.10,
            "no_new_exceptions": 0.16,
            "tests_passed": 0.28,
            "sandbox_clean": 0.18,
            "dependency_evidence": 0.08,
            "stable_outputs": 0.08,
        }
        score = sum(weights[name] for name, ok in signals.items() if ok)
        return cls(score=round(min(1.0, score), 4), signals=signals)


@dataclass(frozen=True)
class PolicyDecision:
    action: Action
    merge_blocker: bool
    reason: str
    reasons: list[str] = field(default_factory=list)
    candidate: Optional[str] = None
    requires_verification: bool = False
    requires_repair: bool = False
    sensitive_mode: bool = False
    policy_flags: dict[str, bool] = field(default_factory=dict)
    thresholds: dict[str, Any] = field(default_factory=dict)
    runtime_confidence_detail: Optional[dict[str, Any]] = None


@dataclass(frozen=True)
class DeploymentPolicyResult:
    action: str
    merge_blocker: bool
    reason: str
    violations: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[dict[str, Any]] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)


# ----------------------------------------------------------------------------
# Basic helpers
# ----------------------------------------------------------------------------


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if obj is None:
        return default
    if isinstance(obj, Mapping):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except Exception:
        return default


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, float(x)))


def _as_mode(mode: str | RiskMode | None) -> RiskMode:
    if isinstance(mode, RiskMode):
        return mode
    if not mode:
        return RiskMode.BALANCED
    try:
        return RiskMode(str(mode).lower())
    except Exception:
        return RiskMode.BALANCED


def _is_sensitive_mode(mode: RiskMode) -> bool:
    return mode in {RiskMode.SECURE, RiskMode.CRITICAL}


def _has_critical_violations(selected: Any) -> bool:
    violations = _get(selected, "critical_violations", []) or []
    return bool(violations)


def _threshold_reason(name: str, got: float, need: float, direction: str = ">=") -> str:
    return f"{name} (got={got:.2f}, need{direction}{need:.2f})"


def _unique(seq: list[str]) -> list[str]:
    return list(dict.fromkeys(seq))


# ----------------------------------------------------------------------------
# Domain inference with low false-positive bias
# ----------------------------------------------------------------------------


def _detect_domain(selected: Any, evaluation: Any) -> str | None:
    tags = {str(t).lower() for t in (_get(selected, "risk_tags", []) or [])}
    text = " ".join(
        [
            str(_get(selected, "candidate", "") or ""),
            str(_get(evaluation, "prompt", "") or ""),
            str(_get(evaluation, "review_focus", "") or ""),
            str(_get(evaluation, "attack_path", "") or ""),
        ]
    ).lower()

    domain_map = {
        "auth": {"auth", "oauth", "jwt", "session", "credential", "rbac", "sso", "saml"},
        "sql": {"sql", "db", "database", "migration", "orm", "query"},
        "payments": {"payments", "payment", "billing", "checkout"},
        "infra": {"infra", "terraform", "kubernetes", "docker", "ci_cd", "helm", "iam"},
        "secrets": {"secret", "secrets", "token", "credential", "private key"},
    }

    for domain, markers in domain_map.items():
        if tags & markers:
            return domain
        if any(marker in text for marker in markers):
            return domain
    return None


# ----------------------------------------------------------------------------
# Evidence / risk aggregation
# ----------------------------------------------------------------------------


def _get_risk_summary(evaluation: Any) -> dict[str, Any]:
    risk_summary = _get(evaluation, "risk_summary", {}) or {}
    if not isinstance(risk_summary, Mapping):
        return {}
    return dict(risk_summary)


def _extract_candidate_metrics(selected: Any) -> dict[str, float]:
    utility = _get(selected, "risk_adjusted_utility", None)
    if utility is None:
        utility = _get(selected, "utility", 0.0)

    security = _get(selected, "security", 0.0)
    behavior = _get(selected, "behavior_preservation", _get(selected, "correctness", 0.85))
    runtime = _get(selected, "runtime_confidence", _get(selected, "confidence", 0.80))
    uncertainty = _get(selected, "uncertainty", 0.5)

    return {
        "utility": _clamp01(_as_float(utility, 0.0)),
        "security": _clamp01(_as_float(security, 0.0)),
        "behavior_preservation": _clamp01(_as_float(behavior, 0.85)),
        "runtime_confidence": _clamp01(_as_float(runtime, 0.80)),
        "uncertainty": _clamp01(_as_float(uncertainty, 0.5)),
    }


def _compute_exploitability(
    *,
    selected: Any,
    evaluation: Any,
    runtime_detail: RuntimeConfidenceDetail,
    domain: str | None,
    sensitive_mode: bool,
) -> dict[str, Any]:
    risk_summary = _get_risk_summary(evaluation)
    candidate = _extract_candidate_metrics(selected)

    catastrophic = _clamp01(_as_float(_get(risk_summary, "catastrophic", 0.0), 0.0))
    regression = _clamp01(_as_float(_get(risk_summary, "regression", 0.0), 0.0))
    blast = _clamp01(_as_float(_get(risk_summary, "blast_radius", 0.0), 0.0))
    reachability = _clamp01(_as_float(_get(risk_summary, "reachability", 0.0), 0.0))

    # Conservative but not hyper-sensitive. This should not by itself doom clean cases.
    domain_weight = {
        "auth": 0.08,
        "sql": 0.06,
        "payments": 0.10,
        "infra": 0.08,
        "secrets": 0.12,
    }.get(domain or "", 0.0)

    p_exploit = max(
        0.0,
        min(
            1.0,
            max(
                1.0 - candidate["security"],
                candidate["uncertainty"] * 0.60,
                catastrophic,
                regression,
                blast,
                reachability,
                1.0 - runtime_detail.score,
                domain_weight if sensitive_mode else domain_weight * 0.5,
            ),
        ),
    )

    return {
        "p_exploit": _clamp01(p_exploit),
        "catastrophic": catastrophic,
        "regression": regression,
        "blast_radius": blast,
        "reachability": reachability,
        "domain_weight": domain_weight,
    }


def _score_exploitability(exploitability: dict[str, Any]) -> int:
    return int(round(_clamp01(_as_float(exploitability.get("p_exploit"), 0.0)) * 100))


# ----------------------------------------------------------------------------
# Decision rules
# ----------------------------------------------------------------------------


def _build_auto_approve_failures(
    *,
    utility: float,
    security: float,
    behavior_preservation: float,
    runtime_confidence: float,
    uncertainty: float,
    bands: ApprovalBands,
    domain: str | None,
    sensitive_mode: bool,
    exploitability: dict[str, Any],
) -> list[str]:
    reasons: list[str] = []

    if utility < bands.auto_approve_utility:
        reasons.append(_threshold_reason("utility_below_auto_approve_threshold", utility, bands.auto_approve_utility))
    if security < bands.auto_approve_security:
        reasons.append(_threshold_reason("security_below_auto_approve_threshold", security, bands.auto_approve_security))
    if behavior_preservation < bands.auto_approve_behavior_preservation:
        reasons.append(_threshold_reason("behavior_preservation_below_auto_approve_threshold", behavior_preservation, bands.auto_approve_behavior_preservation))
    if runtime_confidence < bands.auto_approve_runtime_confidence:
        reasons.append(_threshold_reason("runtime_confidence_below_auto_approve_threshold", runtime_confidence, bands.auto_approve_runtime_confidence))
    if uncertainty > bands.auto_approve_max_uncertainty:
        reasons.append(f"uncertainty_above_auto_approve_threshold (got={uncertainty:.2f}, max={bands.auto_approve_max_uncertainty:.2f})")

    # Domain alone should not block; only mark for review when other evidence exists.
    if domain and domain in bands.sensitive_domains and (security < 0.90 or uncertainty > 0.20):
        reasons.append(f"sensitive_domain_needs_extra_review (domain={domain})")
    if sensitive_mode:
        reasons.append("sensitive_mode_requires_review")
    if _clamp01(_as_float(exploitability.get("p_exploit"), 0.0)) > 0.18:
        reasons.append(f"exploitability_above_auto_approve_threshold (p={_as_float(exploitability.get('p_exploit'), 0.0):.2f})")

    return reasons


# ----------------------------------------------------------------------------
# Public policy API
# ----------------------------------------------------------------------------


def decide_policy(
    evaluation: Any,
    selected: Any = None,
    *,
    mode: str | RiskMode | None = None,
    thresholds: Optional[PolicyThresholds] = None,
    bands: Optional[ApprovalBands] = None,
) -> PolicyDecision:
    th = thresholds or PolicyThresholds()
    bd = bands or ApprovalBands()
    rm = _as_mode(mode)
    sensitive_mode = _is_sensitive_mode(rm)

    selected = selected or _get(evaluation, "selected", None) or _get(evaluation, "best", None)
    if selected is None:
        return PolicyDecision(
            action=Action.ABSTAIN,
            merge_blocker=False,
            reason="No candidate selected.",
            reasons=["no_selected_candidate"],
            sensitive_mode=sensitive_mode,
            thresholds=asdict(th),
        )

    candidate = _extract_candidate_metrics(selected)
    verified = bool(_get(selected, "verified", False))
    candidate_id = _get(selected, "candidate", None)
    repair_converged = bool(_get(evaluation, "repair_converged", True))
    critical_violations = _has_critical_violations(selected)
    domain = _detect_domain(selected, evaluation)

    runtime_detail = RuntimeConfidenceDetail.from_evaluation(evaluation)
    if runtime_detail.score == 0.0 and candidate["runtime_confidence"] > 0.0:
        runtime_detail = RuntimeConfidenceDetail(
            score=candidate["runtime_confidence"],
            signals={
                "syntax_valid": True,
                "imports_resolved": True,
                "no_new_exceptions": candidate["runtime_confidence"] >= 0.80,
                "tests_passed": candidate["runtime_confidence"] >= 0.90,
                "sandbox_clean": candidate["runtime_confidence"] >= 0.80,
                "dependency_evidence": candidate["runtime_confidence"] >= 0.85,
                "stable_outputs": candidate["runtime_confidence"] >= 0.80,
            },
        )

    exploitability = _compute_exploitability(
        selected=selected,
        evaluation=evaluation,
        runtime_detail=runtime_detail,
        domain=domain,
        sensitive_mode=sensitive_mode,
    )
    exploit_score = _score_exploitability(exploitability)

    utility = candidate["utility"]
    security = candidate["security"]
    behavior_preservation = candidate["behavior_preservation"]
    uncertainty = candidate["uncertainty"]
    catastrophic = _as_float(exploitability.get("catastrophic"), 0.0)
    regression = _as_float(exploitability.get("regression"), 0.0)

    # 1) Hard reject only for strong evidence.
    if critical_violations and th.critical_violation_block:
        return PolicyDecision(
            action=Action.REJECT,
            merge_blocker=True,
            reason="Critical violations present; merge blocked.",
            reasons=["critical_violations_detected"],
            candidate=candidate_id,
            requires_repair=True,
            sensitive_mode=sensitive_mode,
            policy_flags={"critical_violations": True},
            thresholds=asdict(th),
            runtime_confidence_detail=runtime_detail.to_dict(),
        )

    if exploit_score >= 85:
        return PolicyDecision(
            action=Action.REJECT,
            merge_blocker=True,
            reason="Exploitability is too high for deployment.",
            reasons=[f"exploitability_score={exploit_score}", "attack_chain_too_practical"],
            candidate=candidate_id,
            requires_repair=True,
            sensitive_mode=sensitive_mode,
            policy_flags={"high_exploitability": True},
            thresholds=asdict(th),
            runtime_confidence_detail=runtime_detail.to_dict(),
        )

    if utility < th.reject_utility and security < th.min_security_block:
        return PolicyDecision(
            action=Action.REJECT,
            merge_blocker=True,
            reason="Utility and security are both too low for a safe change.",
            reasons=[
                _threshold_reason("utility_below_reject_threshold", utility, th.reject_utility),
                _threshold_reason("security_below_block_threshold", security, th.min_security_block),
            ],
            candidate=candidate_id,
            requires_repair=True,
            sensitive_mode=sensitive_mode,
            policy_flags={"low_utility": True, "low_security": True},
            thresholds=asdict(th),
            runtime_confidence_detail=runtime_detail.to_dict(),
        )

    if security < th.min_security_block and exploit_score >= 60:
        return PolicyDecision(
            action=Action.REJECT,
            merge_blocker=True,
            reason="Security below hard block threshold.",
            reasons=[_threshold_reason("security_below_block_threshold", security, th.min_security_block)],
            candidate=candidate_id,
            requires_repair=True,
            sensitive_mode=sensitive_mode,
            policy_flags={"low_security": True},
            thresholds=asdict(th),
            runtime_confidence_detail=runtime_detail.to_dict(),
        )

    if sensitive_mode and not repair_converged:
        return PolicyDecision(
            action=Action.REVISE,
            merge_blocker=True,
            reason="Repair loop did not converge in safety-sensitive mode.",
            reasons=["repair_not_converged_in_sensitive_mode"],
            candidate=candidate_id,
            requires_repair=True,
            sensitive_mode=True,
            policy_flags={"repair_not_converged": True},
            thresholds=asdict(th),
            runtime_confidence_detail=runtime_detail.to_dict(),
        )

    if sensitive_mode and th.verification_required_for_sensitive_modes and not verified:
        return PolicyDecision(
            action=Action.NEEDS_VERIFICATION,
            merge_blocker=True,
            reason="Safety-sensitive mode requires verification.",
            reasons=[f"sensitive_mode_requires_verification (mode={rm.value})"],
            candidate=candidate_id,
            requires_verification=True,
            sensitive_mode=True,
            policy_flags={"needs_runtime_verify": True},
            thresholds=asdict(th),
            runtime_confidence_detail=runtime_detail.to_dict(),
        )

    # 2) Fast allow for clean, well-supported cases.
    clean_allow = (
        verified
        and repair_converged
        and not sensitive_mode
        and utility >= bd.auto_approve_utility
        and security >= bd.auto_approve_security
        and behavior_preservation >= bd.auto_approve_behavior_preservation
        and runtime_detail.score >= bd.auto_approve_runtime_confidence
        and uncertainty <= bd.auto_approve_max_uncertainty
        and exploit_score <= 18
        and catastrophic <= th.max_catastrophic_risk_approve
        and regression <= th.max_regression_risk_approve
        and not domain in bd.sensitive_domains
    )

    if clean_allow:
        return PolicyDecision(
            action=Action.APPROVE,
            merge_blocker=False,
            reason="Clean candidate with strong evidence; approval bands passed.",
            reasons=["all_auto_approve_bands_passed"],
            candidate=candidate_id,
            requires_verification=False,
            requires_repair=False,
            sensitive_mode=False,
            policy_flags={
                "critical_violations": False,
                "uncertainty_high": False,
                "low_security": security < th.low_security_penalty_threshold,
            },
            thresholds=asdict(th),
            runtime_confidence_detail=runtime_detail.to_dict(),
        )

    # 3) Review when the candidate is promising but evidence is incomplete.
    auto_failures = _build_auto_approve_failures(
        utility=utility,
        security=security,
        behavior_preservation=behavior_preservation,
        runtime_confidence=runtime_detail.score,
        uncertainty=uncertainty,
        bands=bd,
        domain=domain,
        sensitive_mode=sensitive_mode,
        exploitability=exploitability,
    )

    review_ready = (
        utility >= th.review_utility
        and security >= th.min_security_review
        and behavior_preservation >= th.min_behavior_approve
        and runtime_detail.score >= th.min_runtime_confidence_review
        and uncertainty <= th.max_uncertainty_review
        and exploit_score < 60
        and catastrophic <= th.max_catastrophic_risk_review
        and regression <= th.max_regression_risk_review
    )

    if review_ready:
        return PolicyDecision(
            action=Action.REVIEW,
            merge_blocker=sensitive_mode,
            reason="Strong candidate, but not yet safe enough for auto-approve.",
            reasons=auto_failures if auto_failures else ["below_auto_approve_thresholds"],
            candidate=candidate_id,
            requires_verification=True,
            requires_repair=False,
            sensitive_mode=sensitive_mode,
            policy_flags={
                "low_security": security < th.low_security_penalty_threshold,
                "uncertainty_high": uncertainty > th.max_uncertainty_approve,
                "risk_high": exploit_score >= 40,
            },
            thresholds=asdict(th),
            runtime_confidence_detail=runtime_detail.to_dict(),
        )

    # 4) Need repair when there is a reasonable path to improve.
    fixable = (
        utility >= th.reject_utility
        or security >= th.min_security_block
        or behavior_preservation >= th.min_behavior_review
        or runtime_detail.score >= th.min_runtime_confidence_review
    )
    if fixable:
        return PolicyDecision(
            action=Action.NEEDS_REPAIR,
            merge_blocker=sensitive_mode or not repair_converged,
            reason="Candidate is not strong enough; repair is required.",
            reasons=auto_failures if auto_failures else ["needs_more_evidence_or_stronger_semantics"],
            candidate=candidate_id,
            requires_repair=True,
            sensitive_mode=sensitive_mode,
            policy_flags={
                "low_security": security < th.low_security_penalty_threshold,
                "repair_not_converged": not repair_converged,
                "exploitability_high": exploit_score >= 40,
            },
            thresholds=asdict(th),
            runtime_confidence_detail=runtime_detail.to_dict(),
        )

    # 5) Final default: review is safer than reject for ambiguous, non-critical cases.
    if has_critical_or_high_signal(selected, exploit_score, security, utility):
        return PolicyDecision(
            action=Action.REVIEW,
            merge_blocker=sensitive_mode,
            reason="Ambiguous but non-critical candidate requires review.",
            reasons=["ambiguous_evidence", f"exploitability_score={exploit_score}"],
            candidate=candidate_id,
            requires_verification=True,
            requires_repair=False,
            sensitive_mode=sensitive_mode,
            policy_flags={
                "critical_violations": critical_violations,
                "low_security": security < th.low_security_penalty_threshold,
                "risk_high": exploit_score >= 40,
            },
            thresholds=asdict(th),
            runtime_confidence_detail=runtime_detail.to_dict(),
        )

    return PolicyDecision(
        action=Action.APPROVE,
        merge_blocker=False,
        reason="No blocking findings and the candidate is within acceptable bounds.",
        reasons=["no_blocking_signals", "allow_by_default_low_risk"],
        candidate=candidate_id,
        requires_verification=False,
        requires_repair=False,
        sensitive_mode=sensitive_mode,
        policy_flags={
            "critical_violations": False,
            "low_security": security < th.low_security_penalty_threshold,
            "risk_high": False,
        },
        thresholds=asdict(th),
        runtime_confidence_detail=runtime_detail.to_dict(),
    )


def has_critical_or_high_signal(selected: Any, exploit_score: int, security: float, utility: float) -> bool:
    if _has_critical_violations(selected):
        return True
    if exploit_score >= 60:
        return True
    if security < 0.50 and utility < 0.45:
        return True
    return False


def should_block_merge(
    evaluation: Any,
    selected: Any = None,
    *,
    mode: str | RiskMode | None = None,
    thresholds: Optional[PolicyThresholds] = None,
) -> bool:
    return decide_policy(evaluation, selected, mode=mode, thresholds=thresholds).merge_blocker


def to_dict(decision: PolicyDecision) -> dict[str, Any]:
    return asdict(decision)


# ----------------------------------------------------------------------------
# Deployment policy layer
# ----------------------------------------------------------------------------


def evaluate_deployment_policy(
    *,
    representation: dict[str, Any],
    runtime_evidence: dict[str, Any],
    risk: dict[str, Any],
    selected: dict[str, Any] | None = None,
    mode: str | RiskMode | None = None,
) -> DeploymentPolicyResult:
    selected = selected or {}
    mode_value = _as_mode(mode).value
    violations: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []

    execution = representation.get("execution_evidence") or {}
    for check in execution.get("checks", []) or []:
        name = str(check.get("name") or "")
        status = str(check.get("status") or "")
        if status == "fail" and name in {
            "terraform_public_cidr",
            "terraform_public_storage",
            "terraform_public_database",
            "terraform_iam_wildcard",
            "terraform_destructive_change",
            "gha_untrusted_secret_access",
            "gha_curl_bash",
        }:
            violations.append(
                {
                    "policy": name,
                    "severity": "critical",
                    "action": "BLOCK",
                    "evidence": check.get("evidence"),
                    "file": check.get("file"),
                }
            )
        elif status in {"warn", "fail"}:
            warnings.append(
                {
                    "policy": name,
                    "severity": "medium" if status == "warn" else "high",
                    "action": "REVIEW",
                    "evidence": check.get("evidence"),
                    "file": check.get("file"),
                }
            )

    selected_candidate = str(selected.get("candidate") or "")
    runtime_items = (
        [runtime_evidence[selected_candidate]]
        if selected_candidate and selected_candidate in (runtime_evidence or {})
        else list((runtime_evidence or {}).values())
    )

    for check in runtime_items:
        if check.get("status") == "failed":
            violations.append(
                {
                    "policy": "runtime_evidence_failed",
                    "severity": "high",
                    "action": "REVIEW",
                    "evidence": check.get("failed_checks", []),
                    "file": check.get("filename"),
                }
            )

    blast = representation.get("blast_radius") or {}
    if str(blast.get("level")) == "critical" and mode_value in {"secure", "critical"}:
        warnings.append(
            {
                "policy": "critical_blast_radius",
                "severity": "high",
                "action": "REVIEW",
                "evidence": blast.get("reasons", []),
            }
        )

    if risk.get("score", 0) >= 90:
        warnings.append(
            {
                "policy": "risk_score_threshold",
                "severity": "high",
                "action": "REVIEW",
                "evidence": f"risk.score={risk.get('score')}",
            }
        )

    if selected.get("critical_violations"):
        violations.append(
            {
                "policy": "candidate_critical_violations",
                "severity": "critical",
                "action": "BLOCK",
                "evidence": selected.get("critical_violations", []),
            }
        )

    if any(v.get("action") == "BLOCK" for v in violations):
        first = violations[0]
        return DeploymentPolicyResult(
            action="BLOCK",
            merge_blocker=True,
            reason=f"{first.get('policy')} violated deployment policy.",
            violations=violations,
            warnings=warnings,
            evidence={"mode": mode_value, "execution_status": execution.get("status"), "risk": risk},
        )

    if violations or warnings:
        first = (violations or warnings)[0]
        return DeploymentPolicyResult(
            action="REVIEW",
            merge_blocker=mode_value in {"secure", "critical"} and bool(violations),
            reason=f"{first.get('policy')} requires verification before deployment.",
            violations=violations,
            warnings=warnings,
            evidence={"mode": mode_value, "execution_status": execution.get("status"), "risk": risk},
        )

    return DeploymentPolicyResult(
        action="ALLOW",
        merge_blocker=False,
        reason="No deployment policy violations detected.",
        violations=[],
        warnings=[],
        evidence={"mode": mode_value, "execution_status": execution.get("status"), "risk": risk},
    )


class PolicyEngine:
    def __init__(
        self,
        thresholds: Optional[PolicyThresholds] = None,
        bands: Optional[ApprovalBands] = None,
    ) -> None:
        self.thresholds = thresholds or PolicyThresholds()
        self.bands = bands or ApprovalBands()

    def decide(
        self,
        evaluation: Any,
        selected: Any = None,
        *,
        mode: str | RiskMode | None = None,
    ) -> PolicyDecision:
        return decide_policy(
            evaluation=evaluation,
            selected=selected,
            mode=mode,
            thresholds=self.thresholds,
            bands=self.bands,
        )

    def block_merge(self, evaluation: Any, selected: Any = None, *, mode=None) -> bool:
        return self.decide(evaluation, selected, mode=mode).merge_blocker

    def evaluate_deployment(self, *, representation, runtime_evidence, risk, selected=None, mode=None):
        return evaluate_deployment_policy(
            representation=representation,
            runtime_evidence=runtime_evidence,
            risk=risk,
            selected=selected,
            mode=mode,
        )
