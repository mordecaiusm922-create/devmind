# backend/policy.py
from __future__ import annotations

from dataclasses import dataclass, field, asdict
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
    Hard bands for auto-approval.
    Auto-approve only if all pass.
    """

    auto_approve_utility: float = 0.75
    auto_approve_security: float = 0.95
    auto_approve_behavior_preservation: float = 0.90
    auto_approve_runtime_confidence: float = 0.95
    auto_approve_max_uncertainty: float = 0.10

    review_min_utility: float = 0.60
    review_min_security: float = 0.80
    review_min_behavior_preservation: float = 0.80
    review_min_runtime_confidence: float = 0.75

    reject_min_utility: float = 0.40
    reject_min_security: float = 0.50

    sensitive_domains: tuple[str, ...] = ("auth", "sql", "secrets", "ci_cd", "infra", "payments")


@dataclass(frozen=True)
class PolicyThresholds:
    approve_utility: float = 0.75
    review_utility: float = 0.60
    reject_utility: float = 0.40

    min_security_approve: float = 0.80
    min_security_review: float = 0.65
    min_security_block: float = 0.50

    min_behavior_approve: float = 0.80
    min_behavior_review: float = 0.70

    min_runtime_confidence_approve: float = 0.80
    min_runtime_confidence_review: float = 0.65

    max_uncertainty_approve: float = 0.30
    max_uncertainty_review: float = 0.45

    max_catastrophic_risk_approve: float = 0.05
    max_catastrophic_risk_review: float = 0.12

    max_regression_risk_approve: float = 0.18
    max_regression_risk_review: float = 0.28

    critical_violation_block: bool = True
    verification_required_for_sensitive_modes: bool = True
    low_security_penalty_threshold: float = 0.50


@dataclass(frozen=True)
class RuntimeConfidenceDetail:
    score: float
    signals: dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 4),
            "signals": self.signals,
        }

    @classmethod
    def from_evaluation(cls, ev: Any) -> "RuntimeConfidenceDetail":
        """
        Build a confidence detail from runtime/sandbox evidence.
        Preference order:
        - explicit runtime_evidence
        - explicit sandbox_evidence
        - explicit runtime fields
        """
        runtime = _get(ev, "runtime_evidence", {}) or _get(ev, "runtime", {}) or {}
        sandbox = _get(ev, "sandbox_evidence", {}) or _get(ev, "sandbox", {}) or {}
        probabilistic = _get(ev, "probabilistic", {}) or {}

        syntax_valid = bool(
            _get(runtime, "syntax_valid", _get(sandbox, "syntax_valid", True))
        )
        tests_passed = bool(
            _get(runtime, "tests_passed", _get(sandbox, "test_passed", False))
        )
        sandbox_clean = not bool(
            _get(sandbox, "static_issues", []) or _get(sandbox, "bandit_issues", [])
        )
        imports_resolved = bool(_get(runtime, "imports_resolved", True))
        no_new_exceptions = bool(_get(runtime, "no_new_exceptions", True))
        dependency_evidence = bool(
            _get(probabilistic, "dependency_evidence", _get(runtime, "dependency_evidence", False))
        )

        signals = {
            "syntax_valid": syntax_valid,
            "tests_passed": tests_passed,
            "sandbox_clean": sandbox_clean,
            "imports_resolved": imports_resolved,
            "no_new_exceptions": no_new_exceptions,
            "dependency_evidence": dependency_evidence,
        }

        weights = {
            "syntax_valid": 0.12,
            "tests_passed": 0.30,
            "sandbox_clean": 0.20,
            "imports_resolved": 0.10,
            "no_new_exceptions": 0.14,
            "dependency_evidence": 0.14,
        }
        score = sum(weights[k] for k, v in signals.items() if v)
        return cls(score=round(score, 4), signals=signals)


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
    return len(violations) > 0


def _detect_domain(selected: Any, evaluation: Any) -> str | None:
    tags = set(str(t).lower() for t in (_get(selected, "risk_tags", []) or []))
    text = " ".join(
        [
            str(_get(selected, "candidate", "") or ""),
            str(_get(evaluation, "prompt", "") or ""),
            str(_get(evaluation, "review_focus", "") or ""),
        ]
    ).lower()

    domain_map = {
        "auth": {"auth", "oauth", "jwt", "session", "credential"},
        "sql": {"sql", "db", "database", "migration", "orm"},
        "payments": {"payments", "payment", "billing", "checkout"},
        "infra": {"infra", "terraform", "kubernetes", "docker", "ci_cd"},
        "secrets": {"secret", "secrets", "token", "credential"},
    }

    for domain, markers in domain_map.items():
        if tags & markers:
            return domain
        if any(m in text for m in markers):
            return domain
    return None


def _threshold_reason(name: str, got: float, need: float, direction: str = ">=") -> str:
    return f"{name} (got={got:.2f}, need{direction}{need:.2f})"


def _build_auto_approve_failures(
    *,
    utility: float,
    security: float,
    behavior_preservation: float,
    runtime_confidence: float,
    uncertainty: float,
    bands: ApprovalBands,
    domain: str | None,
) -> list[str]:
    reasons: list[str] = []

    if utility < bands.auto_approve_utility:
        reasons.append(_threshold_reason("utility_below_auto_approve_threshold", utility, bands.auto_approve_utility))
    if security < bands.auto_approve_security:
        reasons.append(_threshold_reason("security_below_auto_approve_threshold", security, bands.auto_approve_security))
    if behavior_preservation < bands.auto_approve_behavior_preservation:
        reasons.append(
            _threshold_reason(
                "behavior_preservation_below_auto_approve_threshold",
                behavior_preservation,
                bands.auto_approve_behavior_preservation,
            )
        )
    if runtime_confidence < bands.auto_approve_runtime_confidence:
        reasons.append(
            _threshold_reason(
                "runtime_confidence_below_auto_approve_threshold",
                runtime_confidence,
                bands.auto_approve_runtime_confidence,
            )
        )
    if uncertainty > bands.auto_approve_max_uncertainty:
        reasons.append(
            f"uncertainty_above_auto_approve_threshold (got={uncertainty:.2f}, max={bands.auto_approve_max_uncertainty:.2f})"
        )
    if domain and domain in bands.sensitive_domains:
        reasons.append(f"sensitive_domain_requires_human_review (domain={domain})")

    return reasons


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

    risk_summary = _get(evaluation, "risk_summary", {}) or {}

    utility = _get(selected, "risk_adjusted_utility", None)
    if utility is None:
        utility = _get(selected, "utility", 0.0)
    utility = _as_float(utility, 0.0)

    security = _as_float(_get(selected, "security", 0.0), 0.0)
    uncertainty = _as_float(_get(selected, "uncertainty", 1.0), 1.0)
    verified = bool(_get(selected, "verified", False))
    candidate_id = _get(selected, "candidate", None)

    behavior_preservation = _as_float(
        _get(selected, "behavior_preservation", _get(selected, "correctness", 0.85)),
        0.85,
    )

    runtime_raw = _get(selected, "runtime_confidence", None)
    if runtime_raw is None:
        runtime_raw = _get(selected, "confidence", 0.80)
    runtime_raw = _as_float(runtime_raw, 0.80)

    runtime_detail = RuntimeConfidenceDetail.from_evaluation(evaluation)
    if runtime_detail.score == 0.0:
        runtime_detail = RuntimeConfidenceDetail(
            score=runtime_raw,
            signals={
                "syntax_valid": True,
                "tests_passed": runtime_raw >= 0.95,
                "sandbox_clean": runtime_raw >= 0.80,
                "imports_resolved": True,
                "no_new_exceptions": runtime_raw >= 0.85,
                "dependency_evidence": runtime_raw >= 0.90,
            },
        )

    catastrophic = _as_float(_get(risk_summary, "catastrophic", 0.0), 0.0)
    regression = _as_float(_get(risk_summary, "regression", 0.0), 0.0)
    repair_converged = bool(_get(evaluation, "repair_converged", True))
    critical_violations = _has_critical_violations(selected)
    domain = _detect_domain(selected, evaluation)

    low_security = security < th.low_security_penalty_threshold
    security_block = security < th.min_security_block
    utility_reject = utility < th.reject_utility
    risk_block = catastrophic > th.max_catastrophic_risk_review or regression > th.max_catastrophic_risk_review

    # 1) Hard reject conditions
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

    if utility_reject:
        return PolicyDecision(
            action=Action.REJECT,
            merge_blocker=True,
            reason="Utility too low for a safe change.",
            reasons=[_threshold_reason("utility_below_reject_threshold", utility, th.reject_utility)],
            candidate=candidate_id,
            requires_repair=True,
            sensitive_mode=sensitive_mode,
            policy_flags={"low_utility": True},
            thresholds=asdict(th),
            runtime_confidence_detail=runtime_detail.to_dict(),
        )

    if security_block:
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

    if sensitive_mode and not verified and th.verification_required_for_sensitive_modes:
        reasons = [f"sensitive_mode_requires_verification (mode={rm.value})"]
        if domain:
            reasons.append(f"sensitive_domain_detected (domain={domain})")
        return PolicyDecision(
            action=Action.NEEDS_VERIFICATION,
            merge_blocker=True,
            reason="Safety-sensitive mode requires human or test verification.",
            reasons=reasons,
            candidate=candidate_id,
            requires_verification=True,
            sensitive_mode=True,
            policy_flags={"needs_runtime_verify": True},
            thresholds=asdict(th),
            runtime_confidence_detail=runtime_detail.to_dict(),
        )

    # 2) Auto-approve only when everything is strong and consistent
    auto_failures = _build_auto_approve_failures(
        utility=utility,
        security=security,
        behavior_preservation=behavior_preservation,
        runtime_confidence=runtime_detail.score,
        uncertainty=uncertainty,
        bands=bd,
        domain=domain,
    )

    if (
        not auto_failures
        and verified
        and repair_converged
        and not sensitive_mode
        and domain not in bd.sensitive_domains
    ):
        return PolicyDecision(
            action=Action.APPROVE,
            merge_blocker=False,
            reason="All approval bands passed; verification confirmed.",
            reasons=["all_auto_approve_bands_passed"],
            candidate=candidate_id,
            requires_verification=False,
            requires_repair=False,
            sensitive_mode=False,
            policy_flags={
                "critical_violations": False,
                "uncertainty_high": False,
                "low_security": low_security,
            },
            thresholds=asdict(th),
            runtime_confidence_detail=runtime_detail.to_dict(),
        )

    # 3) REVIEW if it is promising but not yet auto-approve safe
    review_ready = (
        utility >= th.review_utility
        and security >= th.min_security_review
        and behavior_preservation >= th.min_behavior_approve
        and runtime_detail.score >= th.min_runtime_confidence_review
        and uncertainty <= th.max_uncertainty_review
        and not risk_block
    )

    if review_ready:
        review_reasons = auto_failures if auto_failures else ["below_auto_approve_thresholds"]
        if verified and repair_converged:
            return PolicyDecision(
                action=Action.REVIEW,
                merge_blocker=False if not sensitive_mode else True,
                reason="Strong candidate, but not yet safe enough for auto-approve.",
                reasons=review_reasons,
                candidate=candidate_id,
                requires_verification=True,
                requires_repair=False,
                sensitive_mode=sensitive_mode,
                policy_flags={
                    "low_security": low_security,
                    "uncertainty_high": uncertainty > th.max_uncertainty_approve,
                    "risk_high": risk_block,
                },
                thresholds=asdict(th),
                runtime_confidence_detail=runtime_detail.to_dict(),
            )

    # 4) NEEDS_REPAIR if it is still fixable but not strong enough
    fixable = utility >= th.reject_utility or security >= th.min_security_block or behavior_preservation >= th.min_behavior_review
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
                "low_security": low_security,
                "repair_not_converged": not repair_converged,
            },
            thresholds=asdict(th),
            runtime_confidence_detail=runtime_detail.to_dict(),
        )

    # 5) Default reject
    return PolicyDecision(
        action=Action.REJECT,
        merge_blocker=True,
        reason="Utility too low or risk too high for approval.",
        reasons=[
            *auto_failures,
            _threshold_reason("utility_below_approve_threshold", utility, th.approve_utility),
        ],
        candidate=candidate_id,
        requires_repair=True,
        sensitive_mode=sensitive_mode,
        policy_flags={
            "critical_violations": critical_violations,
            "low_security": low_security,
            "risk_high": risk_block,
        },
        thresholds=asdict(th),
        runtime_confidence_detail=runtime_detail.to_dict(),
    )


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

    if risk.get("score", 0) >= 85:
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
            merge_blocker=mode_value in {"secure", "critical"} or bool(violations),
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
    ):
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