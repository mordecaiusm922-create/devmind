# backend/policy.py
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Mapping, Optional


class Action(str, Enum):
    APPROVE = "approve"
    REVIEW = "review"
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
class PolicyThresholds:
    approve_utility: float = 0.75
    review_utility: float = 0.60
    reject_utility: float = 0.40

    min_security_approve: float = 0.80
    min_security_review: float = 0.65
    min_security_block: float = 0.50

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
class PolicyDecision:
    action: Action
    merge_blocker: bool
    reason: str
    candidate: Optional[str] = None
    requires_verification: bool = False
    requires_repair: bool = False
    sensitive_mode: bool = False
    policy_flags: dict[str, bool] = field(default_factory=dict)
    thresholds: dict[str, float] = field(default_factory=dict)


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if obj is None:
        return default
    if isinstance(obj, Mapping):
        return obj.get(key, default)
    return getattr(obj, key, default)


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


def _has_any_violations(selected: Any) -> bool:
    violations = _get(selected, "violations", []) or []
    critical = _get(selected, "critical_violations", []) or []
    return len(violations) > 0 or len(critical) > 0


def _risk_summary_value(summary: Any, key: str, default: float = 0.0) -> float:
    value = _get(summary, key, default)
    try:
        return float(value)
    except Exception:
        return default


def decide_policy(
    evaluation: Any,
    selected: Any = None,
    *,
    mode: str | RiskMode | None = None,
    thresholds: Optional[PolicyThresholds] = None,
) -> PolicyDecision:
    """
    Central policy gate for DevMind.

    evaluation:
      Can be dict or object with fields:
      - decision
      - risk_summary
      - requires_verification
      - requires_repair
      - chosen_candidate

    selected:
      Can be dict/object with fields:
      - candidate
      - utility
      - security
      - uncertainty
      - verified
      - critical_violations
      - violations
      - risk_adjusted_utility
    """
    th = thresholds or PolicyThresholds()
    rm = _as_mode(mode)
    sensitive_mode = _is_sensitive_mode(rm)

    decision_raw = _get(evaluation, "decision", None)
    if isinstance(decision_raw, Enum):
        decision_raw = decision_raw.value
    decision_raw = str(decision_raw).lower() if decision_raw is not None else "unknown"

    risk_summary = _get(evaluation, "risk_summary", {}) or {}
    selected = selected or _get(evaluation, "selected", None) or _get(evaluation, "best", None)

    utility = _get(selected, "risk_adjusted_utility", None)
    if utility is None:
        utility = _get(selected, "utility", None)
    utility = float(utility) if utility is not None else 0.0

    security = _get(selected, "security", None)
    security = float(security) if security is not None else 0.0

    uncertainty = _get(selected, "uncertainty", None)
    uncertainty = float(uncertainty) if uncertainty is not None else 1.0

    verified = bool(_get(selected, "verified", False))
    candidate_id = _get(selected, "candidate", None)

    catastrophic = _risk_summary_value(risk_summary, "catastrophic", 0.0)
    regression = _risk_summary_value(risk_summary, "regression", 0.0)
    risk_uncertainty = _risk_summary_value(risk_summary, "uncertainty", uncertainty)

    critical_violations = _has_critical_violations(selected)
    any_violations = _has_any_violations(selected)

    # Core policy flags
    low_security = security < th.low_security_penalty_threshold
    security_block = security < th.min_security_block
    security_review = security < th.min_security_approve
    security_sensitive = any(x >= th.min_security_review for x in [security])

    risk_block = catastrophic > th.max_catastrophic_risk_review or regression > th.max_regression_risk_review
    high_risk_for_approval = catastrophic > th.max_catastrophic_risk_approve or regression > th.max_regression_risk_approve

    uncertainty_block = uncertainty > th.max_uncertainty_review
    uncertainty_review = uncertainty > th.max_uncertainty_approve

    # Hard stops
    if critical_violations and th.critical_violation_block:
        return PolicyDecision(
            action=Action.REJECT,
            merge_blocker=True,
            reason="Critical violations present; merge blocked.",
            candidate=candidate_id,
            requires_verification=False,
            requires_repair=True,
            sensitive_mode=sensitive_mode,
            policy_flags={
                "critical_violations": True,
                "low_security": low_security,
                "uncertainty_high": uncertainty_block,
            },
            thresholds=asdict(th),
        )

    if security_block:
        return PolicyDecision(
            action=Action.REJECT,
            merge_blocker=True,
            reason="Security below hard block threshold.",
            candidate=candidate_id,
            requires_verification=False,
            requires_repair=True,
            sensitive_mode=sensitive_mode,
            policy_flags={
                "critical_violations": False,
                "low_security": True,
                "uncertainty_high": uncertainty_block,
            },
            thresholds=asdict(th),
        )

    if sensitive_mode and not verified and th.verification_required_for_sensitive_modes:
        return PolicyDecision(
            action=Action.NEEDS_VERIFICATION,
            merge_blocker=True,
            reason="Candidate passes policy checks but safety-sensitive mode requires human or test verification.",
            candidate=candidate_id,
            requires_verification=True,
            requires_repair=False,
            sensitive_mode=True,
            policy_flags={
                "critical_violations": critical_violations,
                "low_security": low_security,
                "needs_runtime_verify": True,
            },
            thresholds=asdict(th),
        )

    # Main decision ladder
    if (
        utility >= th.approve_utility
        and security >= th.min_security_approve
        and not uncertainty_review
        and not high_risk_for_approval
        and verified
    ):
        return PolicyDecision(
            action=Action.APPROVE,
            merge_blocker=False,
            reason="High utility, acceptable risk, and verification passed.",
            candidate=candidate_id,
            requires_verification=False,
            requires_repair=False,
            sensitive_mode=sensitive_mode,
            policy_flags={
                "critical_violations": False,
                "low_security": low_security,
                "uncertainty_high": False,
            },
            thresholds=asdict(th),
        )

    if (
        utility >= th.review_utility
        or security_review
        or uncertainty_review
        or risk_block
        or any_violations
    ):
        merge_blocker = sensitive_mode or risk_block or uncertainty_review or any_violations
        return PolicyDecision(
            action=Action.NEEDS_VERIFICATION,
            merge_blocker=merge_blocker,
            reason="Candidate is promising but requires further verification or risk review.",
            candidate=candidate_id,
            requires_verification=True,
            requires_repair=not verified and (utility < th.approve_utility or security_review),
            sensitive_mode=sensitive_mode,
            policy_flags={
                "critical_violations": False,
                "low_security": low_security,
                "uncertainty_high": uncertainty_review,
                "risk_high": risk_block,
            },
            thresholds=asdict(th),
        )

    if utility >= th.reject_utility:
        return PolicyDecision(
            action=Action.NEEDS_REPAIR,
            merge_blocker=sensitive_mode or uncertainty_block,
            reason="Candidate is not strong enough to approve; repair is recommended.",
            candidate=candidate_id,
            requires_verification=False,
            requires_repair=True,
            sensitive_mode=sensitive_mode,
            policy_flags={
                "critical_violations": False,
                "low_security": low_security,
                "uncertainty_high": uncertainty_block,
            },
            thresholds=asdict(th),
        )

    return PolicyDecision(
        action=Action.REJECT,
        merge_blocker=True,
        reason="Utility too low or risk too high for approval.",
        candidate=candidate_id,
        requires_verification=False,
        requires_repair=True,
        sensitive_mode=sensitive_mode,
        policy_flags={
            "critical_violations": critical_violations,
            "low_security": low_security,
            "uncertainty_high": uncertainty_block,
            "risk_high": risk_block,
        },
        thresholds=asdict(th),
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


class PolicyEngine:
    """
    Small wrapper so your pipeline can hold a policy object.
    """

    def __init__(self, thresholds: Optional[PolicyThresholds] = None):
        self.thresholds = thresholds or PolicyThresholds()

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
        )

    def block_merge(
        self,
        evaluation: Any,
        selected: Any = None,
        *,
        mode: str | RiskMode | None = None,
    ) -> bool:
        return self.decide(evaluation, selected, mode=mode).merge_blocker