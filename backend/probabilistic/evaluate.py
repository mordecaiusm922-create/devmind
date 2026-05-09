from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .schemas import Candidate, EvaluateRequest, EvaluateResult, Weights
from .scoring import evaluate_candidate


@dataclass(frozen=True)
class EvaluationConfig:
    approve_utility: float = 0.78
    review_utility: float = 0.60
    reject_utility: float = 0.42

    min_security_approve: float = 0.82
    min_security_review: float = 0.65
    min_security_block: float = 0.50

    max_uncertainty_approve: float = 0.28
    max_uncertainty_review: float = 0.42

    max_catastrophic_risk_approve: float = 0.05
    max_catastrophic_risk_review: float = 0.12

    max_regression_risk_approve: float = 0.18
    max_regression_risk_review: float = 0.28

    verification_always_for_secure: bool = True
    verification_always_for_critical: bool = True


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, float(x)))


def _confidence_from_score(
    utility: float,
    security: float,
    uncertainty: float,
    catastrophic_risk: float,
    regression_risk: float,
    rationale_len: int,
) -> float:
    """
    Conservative confidence:
    - penalize uncertainty strongly
    - penalize high risk
    - slightly reward stronger evidence
    """
    evidence_bonus = min(0.05, rationale_len * 0.005)
    risk_penalty = 0.35 * catastrophic_risk + 0.20 * regression_risk
    raw = (
        0.45 * utility
        + 0.25 * security
        + 0.30 * (1.0 - uncertainty)
        - risk_penalty
        + evidence_bonus
    )
    return _clamp01(raw)


def _adjust_uncertainty(
    base_uncertainty: float,
    utility: float,
    security: float,
    catastrophic_risk: float,
    regression_risk: float,
    rationale_len: int,
) -> float:
    """
    Higher when:
    - utility is mediocre
    - security is weak
    - risk is high
    - evidence is thin
    """
    evidence_penalty = 0.04 if rationale_len <= 2 else 0.0
    risk_penalty = 0.10 * catastrophic_risk + 0.08 * regression_risk
    confidence_gap = 0.12 * (1.0 - utility) + 0.10 * (1.0 - security)
    raw = base_uncertainty + evidence_penalty + risk_penalty + confidence_gap
    return _clamp01(raw)


def _select_best_candidate(
    scored: dict[str, Any],
) -> tuple[str | None, Any | None]:
    if not scored:
        return None, None

    best_id = None
    best_score = float("-inf")
    best = None

    for cid, score in scored.items():
        # risk-adjusted utility with conservative ordering
        rau = score.utility - (
            0.60 * score.catastrophic_risk + 0.40 * score.regression_risk
        )
        tie_break = (
            rau,
            score.confidence,
            score.security,
            score.correctness,
            -score.uncertainty,
        )
        if tie_break > (best_score, -1, -1, -1, -1):
            best_score = rau
            best_id = cid
            best = score

    return best_id, best


def _decision_from_best(
    *,
    utility: float,
    security: float,
    uncertainty: float,
    catastrophic_risk: float,
    regression_risk: float,
    cfg: EvaluationConfig,
    mode: str | None = None,
) -> tuple[str, bool, bool]:
    """
    Returns:
      decision, requires_verification, requires_repair
    """
    mode = (mode or "").lower()
    sensitive_mode = mode in {"secure", "critical"}

    if security < cfg.min_security_block:
        return "reject", False, True

    if (
        utility >= cfg.approve_utility
        and security >= cfg.min_security_approve
        and uncertainty <= cfg.max_uncertainty_approve
        and catastrophic_risk <= cfg.max_catastrophic_risk_approve
        and regression_risk <= cfg.max_regression_risk_approve
        and not sensitive_mode
    ):
        return "approve", False, False

    if (
        utility >= cfg.review_utility
        or security < cfg.min_security_approve
        or uncertainty > cfg.max_uncertainty_approve
        or catastrophic_risk > cfg.max_catastrophic_risk_approve
        or regression_risk > cfg.max_regression_risk_approve
        or sensitive_mode
    ):
        requires_verification = (
            sensitive_mode
            or uncertainty > cfg.max_uncertainty_review
            or catastrophic_risk > cfg.max_catastrophic_risk_review
            or regression_risk > cfg.max_regression_risk_review
        )
        requires_repair = utility < cfg.approve_utility or security < cfg.min_security_approve
        return "needs_verification", requires_verification, requires_repair

    if utility >= cfg.reject_utility:
        return "revise", False, True

    return "reject", False, True


def evaluate_request(req: EvaluateRequest) -> EvaluateResult:
    cfg = EvaluationConfig()
    weights = req.weights or Weights()

    scored: dict[str, Any] = {}
    chosen_id: str | None = None
    best = None
    best_rationale: list[str] = []

    for candidate_model in req.candidates:
        candidate = Candidate(
            id=candidate_model.id,
            diff=candidate_model.diff,
            strategy=candidate_model.strategy,
            explanation=candidate_model.explanation,
            metadata=dict(candidate_model.metadata),
        )

        score = evaluate_candidate(candidate, req.prompt, req.context, weights)

        # Recalibrate the score a bit so it is less overconfident.
        rationale_len = len(score.rationale)
        adjusted_uncertainty = _adjust_uncertainty(
            base_uncertainty=score.uncertainty,
            utility=score.utility,
            security=score.security,
            catastrophic_risk=score.catastrophic_risk,
            regression_risk=score.regression_risk,
            rationale_len=rationale_len,
        )
        adjusted_confidence = _confidence_from_score(
            utility=score.utility,
            security=score.security,
            uncertainty=adjusted_uncertainty,
            catastrophic_risk=score.catastrophic_risk,
            regression_risk=score.regression_risk,
            rationale_len=rationale_len,
        )

        # Replace with more conservative values while preserving the rest.
        score.uncertainty = adjusted_uncertainty
        score.confidence = adjusted_confidence

        scored[candidate.id] = score

    if not scored:
        return EvaluateResult(
            decision="reject",
            chosen_candidate=None,
            scores={},
            risk_summary={"catastrophic": 1.0, "regression": 1.0, "uncertainty": 1.0},
            best_rationale=["no candidates provided"],
            requires_verification=True,
            requires_repair=True,
        )

    chosen_id, best = _select_best_candidate(scored)

    if best is None:
        return EvaluateResult(
            decision="reject",
            chosen_candidate=None,
            scores={},
            risk_summary={"catastrophic": 1.0, "regression": 1.0, "uncertainty": 1.0},
            best_rationale=["no valid best candidate"],
            requires_verification=True,
            requires_repair=True,
        )

    best_rationale = list(best.rationale)

    decision, requires_verification, requires_repair = _decision_from_best(
        utility=best.utility,
        security=best.security,
        uncertainty=best.uncertainty,
        catastrophic_risk=best.catastrophic_risk,
        regression_risk=best.regression_risk,
        cfg=cfg,
        mode=getattr(req, "mode", None),
    )

    # Stronger safety behavior for secure/critical modes
    mode = (getattr(req, "mode", "") or "").lower()
    if mode in {"secure", "critical"}:
        requires_verification = True

    risk_summary = {
        "catastrophic": best.catastrophic_risk,
        "regression": best.regression_risk,
        "uncertainty": best.uncertainty,
    }

    return EvaluateResult(
        decision=decision,
        chosen_candidate=chosen_id,
        scores=scored,
        risk_summary=risk_summary,
        best_rationale=best_rationale,
        requires_verification=requires_verification,
        requires_repair=requires_repair,
    )