from __future__ import annotations

from typing import Any

from .schemas import Candidate, EvaluateRequest, EvaluateResult, Weights
from .scoring import evaluate_candidate

_APPROVE_UTILITY = 0.76
_REPAIR_UTILITY = 0.58
_HIGH_RISK = 0.22


def evaluate_request(req: EvaluateRequest) -> EvaluateResult:
    weights = req.weights or Weights()

    scored: dict[str, Any] = {}
    chosen_id: str | None = None
    best = None
    best_score = float("-inf")
    best_rationale: list[str] = []
    risk_summary = {"catastrophic": 0.0, "regression": 0.0}

    for candidate_model in req.candidates:
        candidate = Candidate(
            id=candidate_model.id,
            diff=candidate_model.diff,
            strategy=candidate_model.strategy,
            explanation=candidate_model.explanation,
            metadata=dict(candidate_model.metadata),
        )
        score = evaluate_candidate(candidate, req.prompt, req.context, weights)
        scored[candidate.id] = score
        if score.utility > best_score:
            best_score = score.utility
            best = score
            chosen_id = candidate.id
            best_rationale = list(score.rationale)

    if best is None:
        return EvaluateResult(
            decision="reject",
            chosen_candidate=None,
            scores={},
            risk_summary={"catastrophic": 1.0, "regression": 1.0},
            best_rationale=["no candidates provided"],
            requires_verification=True,
            requires_repair=True,
        )

    risk_summary = {
        "catastrophic": best.catastrophic_risk,
        "regression": best.regression_risk,
    }

    if best.utility >= _APPROVE_UTILITY and best.catastrophic_risk <= _HIGH_RISK:
        decision = "approve"
        requires_repair = False
    elif best.utility >= _REPAIR_UTILITY:
        decision = "revise"
        requires_repair = True
    else:
        decision = "reject"
        requires_repair = True

    return EvaluateResult(
        decision=decision,
        chosen_candidate=chosen_id,
        scores=scored,
        risk_summary=risk_summary,
        best_rationale=best_rationale,
        requires_verification=True,
        requires_repair=requires_repair,
    )
