from __future__ import annotations

from .evaluate import evaluate_request
from .generate import _candidate_diff  # internal helper
from .schemas import CandidateModel, EvaluateRequest, RepairRequest, RepairResult
from .verifier import verify_candidate


def _repair_diff(diff: str, rationale: list[str], prompt: str, strategy: str, idx: int) -> str:
    t = (diff + "\n" + "\n".join(rationale)).lower()
    patched = diff
    if any(k in t for k in ("secret logging", "possible secret logging", "secret")):
        patched += "\n# repair: redact or remove sensitive logs"
    if any(k in t for k in ("race", "concurrency", "lock", "mutex", "atomic")):
        patched += "\n# repair: tighten critical-section protection"
    if any(k in t for k in ("latency", "performance", "slow", "throughput")):
        patched += "\n# repair: preserve hot-path performance constraints"
    if any(k in t for k in ("idempotent", "dedupe", "double payment", "payments")):
        patched += "\n# repair: ensure idempotency / deduplication"
    return patched + f"\n# repair_iteration: {idx}"


def repair_request(req: RepairRequest) -> RepairResult:
    candidate = req.candidate or CandidateModel(
        id="seed",
        diff=_candidate_diff(req.prompt, req.context, req.mode, "seed candidate", 0),
        strategy=f"{req.mode}-seed",
        explanation="Seed candidate created for repair loop",
    )

    history: list[dict[str, object]] = []
    best_eval = None

    for i in range(1, max(1, req.max_iters) + 1):
        eval_req = EvaluateRequest(
            prompt=req.prompt,
            context=req.context,
            candidates=[candidate],
            weights=req.weights,
        )
        evaluation = evaluate_request(eval_req)
        best_eval = evaluation
        score = evaluation.scores[candidate.id]
        verification = verify_candidate(candidate.diff, ["race_condition_mitigation", "no_data_leak"])
        history.append(
            {
                "iteration": i,
                "decision": evaluation.decision,
                "utility": score.utility,
                "confidence": score.confidence,
                "risk": evaluation.risk_summary,
                "verified": verification.verified,
                "violations": verification.violations,
            }
        )

        if evaluation.decision == "approve" and verification.verified:
            return RepairResult(
                converged=True,
                iterations=i,
                candidate=candidate,
                evaluation=evaluation,
                history=history,
            )

        candidate = CandidateModel(
            id=f"repair_{i}",
            diff=_repair_diff(candidate.diff, evaluation.best_rationale + verification.evidence, req.prompt, req.mode, i),
            strategy=f"{req.mode}-repaired-{i}",
            explanation="Iteratively repaired candidate based on evaluation feedback",
            metadata={"iteration": i},
        )

    assert best_eval is not None
    return RepairResult(
        converged=False,
        iterations=max(1, req.max_iters),
        candidate=candidate,
        evaluation=best_eval,
        history=history,
    )
