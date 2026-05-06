from __future__ import annotations

from .evaluate import evaluate_request
from .schemas import CandidateModel, ContextModel, EvaluateRequest, GenerateRequest, GenerateResult


def _strategy_templates(mode: str) -> list[tuple[str, str]]:
    if mode == "secure":
        return [
            ("secure-minimal", "Minimal patch with explicit validation, sanitization, and no new attack surface."),
            ("secure-robust", "Robust fix prioritizing authentication, idempotency, and safe defaults."),
            ("secure-defense", "Defense-in-depth change adding guards, assertions, and fail-closed behavior."),
        ]
    if mode == "fast":
        return [
            ("fast-path", "Fast path optimization with minimal control-flow impact and reduced overhead."),
            ("bounded-fast", "Low-latency change preserving hot path behavior and avoiding broad refactors."),
            ("cache-optimized", "Cache or memoization oriented patch with careful invalidation."),
        ]
    if mode == "robust":
        return [
            ("robust-fix", "Robust fix emphasizing invariants, transactional safety, and idempotency."),
            ("robust-refactor", "Refactor that isolates state, reduces coupling, and improves testability."),
            ("robust-safe", "Conservative solution with explicit guards, retries, and rollback-friendly structure."),
        ]
    return [
        ("minimal-patch", "Small patch that addresses the symptom while keeping the diff narrow."),
        ("balanced-fix", "Balanced fix improving correctness, safety, and maintainability."),
        ("refactor-safe", "Moderate refactor that improves clarity without expanding the blast radius."),
    ]


def _candidate_diff(prompt: str, context: ContextModel, strategy: str, explanation: str, idx: int) -> str:
    files = context.files[:3]
    file_hint = files[0] if files else "target_file.py"
    lower = prompt.lower()
    if any(k in lower for k in ("race", "concurrency", "thread", "lock")):
        body = f"""diff --git a/{file_hint} b/{file_hint}
--- a/{file_hint}
+++ b/{file_hint}
@@
- # unsafe critical section
+ # {strategy}: protect critical section with explicit synchronization
+ # TODO: replace with repo-specific lock / atomic primitive
"""
    elif any(k in lower for k in ("payment", "billing", "charge", "invoice")):
        body = f"""diff --git a/{file_hint} b/{file_hint}
--- a/{file_hint}
+++ b/{file_hint}
@@
- process_payment(payload)
+ process_payment_with_idempotency(payload)
+ # {strategy}: enforce deduplication and rollback-safe semantics
"""
    elif any(k in lower for k in ("auth", "token", "secret", "login")):
        body = f"""diff --git a/{file_hint} b/{file_hint}
--- a/{file_hint}
+++ b/{file_hint}
@@
- logger.info(user_token)
+ logger.info("auth event")
+ # {strategy}: avoid secret exposure and validate inputs
"""
    elif any(k in lower for k in ("performance", "latency", "slow", "optimize")):
        body = f"""diff --git a/{file_hint} b/{file_hint}
--- a/{file_hint}
+++ b/{file_hint}
@@
- for item in items:
-     compute(item)
+ # {strategy}: batch or short-circuit hot-path work
+ for item in items:
+     compute(item)
"""
    else:
        body = f"""diff --git a/{file_hint} b/{file_hint}
--- a/{file_hint}
+++ b/{file_hint}
@@
- old_logic()
+ new_logic()
+ # {strategy}: conservative placeholder patch for evaluation pipeline
"""
    return body.strip() + f"\n# explanation: {explanation}\n# variant: {idx}"


def generate_request(req: GenerateRequest) -> GenerateResult:
    templates = _strategy_templates(req.mode)
    candidates: list[CandidateModel] = []
    for idx in range(max(1, req.n_candidates)):
        strategy, explanation = templates[idx % len(templates)]
        diff = _candidate_diff(req.prompt, req.context, strategy, explanation, idx)
        candidates.append(
            CandidateModel(
                id=f"c{idx+1}",
                diff=diff,
                strategy=strategy,
                explanation=explanation,
                metadata={"mode": req.mode, "rank": idx + 1},
            )
        )

    eval_req = EvaluateRequest(
        prompt=req.prompt,
        context=req.context,
        candidates=candidates,
        weights=req.weights,
    )
    evaluation = evaluate_request(eval_req)
    return GenerateResult(prompt=req.prompt, candidates=candidates, evaluation=evaluation)
