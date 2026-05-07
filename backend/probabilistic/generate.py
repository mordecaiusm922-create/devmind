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
    import os
    from groq import Groq

    client = Groq(api_key=os.getenv("GROQ_API_KEY"))

    file_context = ""
    if context.files:
        file_context = f"Files involved: {', '.join(context.files[:3])}"
    if context.repo:
        file_context += f"\nRepo: {context.repo}"

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {
                "role": "system",
                "content": (
                    f"You are a security-focused code fix generator. "
                    f"Strategy: {strategy}. {explanation} "
                    f"Output ONLY a valid unified diff in this exact format:\n"
                    f"diff --git a/filename b/filename\n"
                    f"--- a/filename\n"
                    f"+++ b/filename\n"
                    f"@@ ... @@\n"
                    f"- removed line\n"
                    f"+ added line\n"
                    f"No explanations, no markdown, no extra text. Only the diff."
                ),
            },
            {
                "role": "user",
                "content": f"Fix this issue: {prompt}\n\n{file_context}",
            },
        ],
        max_tokens=600,
        temperature=0.2,
    )

    diff = response.choices[0].message.content.strip()
    return f"{diff}\n# strategy: {strategy}\n# variant: {idx}"

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
