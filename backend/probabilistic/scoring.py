from __future__ import annotations

import re
from typing import Tuple

from .schemas import Candidate, ContextModel, Weights, CandidateScores

_SECURITY_PATTERNS = (
    (re.compile(r"\b(secret|api_key|token|password|passwd|pwd)\b", re.I), "sensitive_data"),
    (re.compile(r"\b(eval|exec|__import__)\s*\(", re.I), "code_injection"),
    (re.compile(r"verify\s*=\s*False", re.I), "tls_disabled"),
    (re.compile(r"logging\.(info|debug|warning|error|exception).{0,80}(token|secret|password|key)", re.I | re.S), "secret_logging"),
    (re.compile(r"\b(requests?\.|httpx\.|urllib\.|fetch\()", re.I), "network_access"),
    (re.compile(r"\b(auth|oauth|jwt|session|credential)\b", re.I), "auth_surface"),
    (re.compile(r"\b(payment|billing|checkout|transfer|charge)\b", re.I), "financial_logic"),
    (re.compile(r"\b(lock|mutex|atomic|transaction|idempotent|dedupe|queue|semaphore)\b", re.I), "concurrency_mitigation"),
)

_RISK_FILES = (
    (re.compile(r"auth|oauth|jwt|token|session|credential|secret", re.I), 0.22, "auth"),
    (re.compile(r"payment|billing|checkout|invoice|charge", re.I), 0.30, "payments"),
    (re.compile(r"migrat|schema|sql|ddl|db|orm|prisma|sqlalchemy", re.I), 0.20, "db"),
    (re.compile(r"lock|mutex|async|await|thread|queue|worker|concurr", re.I), 0.16, "concurrency"),
    (re.compile(r"infra|k8s|helm|terraform|docker|deploy|pipeline", re.I), 0.18, "infra"),
    (re.compile(r"test|spec", re.I), -0.05, "tests"),
)

_MITIGATION_TERMS = {
    "idempotent", "idempotency", "transaction", "atomic", "lock", "mutex",
    "dedupe", "validate", "sanitize", "escape", "parameterize", "rollback",
    "retry", "backoff", "boundary", "assert", "invariant", "contract",
}

_PERF_TERMS = {
    "cache", "batch", "stream", "memoize", "index", "amortized", "constant",
    "linear", "reduce", "minimize", "profile", "optimize", "short-circuit",
}

_ALIGN_TERMS = {
    "fix", "repair", "safe", "secure", "robust", "minimal", "refactor", "preserve",
    "latency", "performance", "maintainability", "compatibility", "invariant",
}


def _clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))


def _norm_text(*parts: str) -> str:
    return "\n".join(p for p in parts if p).lower()


def _token_set(text: str) -> set[str]:
    return set(re.findall(r"[a-zA-Z_][a-zA-Z0-9_]+", text.lower()))


def _diff_stats(diff: str) -> dict[str, int]:
    added = sum(1 for line in diff.splitlines() if line.startswith("+") and not line.startswith("+++"))
    removed = sum(1 for line in diff.splitlines() if line.startswith("-") and not line.startswith("---"))
    files = len(re.findall(r"^diff --git", diff, re.M)) or 1
    return {"added": added, "removed": removed, "files": files, "churn": added + removed}


def risk_tags(candidate: Candidate, context: ContextModel) -> list[str]:
    text = _norm_text(candidate.diff, candidate.explanation, candidate.strategy, context.history, " ".join(context.files))
    tags: list[str] = []
    for rx, tag in _SECURITY_PATTERNS:
        if rx.search(text):
            tags.append(tag)
    return sorted(set(tags))


def correctness_score(candidate: Candidate, context: ContextModel, prompt: str) -> tuple[float, list[str]]:
    text = _norm_text(candidate.diff, candidate.explanation, candidate.strategy)
    tokens = _token_set(text)
    evidence: list[str] = []

    score = 0.52
    stats = _diff_stats(candidate.diff)

    if any(t in tokens for t in {"test", "tests", "unit", "integration", "property"}):
        score += 0.12
        evidence.append("mentions tests")
    if any(t in tokens for t in {"assert", "invariant", "contract", "precondition", "postcondition"}):
        score += 0.10
        evidence.append("mentions invariants/contracts")
    if any(t in tokens for t in {"atomic", "transaction", "idempotent", "lock", "mutex"}):
        score += 0.08
        evidence.append("uses concurrency mitigation")
    if stats["churn"] > 250:
        score -= 0.08
        evidence.append("large churn")
    if stats["churn"] <= 20:
        score += 0.05
        evidence.append("small patch")
    if any(x in prompt.lower() for x in {"race", "concurrency", "payment", "auth", "security"}):
        score += 0.06
    return _clamp(score), evidence


def security_score(candidate: Candidate, context: ContextModel, prompt: str) -> tuple[float, list[str]]:
    text = _norm_text(candidate.diff, candidate.explanation, candidate.strategy, context.history, prompt)
    score = 0.70
    evidence: list[str] = []
    tags = risk_tags(candidate, context)

    if "secret_logging" in tags:
        score -= 0.35
        evidence.append("possible secret logging")
    if "code_injection" in tags:
        score -= 0.40
        evidence.append("dynamic code execution")
    if "tls_disabled" in tags:
        score -= 0.30
        evidence.append("tls verification disabled")
    if "financial_logic" in tags:
        score -= 0.10
        evidence.append("touches financial logic")
    if any(t in text for t in _MITIGATION_TERMS):
        score += 0.08
        evidence.append("mitigation terms present")
    if re.search(r"(sanitize|escape|parameterize|validate|allowlist|denyl?ist)", text):
        score += 0.10
        evidence.append("security hygiene present")
    if re.search(r"(no|without)\s+(logging|print|expose|leak)", text):
        score += 0.06
        evidence.append("explicit anti-leak intent")
    return _clamp(score), evidence


def performance_score(candidate: Candidate, context: ContextModel, prompt: str) -> tuple[float, list[str]]:
    text = _norm_text(candidate.diff, candidate.explanation, candidate.strategy, prompt)
    score = 0.62
    evidence: list[str] = []
    if any(t in text for t in _PERF_TERMS):
        score += 0.12
        evidence.append("performance-oriented wording")
    if any(t in text for t in {"nested loop", "quadratic", "o(n^2)", "o(n3)", "latency", "throughput"}):
        score += 0.06
        evidence.append("performance analysis present")
    if re.search(r"(global lock|serialize|single thread|blocking queue)", text):
        score -= 0.16
        evidence.append("serialization may hurt latency")
    if re.search(r"(cache|memoize|batch|async|parallel|stream)", text):
        score += 0.08
        evidence.append("performance technique present")
    return _clamp(score), evidence


def maintainability_score(candidate: Candidate, context: ContextModel, prompt: str) -> tuple[float, list[str]]:
    diff = candidate.diff
    text = _norm_text(candidate.explanation, candidate.strategy)
    stats = _diff_stats(diff)
    score = 0.66
    evidence: list[str] = []
    if stats["churn"] <= 15:
        score += 0.12
        evidence.append("minimal change")
    elif stats["churn"] >= 200:
        score -= 0.15
        evidence.append("large patch")
    if any(t in text for t in {"refactor", "readability", "modular", "separate", "small function"}):
        score += 0.08
        evidence.append("maintainability language")
    if re.search(r"(complex|hack|temporary|quick fix|workaround)", text):
        score -= 0.10
        evidence.append("ad hoc wording")
    if len(context.files) > 20:
        score -= 0.05
        evidence.append("broad surface area")
    return _clamp(score), evidence


def alignment_score(candidate: Candidate, prompt: str, context: ContextModel) -> tuple[float, list[str]]:
    p = _norm_text(prompt, candidate.explanation, candidate.strategy)
    score = 0.60
    evidence: list[str] = []
    for term in _ALIGN_TERMS:
        if term in p:
            score += 0.02
    if "security" in prompt.lower() and any(t in p for t in {"secure", "sanitize", "validate", "auth"}):
        score += 0.12
        evidence.append("aligned to security request")
    if "performance" in prompt.lower() and any(t in p for t in {"latency", "cache", "batch", "optimize"}):
        score += 0.12
        evidence.append("aligned to performance request")
    if "maintain" in prompt.lower() and any(t in p for t in {"refactor", "modular", "readability"}):
        score += 0.12
        evidence.append("aligned to maintainability request")
    if "minimal" in prompt.lower() and "minimal" in p:
        score += 0.10
        evidence.append("aligned to minimal patch")
    return _clamp(score), evidence


def risk_estimate(candidate: Candidate, context: ContextModel) -> tuple[float, float, list[str]]:
    text = _norm_text(candidate.diff, candidate.explanation, candidate.strategy, context.history, " ".join(context.files))
    tags = risk_tags(candidate, context)
    catastrophic = 0.02
    regression = 0.06

    for rx, bump, tag in _RISK_FILES:
        hay = " ".join(context.files + [text])
        if rx.search(hay):
            regression += bump
            if bump > 0:
                tags.append(tag)

    if any(t in tags for t in {"payments", "auth", "infra"}):
        catastrophic += 0.10
    if any(t in text for t in {"serialize", "global lock", "single thread"}):
        regression += 0.08
    if any(t in text for t in {"transaction", "atomic", "idempotent", "dedupe"}):
        catastrophic -= 0.03
        regression -= 0.03

    catastrophic = _clamp(catastrophic)
    regression = _clamp(regression)
    return catastrophic, regression, sorted(set(tags))


def confidence_from_scores(scores: dict[str, float]) -> float:
    mean = sum(scores.values()) / max(1, len(scores))
    spread = max(scores.values()) - min(scores.values())
    raw = mean - 0.18 * spread
    return _clamp(raw)


def utility_from_scores(scores: dict[str, float], weights: Weights) -> float:
    return _clamp(
        weights.correctness * scores["correctness"]
        + weights.security * scores["security"]
        + weights.performance * scores["performance"]
        + weights.maintainability * scores["maintainability"]
        + weights.alignment * scores["alignment"]
        - weights.risk_penalty * (0.60 * scores["catastrophic_risk"] + 0.40 * scores["regression_risk"])
    )


def evaluate_candidate(candidate: Candidate, prompt: str, context: ContextModel, weights: Weights | None = None) -> CandidateScores:
    w = weights or Weights()
    corr, corr_e = correctness_score(candidate, context, prompt)
    sec, sec_e = security_score(candidate, context, prompt)
    perf, perf_e = performance_score(candidate, context, prompt)
    maint, maint_e = maintainability_score(candidate, context, prompt)
    align, align_e = alignment_score(candidate, prompt, context)
    cat, reg, tags = risk_estimate(candidate, context)

    scores = {
        "correctness": corr,
        "security": sec,
        "performance": perf,
        "maintainability": maint,
        "alignment": align,
        "catastrophic_risk": cat,
        "regression_risk": reg,
    }
    utility = utility_from_scores(scores, w)
    confidence = confidence_from_scores({k: scores[k] for k in ("correctness", "security", "performance", "maintainability", "alignment")})

    rationale: list[str] = []
    for chunk in (corr_e, sec_e, perf_e, maint_e, align_e):
        rationale.extend(chunk)

    result = CandidateScores(
        correctness=corr,
        security=sec,
        performance=perf,
        maintainability=maint,
        alignment=align,
        catastrophic_risk=cat,
        regression_risk=reg,
        utility=utility,
        confidence=confidence,
        rationale=rationale[:12],
        risk_tags=tags,
    )
    _log_evaluation(prompt, candidate, result)
    return result

def _log_evaluation(prompt: str, candidate, scores) -> str:
    import json, time, uuid, os
    from pathlib import Path

    record = {
        "id":          str(uuid.uuid4()),
        "ts":          time.time(),
        "prompt":      prompt[:200],
        "utility":     round(scores.utility, 4),
        "security":    round(scores.security, 4),
        "confidence":  round(scores.confidence, 4),
        "cat_risk":    round(scores.catastrophic_risk, 4),
        "reg_risk":    round(scores.regression_risk, 4),
        "risk_tags":   scores.risk_tags,
        "rationale":   scores.rationale,
        "human_label": None,
    }

    # Supabase (producción)
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_SERVICE_KEY")
    if url and key:
        try:
            from supabase import create_client
            sb = create_client(url, key)
            sb.table("devmind_events").insert(record).execute()
        except Exception:
            pass

    # Fallback local (desarrollo)
    path = Path(__file__).parent.parent / "data" / "events"
    path.mkdir(parents=True, exist_ok=True)
    (path / f"{record['id']}.json").write_text(json.dumps(record, indent=2))

    return record["id"]
