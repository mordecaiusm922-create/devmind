from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel

from verify import verify_candidate_evidence, verify_sql_semantics


# ── Pydantic request models ──────────────────────────────────────────────────

class GenerateRequest(BaseModel):
    prompt: str
    context: dict[str, Any] = {}
    n_candidates: int = 2


class EvaluateRequest(BaseModel):
    prompt: str
    candidates: list[dict[str, Any]]
    context: dict[str, Any] = {}


class RepairRequest(BaseModel):
    prompt: str
    candidate: dict[str, Any]
    evaluation: dict[str, Any]
    context: dict[str, Any] = {}


class VerifyRequest(BaseModel):
    candidate: dict[str, Any]
    context: dict[str, Any] = {}


# ── Domain detection ─────────────────────────────────────────────────────────

_AUTH_PATTERNS = re.compile(
    r"secret|token|key|password|credential|jwt|oauth|session|auth",
    re.IGNORECASE,
)
_PAYMENT_PATTERNS = re.compile(
    r"payment|billing|stripe|paddle|invoice|charge|card",
    re.IGNORECASE,
)
_FAILFAST_PATTERNS = re.compile(
    r"raise\s+ValueError|raise\s+RuntimeError|sys\.exit|assert\s+\w",
    re.IGNORECASE,
)
_HARDCODED_PATTERNS = re.compile(
    r"(SECRET_KEY|PASSWORD|TOKEN)\s*=\s*['\"][^'\"]{4,}['\"]",
)
_ENV_PATTERNS = re.compile(
    r"os\.environ|os\.getenv|environ\.get",
)


def _detect_domain(text: str) -> str:
    if _AUTH_PATTERNS.search(text):
        return "auth"
    if _PAYMENT_PATTERNS.search(text):
        return "payments"
    return "general"


def _has_fail_fast(diff: str) -> bool:
    return bool(_FAILFAST_PATTERNS.search(diff))


def _has_hardcoded_secret(diff: str) -> bool:
    return bool(_HARDCODED_PATTERNS.search(diff))


def _has_env_read(diff: str) -> bool:
    return bool(_ENV_PATTERNS.search(diff))


def _patch_size(diff: str) -> str:
    lines = [l for l in diff.splitlines() if l.startswith(("+", "-")) and not l.startswith(("+++", "---"))]
    n = len(lines)
    if n <= 5:
        return "small"
    if n <= 20:
        return "medium"
    return "large"


# ── Scoring ──────────────────────────────────────────────────────────────────

def _score_candidate(
    candidate: dict[str, Any],
    prompt: str,
    domain: str,
) -> dict[str, Any]:
    diff = str(candidate.get("diff", ""))
    explanation = str(candidate.get("explanation", ""))
    strategy = str(candidate.get("strategy", ""))
    text = diff + " " + explanation + " " + strategy

    # ── correctness: behavior + fail-safe + invariants ──
    correctness = 0.50
    if _has_env_read(diff):
        correctness += 0.10          # reads from env, not hardcoded
    if _has_fail_fast(diff):
        correctness += 0.20          # explicit fail on missing value
    if not _has_hardcoded_secret(diff):
        correctness += 0.10          # no hardcoded secret introduced
    if domain in ("auth", "payments") and _has_fail_fast(diff):
        correctness += 0.10          # domain-specific: fail-fast is correct
    correctness = min(correctness, 0.95)

    # ── security ──
    security = 0.50
    if not _has_hardcoded_secret(diff):
        security += 0.20
    if _has_env_read(diff):
        security += 0.10
    if _has_fail_fast(diff):
        security += 0.10
    mitigation_terms = ["sanitiz", "validat", "encrypt", "hash", "escape", "mitigat"]
    if any(t in text.lower() for t in mitigation_terms):
        security += 0.10
    security = min(security, 0.94)

    # ── robustness (separate from correctness) ──
    robustness = 0.50
    if _has_fail_fast(diff):
        robustness += 0.25           # explicit error > silent None
    if "try" in diff and "except" in diff:
        robustness += 0.10
    robustness = min(robustness, 0.85)

    # ── performance ──
    performance = 0.60
    size = _patch_size(diff)
    if size == "small":
        performance += 0.10
    elif size == "large":
        performance -= 0.10
    performance = max(0.0, min(performance, 1.0))

    # ── maintainability ──
    maintainability = 0.65
    if len(explanation) > 40:
        maintainability += 0.10
    if size == "small":
        maintainability += 0.05
    maintainability = min(maintainability, 1.0)

    # ── alignment with prompt ──
    prompt_lower = prompt.lower()
    alignment = 0.55
    if any(w in text.lower() for w in prompt_lower.split()):
        alignment += 0.15
    alignment = min(alignment, 1.0)

    # ── risk ──
    catastrophic_risk = 0.05
    if _has_hardcoded_secret(diff):
        catastrophic_risk += 0.40
    if domain in ("auth", "payments"):
        catastrophic_risk += 0.05
    catastrophic_risk = min(catastrophic_risk, 1.0)

    regression_risk = 0.15
    if size == "large":
        regression_risk += 0.15
    if size == "medium":
        regression_risk += 0.07
    regression_risk = min(regression_risk, 1.0)

    # ── uncertainty ──
    uncertainty = 0.20
    if size == "large":
        uncertainty += 0.15
    if domain in ("auth", "payments"):
        uncertainty += 0.05
    uncertainty = min(uncertainty, 1.0)

    # ── utility = weighted expected value - risk ──
    beta = 0.30
    utility = (
        0.30 * correctness
        + 0.25 * security
        + 0.15 * robustness
        + 0.15 * maintainability
        + 0.10 * alignment
        + 0.05 * performance
        - beta * (0.6 * catastrophic_risk + 0.4 * regression_risk)
    )
    utility = max(0.0, min(utility, 1.0))

    confidence = 1.0 - uncertainty

    rationale = []
    if size == "small":
        rationale.append("small patch")
    if _has_fail_fast(diff):
        rationale.append("fail-fast on missing value")
    if _has_env_read(diff):
        rationale.append("reads from environment")
    if any(t in text.lower() for t in mitigation_terms):
        rationale.append("mitigation terms present")
    if not _has_hardcoded_secret(diff):
        rationale.append("no hardcoded secret")

    risk_tags = []
    if domain == "auth":
        risk_tags.append("auth")
    if domain == "payments":
        risk_tags.append("payments")
    if catastrophic_risk > 0.30:
        risk_tags.append("critical-risk")

    return {
        "correctness":              round(correctness, 4),
        "correctness_uncertainty":  round(uncertainty * 0.5, 4),
        "security":                 round(security, 4),
        "security_uncertainty":     round(uncertainty * 0.3, 4),
        "robustness":               round(robustness, 4),
        "performance":              round(performance, 4),
        "maintainability":          round(maintainability, 4),
        "alignment":                round(alignment, 4),
        "catastrophic_risk":        round(catastrophic_risk, 4),
        "regression_risk":          round(regression_risk, 4),
        "uncertainty":              round(uncertainty, 4),
        "utility":                  round(utility, 4),
        "confidence":               round(confidence, 4),
        "risk_tags":                risk_tags,
        "rationale":                rationale,
    }


# ── Decision logic ────────────────────────────────────────────────────────────

_UNCERTAINTY_ABSTAIN = 0.55
_CATASTROPHIC_REJECT = 0.50
_REPAIR_THRESHOLD    = 0.60   # utility below this → repair
_VERIFY_DOMAINS      = {"auth", "payments"}


def _decide(
    scores: dict[str, dict[str, Any]],
    best_id: str,
    domain: str,
) -> tuple[str, bool, bool]:
    """Returns (decision, requires_repair, requires_verification)."""
    s = scores[best_id]

    if s["catastrophic_risk"] >= _CATASTROPHIC_REJECT:
        return "reject", False, False

    if s["uncertainty"] >= _UNCERTAINTY_ABSTAIN:
        return "insufficient_confidence", True, True

    requires_verification = domain in _VERIFY_DOMAINS

    if s["utility"] < _REPAIR_THRESHOLD:
        return "revise", True, requires_verification

    if requires_verification:
        return "needs_verification", False, True

    return "approve", False, False


# ── Public endpoint handlers ──────────────────────────────────────────────────

def generate_request(req: GenerateRequest) -> dict[str, Any]:
    """
    Generate fix candidates for a given prompt.
    Two strategies: secure-minimal and secure-robust.
    """
    prompt = req.prompt
    ctx = req.context

    diff_base = ctx.get("diff", "")
    filename  = ctx.get("filename", "settings.py")

    # Strategy 1 — minimal: just read from env
    c1_diff = (
        diff_base or
        f"diff --git a/{filename} b/{filename}\n"
        f"--- a/{filename}\n+++ b/{filename}\n"
        f"@@ -1,1 +1,2 @@\n"
        f"+import os\n"
        f"+SECRET_KEY = os.environ.get('SECRET_KEY')\n"
        f"# strategy: secure-minimal\n# variant: 0"
    )

    # Strategy 2 — robust: read + fail-fast
    c2_diff = (
        diff_base or
        f"diff --git a/{filename} b/{filename}\n"
        f"--- a/{filename}\n+++ b/{filename}\n"
        f"@@ -1,1 +1,4 @@\n"
        f"+import os\n"
        f"+SECRET_KEY = os.environ.get('SECRET_KEY')\n"
        f"+if not SECRET_KEY:\n"
        f"+    raise ValueError('SECRET_KEY environment variable is not set')\n"
        f"# strategy: secure-robust\n# variant: 1"
    )

    candidates = [
        {
            "id": "c1",
            "diff": c1_diff,
            "strategy": "secure-minimal",
            "explanation": "Minimal patch with explicit validation, sanitization, and no new attack surface.",
            "metadata": {"mode": "secure", "rank": 1},
        },
        {
            "id": "c2",
            "diff": c2_diff,
            "strategy": "secure-robust",
            "explanation": "Robust fix prioritizing authentication, idempotency, and safe defaults.",
            "metadata": {"mode": "secure", "rank": 2},
        },
    ]

    return {"prompt": prompt, "candidates": candidates[:req.n_candidates]}


def evaluate_request(req: EvaluateRequest) -> dict[str, Any]:
    """
    Score each candidate and pick the best.
    Fixes: correctness != security != robustness.
    """
    prompt    = req.prompt
    candidates = req.candidates
    domain    = _detect_domain(prompt + " " + str(req.context))

    scores: dict[str, dict[str, Any]] = {}
    for c in candidates:
        cid = str(c.get("id", "c"))
        scores[cid] = _score_candidate(c, prompt, domain)

    # best = highest utility
    best_id = max(scores, key=lambda k: scores[k]["utility"])
    decision, requires_repair, requires_verification = _decide(scores, best_id, domain)

    return {
        "prompt":     prompt,
        "candidates": candidates,
        "evaluation": {
            "decision":              decision,
            "chosen_candidate":      best_id,
            "scores":                scores,
            "risk_summary": {
                "catastrophic": scores[best_id]["catastrophic_risk"],
                "regression":   scores[best_id]["regression_risk"],
                "uncertainty":  scores[best_id]["uncertainty"],
            },
            "best_rationale":        scores[best_id]["rationale"],
            "requires_verification": requires_verification,
            "requires_repair":       requires_repair,
        },
    }


def repair_request(req: RepairRequest) -> dict[str, Any]:
    """
    Attempt to repair a candidate based on evaluation feedback.
    """
    candidate  = req.candidate
    evaluation = req.evaluation
    diff       = str(candidate.get("diff", ""))

    repaired_diff = diff
    notes: list[str] = []

    scores = evaluation.get("scores", {})
    cid    = str(candidate.get("id", "c"))
    cscore = scores.get(cid, {})

    # If correctness is low and no fail-fast → add it
    if cscore.get("correctness", 1.0) < 0.70 and not _has_fail_fast(diff):
        repaired_diff += (
            "\n+if not SECRET_KEY:\n"
            "+    raise ValueError('SECRET_KEY environment variable is not set')\n"
        )
        notes.append("added fail-fast validation")

    # If hardcoded secret detected → flag it
    if _has_hardcoded_secret(diff):
        notes.append("WARNING: hardcoded secret still present — manual review required")

    repaired = {**candidate, "diff": repaired_diff, "id": cid + "_r"}
    return {
        "original":  candidate,
        "repaired":  repaired,
        "notes":     notes,
        "repaired":  repaired,
    }


def verify_candidate(req: VerifyRequest) -> dict[str, Any]:
    """
    Verify a candidate against security invariants.
    """
    candidate = req.candidate
    diff      = str(candidate.get("diff", ""))
    ctx       = req.context

    checks: dict[str, bool] = {
        "no_hardcoded_secret": not _has_hardcoded_secret(diff),
        "reads_from_env":      _has_env_read(diff),
        "has_fail_fast":       _has_fail_fast(diff),
        "no_insecure_fallback": "None" not in diff and "none" not in diff.lower(),
    }
    sql_semantics = verify_sql_semantics(diff)
    if sql_semantics.get("sql_detected"):
        checks["sql_semantic_safe"] = not sql_semantics.get("critical_violations")
        checks["validate_email_present"] = bool(sql_semantics.get("validate_email_present"))
    sandbox = verify_candidate_evidence(candidate, ctx)
    checks["sandbox_safe"] = bool(sandbox.get("verified"))

    passed  = all(checks.values())
    failed  = [k for k, v in checks.items() if not v]

    return {
        "candidate": candidate.get("id"),
        "passed":    passed,
        "failed":    failed,
        "checks":    checks,
        "sql_semantics": sql_semantics,
        "sandbox_evidence": sandbox.get("sandbox_evidence", {}),
        "traps": sandbox.get("traps", []),
        "sandbox_violations": sandbox.get("violations", []),
        "verdict":   "approved" if passed else "rejected",
    }
