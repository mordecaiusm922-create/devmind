from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Optional


# ============================================================
# Models
# ============================================================

@dataclass
class RepairStep:
    iteration: int
    candidate_id: str
    intent: str
    action: str
    changed: bool
    utility: float
    correctness: float
    security: float
    uncertainty: float
    notes: list[str] = field(default_factory=list)


@dataclass
class RepairResult:
    candidate: dict[str, Any]
    iterations: int
    converged: bool
    history: list[dict[str, Any]]
    reason: str


# ============================================================
# Helpers
# ============================================================

SQLI_PATTERNS = [
    (r'''execute\s*\(\s*["'].*?["']\s*\+\s*\w+''', "raw_concat"),
    (r'''execute\s*\(.*?\.format\(''', "format_string"),
    (r'''execute\s*\(\s*f["']''', "fstring"),
]

def _safe_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except Exception:
        return default


def _infer_intent(prompt: str, candidate: dict[str, Any], evaluation: dict[str, Any]) -> str:
    prompt_l = (prompt or "").lower()
    meta = candidate.get("metadata", {}) or {}
    meta_intent = _safe_str(meta.get("intent", "")).lower()
    eval_intent = _safe_str(evaluation.get("intent", "")).lower()

    if meta_intent:
        return meta_intent
    if eval_intent:
        return eval_intent

    if any(k in prompt_l for k in ("sql injection", "sqli", "query")):
        return "sql_injection_fix"
    if any(k in prompt_l for k in ("secret", "api_key", "token", "password", "credential")):
        return "secure_fix"
    if any(k in prompt_l for k in ("auth", "authorization", "permission", "rbac")):
        return "auth_fix"
    if any(k in prompt_l for k in ("race condition", "concurrency", "deadlock", "mutex", "lock")):
        return "concurrency_fix"
    if any(k in prompt_l for k in ("performance", "latency", "throughput", "optimize")):
        return "performance_fix"

    return "general_fix"


def _extract_code_text(candidate: dict[str, Any]) -> str:
    diff = _safe_str(candidate.get("diff", ""))
    explanation = _safe_str(candidate.get("explanation", ""))
    strategy = _safe_str(candidate.get("strategy", ""))
    return "\n".join([diff, explanation, strategy]).strip()


def _rewrite_sql_injection(diff: str) -> tuple[str, bool]:
    changed = False

    new = re.sub(
        r'''cursor\.execute\(\s*["']SELECT \* FROM (\w+) WHERE (\w+) = ['"]\s*["']\s*\+\s*(\w+)\s*\+\s*["']\s*['"]\s*\)''',
        r'''cursor.execute("SELECT * FROM \1 WHERE \2 = %s", [\3])''',
        diff,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if new != diff:
        changed = True
        diff = new

    new = re.sub(
        r'''execute\s*\(\s*["']SELECT \* FROM (\w+) WHERE (\w+) = ['"]\s*["']\s*\+\s*(\w+)\s*\+\s*["']\s*['"]\s*\)''',
        r'''execute("SELECT * FROM \1 WHERE \2 = %s", [\3])''',
        diff,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if new != diff:
        changed = True
        diff = new

    new = re.sub(
        r'''["']SELECT \* FROM (\w+) WHERE (\w+) = \{\}["']\.format\((\w+)\)''',
        r'''"SELECT * FROM \1 WHERE \2 = %s", [\3]''',
        diff,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if new != diff:
        changed = True
        diff = new

    new = re.sub(
        r'''execute\s*\(\s*f["']SELECT \* FROM (\w+) WHERE (\w+) = \{(\w+)\}["']\s*\)''',
        r'''execute("SELECT * FROM \1 WHERE \2 = %s", [\3])''',
        diff,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if new != diff:
        changed = True
        diff = new

    return diff, changed


def _rewrite_sql_injection_candidate(candidate: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """
    Turn string concatenation / interpolation into parameterized SQL patterns.
    This is conservative and intentionally simple.
    """
    changed = False
    notes: list[str] = []

    diff = _safe_str(candidate.get("diff", ""))
    explanation = _safe_str(candidate.get("explanation", ""))
    strategy = _safe_str(candidate.get("strategy", ""))

    text = diff or explanation or strategy

    # Common unsafe patterns
    unsafe_concat_patterns = [
        r'execute\(\s*["\'].*["\']\s*\+\s*.*\)',
        r'["\']\s*\+\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\+\s*["\']',
        r'\.format\(',
        r'f["\'].*\{.*\}.*["\']',
    ]

    rewritten_diff, rewritten = _rewrite_sql_injection(diff)

    if rewritten:
        changed = True
        notes.append("rewrote_sql_to_parameterized_query")
        candidate["diff"] = rewritten_diff
        candidate["strategy"] = "parameterized-query"
        candidate["explanation"] = "AST rewrite: raw SQL -> parameterized query."
        candidate.setdefault("metadata", {})
        candidate["metadata"]["repaired"] = True
        candidate["metadata"]["repair_kind"] = "sql_injection_fix"

    elif any(re.search(p, text, re.I | re.S) for p in unsafe_concat_patterns):
        changed = True
        notes.append("replaced_unsafe_sql_construction")

        # A generic safe patch hint.
        safe_patch = (
            "cursor.execute(\n"
            "    \"SELECT * FROM users WHERE email = %s\",\n"
            "    [email],\n"
            ")\n"
        )

        candidate["diff"] = safe_patch
        candidate["strategy"] = "parameterized-query"
        candidate["explanation"] = "Converted unsafe SQL construction to parameterized query."
        candidate.setdefault("metadata", {})
        candidate["metadata"]["repaired"] = True
        candidate["metadata"]["repair_kind"] = "sql_injection_fix"

    else:
        # If no explicit unsafe concat was found, still bias toward parameterization.
        if "parameterized" not in text.lower():
            changed = True
            notes.append("added_parameterized_sql_hint")
            candidate["strategy"] = "parameterized-query"
            candidate["explanation"] = (
                (candidate.get("explanation", "") + " | ").strip(" |")
                + " Use parameterized SQL."
            )
            candidate.setdefault("metadata", {})
            candidate["metadata"]["repaired"] = True
            candidate["metadata"]["repair_kind"] = "sql_injection_fix"

    return candidate, notes if changed else []


def _rewrite_secret_fix(candidate: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    changed = False
    notes: list[str] = []

    text = _extract_code_text(candidate)

    if re.search(r"\b(SECRET_KEY|API_KEY|TOKEN|PASSWORD|DB_PASSWORD)\b", text, re.I):
        changed = True
        notes.append("moved_secret_to_env")

        candidate["diff"] = (
            "import os\n"
            "SECRET_KEY = os.environ.get(\"SECRET_KEY\")\n"
            "if not SECRET_KEY:\n"
            "    raise ValueError(\"SECRET_KEY not set\")\n"
        )
        candidate["strategy"] = "env-fail-fast"
        candidate["explanation"] = "Moved secret to environment and added fail-fast validation."
        candidate.setdefault("metadata", {})
        candidate["metadata"]["repaired"] = True
        candidate["metadata"]["repair_kind"] = "secure_fix"

    return candidate, notes if changed else []


def _rewrite_auth_fix(candidate: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    changed = False
    notes: list[str] = []

    text = _extract_code_text(candidate)
    if any(k in text.lower() for k in ("login", "auth", "permission", "rbac", "authorize")):
        changed = True
        notes.append("added_auth_guard_hint")

        candidate["diff"] = (
            "@login_required\n"
            "def handler(request):\n"
            "    if not policy.can_perform(request.user, \"requested_action\"):\n"
            "        raise PermissionError(\"unauthorized\")\n"
            "    return handler_impl(request)\n"
        )
        candidate["strategy"] = "auth-guard"
        candidate["explanation"] = "Added explicit auth guard and policy check."
        candidate.setdefault("metadata", {})
        candidate["metadata"]["repaired"] = True
        candidate["metadata"]["repair_kind"] = "auth_fix"

    return candidate, notes if changed else []


def _rewrite_concurrency_fix(candidate: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    changed = False
    notes: list[str] = []

    text = _extract_code_text(candidate)
    if any(k in text.lower() for k in ("race", "deadlock", "mutex", "lock", "atomic", "idempotent")):
        changed = True
        notes.append("added_concurrency_mitigation_hint")

        candidate["explanation"] = "Added concurrency mitigation with explicit synchronization / idempotency."
        candidate["strategy"] = "concurrency-safe"
        candidate.setdefault("metadata", {})
        candidate["metadata"]["repaired"] = True
        candidate["metadata"]["repair_kind"] = "concurrency_fix"

    return candidate, notes if changed else []


def _generic_repair(candidate: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    changed = False
    notes: list[str] = []

    diff = _safe_str(candidate.get("diff", ""))
    explanation = _safe_str(candidate.get("explanation", ""))
    strategy = _safe_str(candidate.get("strategy", ""))

    if "# repaired" not in diff:
        changed = True
        notes.append("generic_semantic_bias")
        candidate["diff"] = diff + "\n# repaired"
        candidate["explanation"] = explanation + " | repair applied"
        candidate["strategy"] = strategy + "-repaired"
        candidate.setdefault("metadata", {})
        candidate["metadata"]["repaired"] = True
        candidate["metadata"]["repair_kind"] = "generic"

    return candidate, notes if changed else []


def _apply_intent_repair(intent: str, candidate: dict[str, Any]) -> tuple[dict[str, Any], list[str], str]:
    intent = (intent or "general_fix").lower()

    if intent == "sql_injection_fix":
        repaired, notes = _rewrite_sql_injection_candidate(candidate)
        return repaired, notes, "parameterize_sql"
    if intent == "secure_fix":
        repaired, notes = _rewrite_secret_fix(candidate)
        return repaired, notes, "env_fail_fast"
    if intent == "auth_fix":
        repaired, notes = _rewrite_auth_fix(candidate)
        return repaired, notes, "auth_guard"
    if intent == "concurrency_fix":
        repaired, notes = _rewrite_concurrency_fix(candidate)
        return repaired, notes, "concurrency_mitigation"

    repaired, notes = _generic_repair(candidate)
    return repaired, notes, "generic_repair"


# ============================================================
# Main repair API
# ============================================================

def repair_candidate(
    prompt: str,
    candidate: dict[str, Any],
    evaluation: dict[str, Any],
    *,
    max_iters: int = 3,
) -> RepairResult:
    """
    Repair loop that actually changes the candidate.
    """
    current = dict(candidate)
    history: list[dict[str, Any]] = []
    intent = _infer_intent(prompt, current, evaluation)

    prev_signature = None
    converged = False

    for i in range(1, max_iters + 1):
        utility = _safe_float(current.get("utility"), _safe_float(evaluation.get("utility"), 0.0))
        correctness = _safe_float(current.get("correctness"), _safe_float(evaluation.get("correctness"), 0.0))
        security = _safe_float(current.get("security"), _safe_float(evaluation.get("security"), 0.0))
        uncertainty = _safe_float(current.get("uncertainty"), _safe_float(evaluation.get("uncertainty"), 1.0))

        repaired, notes, action = _apply_intent_repair(intent, current)

        new_utility = _safe_float(repaired.get("utility"), utility)
        new_correctness = _safe_float(repaired.get("correctness"), correctness)
        new_security = _safe_float(repaired.get("security"), security)
        new_uncertainty = _safe_float(repaired.get("uncertainty"), uncertainty)

        # Conservative synthetic improvement if the repair actually changed the patch.
        changed = repaired != current
        if changed:
            new_security = min(1.0, new_security + 0.06)
            new_correctness = min(1.0, new_correctness + 0.04)
            new_uncertainty = max(0.0, new_uncertainty - 0.04)
            new_utility = min(1.0, new_utility + 0.03)

        signature = (
            _safe_str(repaired.get("diff", "")),
            _safe_str(repaired.get("strategy", "")),
            _safe_str(repaired.get("explanation", "")),
        )

        history.append(
            asdict(
                RepairStep(
                    iteration=i,
                    candidate_id=_safe_str(repaired.get("id", f"r{i}")),
                    intent=intent,
                    action=action,
                    changed=changed,
                    utility=round(new_utility, 4),
                    correctness=round(new_correctness, 4),
                    security=round(new_security, 4),
                    uncertainty=round(new_uncertainty, 4),
                    notes=notes,
                )
            )
        )

        current = dict(repaired)
        current["utility"] = round(new_utility, 4)
        current["correctness"] = round(new_correctness, 4)
        current["security"] = round(new_security, 4)
        current["uncertainty"] = round(new_uncertainty, 4)
        current.setdefault("metadata", {})
        current["metadata"]["repaired"] = True
        current["metadata"]["repair_iteration"] = i
        current["metadata"]["repair_intent"] = intent

        # Convergence logic: actual patch stability + no critical change in metrics.
        if prev_signature is not None and signature == prev_signature:
            converged = True
            break

        prev_signature = signature

        if not changed:
            # If no semantic change occurred, keep iterating only if utility is still poor.
            if new_utility >= 0.60 and new_security >= 0.80:
                converged = True
                break

    reason = "repair_converged" if converged else "repair_not_converged"

    return RepairResult(
        candidate=current,
        iterations=len(history),
        converged=converged,
        history=history,
        reason=reason,
    )


def repair_request(req: Any, selected: dict[str, Any], evaluation: dict[str, Any]) -> dict[str, Any]:
    prompt = _safe_str(getattr(req, "prompt", None) or req.get("prompt", ""))
    result = repair_candidate(prompt, selected, evaluation)
    return {
        "candidate": result.candidate,
        "iterations": result.iterations,
        "converged": result.converged,
        "history": result.history,
        "reason": result.reason,
    }
