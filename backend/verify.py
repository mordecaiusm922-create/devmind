# backend/verify.py
from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Any, Mapping


# ============================================================
# Policy / config
# ============================================================

@dataclass(frozen=True)
class VerifyConfig:
    # Secrets
    secret_patterns: tuple[str, ...] = (
        r"SECRET_KEY\s*=\s*['\"][^'\"]+['\"]",
        r"API_KEY\s*=\s*['\"][^'\"]+['\"]",
        r"TOKEN\s*=\s*['\"][^'\"]+['\"]",
        r"PASSWORD\s*=\s*['\"][^'\"]+['\"]",
        r"PRIVATE_KEY\s*=\s*['\"][^'\"]+['\"]",
        r"DB_PASSWORD\s*=\s*['\"][^'\"]+['\"]",
    )

    env_patterns: tuple[str, ...] = (
        r"os\.environ\.get\(",
        r"os\.getenv\(",
        r"process\.env\.",
        r"getenv\(",
    )

    fail_fast_patterns: tuple[str, ...] = (
        r"raise\s+ValueError\(",
        r"raise\s+RuntimeError\(",
        r"raise\s+PermissionError\(",
        r"assert\s+",
    )

    # Auth
    auth_sensitive_terms: tuple[str, ...] = (
        "auth", "authentication", "authorization", "permission", "rbac", "login", "session", "jwt", "oauth"
    )
    auth_guard_patterns: tuple[str, ...] = (
        r"login_required",
        r"permission_required",
        r"policy\.",
        r"authorize\(",
        r"is_authenticated",
        r"has_perm\(",
        r"has_permission\(",
        r"require_auth",
    )

    # Invariants / runtime discipline
    invariant_terms: tuple[str, ...] = (
        "invariant", "contract", "precondition", "postcondition", "idempotent", "idempotency",
        "transaction", "atomic", "dedupe", "lock", "mutex", "rollback",
    )

    invariant_patterns: tuple[str, ...] = (
        r"assert\s+",
        r"raise\s+\w*Error\(",
        r"check_.*\(",
        r"ensure_.*\(",
        r"validate_.*\(",
    )

    # Dangerous sinks
    dangerous_patterns: tuple[tuple[str, str, str], ...] = (
        (r"\beval\s*\(", "dangerous_sink", "eval"),
        (r"\bexec\s*\(", "dangerous_sink", "exec"),
        (r"__import__\s*\(", "dangerous_sink", "__import__"),
        (r"\bpickle\.loads\s*\(", "dangerous_sink", "pickle.loads"),
        (r"\byaml\.load\s*\(", "dangerous_sink", "yaml.load"),
        (r"\bos\.system\s*\(", "dangerous_sink", "os.system"),
        (r"\bsubprocess\.(Popen|run|call)\s*\(", "dangerous_sink", "subprocess"),
    )

    shell_true_pattern: str = r"shell\s*=\s*True"
    unsafe_http_patterns: tuple[str, ...] = (
        r"verify\s*=\s*False",
        r"allow_redirects\s*=\s*True",
    )

    # Scoring thresholds
    min_verified_score: float = 0.72
    runtime_pass_bonus: float = 0.12
    runtime_fail_penalty: float = 0.18


@dataclass(frozen=True)
class VerificationResult:
    verified: bool
    violations: list[dict[str, Any]]
    critical_violations: list[dict[str, Any]]
    properties: list[str]
    runtime_evidence_status: str
    runtime_evidence_score: float
    confidence: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ============================================================
# Helpers
# ============================================================

def _get(obj: Any, key: str, default: Any = None) -> Any:
    if obj is None:
        return default
    if isinstance(obj, Mapping):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, float(x)))


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def _extract_diff_text(selected: Any) -> str:
    diff = _get(selected, "diff", "") or _get(selected, "code", "") or ""
    return _normalize_text(diff)


def _extract_added_lines(diff_text: str) -> str:
    """
    If the input is a unified diff, keep only added lines to reduce noise.
    If it's plain code, return as-is.
    """
    lines = diff_text.splitlines()
    added = []
    saw_diff_headers = any(line.startswith("diff --git") or line.startswith("@@") for line in lines)

    if not saw_diff_headers:
        return diff_text

    for line in lines:
        if line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:])
    return "\n".join(added)


def _text_has_any(text: str, patterns: tuple[str, ...]) -> bool:
    return any(re.search(p, text, re.I | re.S) for p in patterns)


def _find_matches(text: str, patterns: tuple[tuple[str, str, str], ...]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for pattern, tag, label in patterns:
        if re.search(pattern, text, re.I | re.S):
            matches.append({
                "type": tag,
                "label": label,
                "pattern": pattern,
            })
    return matches


def _risk_level_from_count(n: int) -> str:
    if n <= 0:
        return "none"
    if n == 1:
        return "low"
    if n == 2:
        return "medium"
    return "high"


# ============================================================
# Verifier
# ============================================================

def verify_candidate(
    req_or_code: Any,
    selected_or_properties: Any = None,
    *,
    config: VerifyConfig | None = None,
) -> dict[str, Any]:
    """
    Main verification entrypoint.

    Supports two calling styles:
      1) verify_candidate(req, selected)
      2) verify_candidate(code, properties)

    Returns dict with:
      - verified
      - violations
      - critical_violations
      - properties
      - runtime_evidence_status
      - runtime_evidence_score
      - confidence
    """
    cfg = config or VerifyConfig()

    # Flexible input handling
    if isinstance(req_or_code, str):
        code_text = req_or_code
        prompt = ""
        mode = "balanced"
        selected = selected_or_properties if isinstance(selected_or_properties, Mapping) else {}
        properties = list(_get(selected_or_properties, "properties", []) or [])
        runtime_evidence_status = _get(selected_or_properties, "runtime_evidence_status", "not_available")
        runtime_evidence_score = float(_get(selected_or_properties, "runtime_evidence_score", 0.0) or 0.0)
    else:
        req = req_or_code
        selected = selected_or_properties if isinstance(selected_or_properties, Mapping) else {}

        prompt = _normalize_text(_get(req, "prompt", ""))
        mode = _normalize_text(_get(req, "mode", "balanced")).lower()
        code_text = _extract_diff_text(selected)
        properties = list(_get(selected, "properties", []) or _get(req, "properties", []) or [])
        runtime_evidence_status = _get(selected, "runtime_evidence_status", "not_available")
        runtime_evidence_score = float(_get(selected, "runtime_evidence_score", 0.0) or 0.0)

    code_text = _extract_added_lines(code_text)
    text = f"{prompt}\n{code_text}".strip()

    violations: list[dict[str, Any]] = []
    critical_violations: list[dict[str, Any]] = []
    props = set(str(p) for p in properties)

    # --------------------------------------------------------
    # 1) Secrets
    # --------------------------------------------------------
    secret_hits = []
    for pat in cfg.secret_patterns:
        if re.search(pat, text, re.I | re.S):
            secret_hits.append(pat)

    env_ok = _text_has_any(text, cfg.env_patterns)
    fail_fast_ok = _text_has_any(text, cfg.fail_fast_patterns)

    if secret_hits:
        if env_ok:
            props.add("secret_from_environment")
        else:
            violations.append({
                "type": "secret",
                "severity": "high",
                "message": "Hardcoded secret-like value detected without environment sourcing.",
                "evidence": secret_hits[:3],
            })
            critical_violations.append({
                "type": "secret",
                "severity": "critical",
                "message": "Potential hardcoded secret in patch.",
                "evidence": secret_hits[:3],
            })

        if not fail_fast_ok and mode in {"secure", "critical"}:
            violations.append({
                "type": "secret",
                "severity": "medium",
                "message": "Secret source is present but missing explicit fail-fast behavior.",
            })

    # --------------------------------------------------------
    # 2) Auth
    # --------------------------------------------------------
    prompt_lower = prompt.lower()
    if any(term in prompt_lower for term in cfg.auth_sensitive_terms):
        auth_guard = _text_has_any(text, cfg.auth_guard_patterns)
        if auth_guard:
            props.add("auth_guard_present")
        else:
            violations.append({
                "type": "auth",
                "severity": "high",
                "message": "Auth-sensitive change without an obvious authorization guard.",
            })
            critical_violations.append({
                "type": "auth",
                "severity": "critical",
                "message": "Missing auth guard in a sensitive path.",
            })

    # --------------------------------------------------------
    # 3) Invariants
    # --------------------------------------------------------
    if _text_has_any(text, cfg.invariant_terms):
        invariant_ok = _text_has_any(text, cfg.invariant_patterns)
        if invariant_ok:
            props.add("invariant_checked")
        else:
            violations.append({
                "type": "invariant",
                "severity": "medium",
                "message": "Invariant-sensitive change lacks explicit invariant/assertion checks.",
            })

    # --------------------------------------------------------
    # 4) Dangerous sinks
    # --------------------------------------------------------
    sink_hits = _find_matches(text, cfg.dangerous_patterns)
    if sink_hits:
        violations.append({
            "type": "dangerous_sink",
            "severity": "high",
            "message": "Dangerous sink detected.",
            "evidence": sink_hits,
        })
        critical_violations.append({
            "type": "dangerous_sink",
            "severity": "critical",
            "message": "Patch introduces or preserves a dangerous execution sink.",
            "evidence": sink_hits,
        })

    if re.search(cfg.shell_true_pattern, text, re.I):
        violations.append({
            "type": "dangerous_sink",
            "severity": "high",
            "message": "subprocess shell=True detected.",
        })
        critical_violations.append({
            "type": "dangerous_sink",
            "severity": "critical",
            "message": "shell=True is unsafe in production-sensitive code.",
        })

    if _text_has_any(text, cfg.unsafe_http_patterns):
        violations.append({
            "type": "runtime_safety",
            "severity": "medium",
            "message": "Unsafe HTTP/runtime option detected.",
        })

    # --------------------------------------------------------
    # 5) Runtime sanity
    # --------------------------------------------------------
    # Without a sandbox we still require a runtime-ish signal if the candidate is sensitive.
    # This is conservative by design.
    if runtime_evidence_status == "passed":
        runtime_score = _clamp01(runtime_evidence_score if runtime_evidence_score > 0 else 1.0)
        props.add("runtime_evidence_passed")
    elif runtime_evidence_status in {"failed", "error"}:
        runtime_score = 0.0
        violations.append({
            "type": "runtime",
            "severity": "high",
            "message": f"Runtime evidence failed with status={runtime_evidence_status}.",
        })
        critical_violations.append({
            "type": "runtime",
            "severity": "critical",
            "message": "Runtime evidence failed.",
        })
    else:
        runtime_score = 0.35 if not critical_violations else 0.15
        if mode in {"secure", "critical"}:
            violations.append({
                "type": "runtime",
                "severity": "medium",
                "message": "No runtime evidence available in a safety-sensitive mode.",
            })

    # --------------------------------------------------------
    # Aggregate confidence / verdict
    # --------------------------------------------------------
    violation_penalty = 0.15 * len(violations) + 0.30 * len(critical_violations)
    base_confidence = 0.90
    if critical_violations:
        base_confidence -= 0.40
    if violations and not critical_violations:
        base_confidence -= 0.15
    if runtime_evidence_status == "passed":
        base_confidence += cfg.runtime_pass_bonus
    elif runtime_evidence_status in {"failed", "error"}:
        base_confidence -= cfg.runtime_fail_penalty

    confidence = _clamp01(base_confidence - min(0.35, violation_penalty))

    verified = (
        len(critical_violations) == 0
        and len(violations) == 0
        and runtime_score >= 0.60
    )

    # Security-sensitive modes should be stricter.
    if mode in {"secure", "critical"}:
        verified = verified and runtime_evidence_status == "passed"

    if verified:
        props.add("verified")

    result = VerificationResult(
        verified=verified,
        violations=violations,
        critical_violations=critical_violations,
        properties=sorted(props),
        runtime_evidence_status=runtime_evidence_status,
        runtime_evidence_score=round(runtime_score, 4),
        confidence=round(confidence, 4),
    )

    return result.to_dict()


def verify_request(req: Any, selected: Any) -> dict[str, Any]:
    return verify_candidate(req, selected)


def verify_code(
    code: str,
    properties: list[str] | None = None,
    *,
    mode: str = "balanced",
    runtime_evidence_status: str = "not_available",
    runtime_evidence_score: float = 0.0,
) -> dict[str, Any]:
    fake_req = {
        "prompt": "",
        "mode": mode,
        "properties": properties or [],
    }
    fake_selected = {
        "code": code,
        "properties": properties or [],
        "runtime_evidence_status": runtime_evidence_status,
        "runtime_evidence_score": runtime_evidence_score,
    }
    return verify_candidate(fake_req, fake_selected)