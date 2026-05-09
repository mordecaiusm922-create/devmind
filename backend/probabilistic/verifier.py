from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from .schemas import VerifyRequest, VerifyResult

_SECRET_RX = re.compile(r"(secret|api_key|token|password|passwd|pwd)", re.I)
_LOG_SECRET_RX = re.compile(r"logging\.(?:info|debug|warning|error|exception).{0,80}(secret|token|password|key)", re.I | re.S)


def _has_py_syntax(code: str) -> tuple[bool, list[str]]:
    evidence: list[str] = []
    try:
        ast.parse(code)
        evidence.append("python syntax valid")
        return True, evidence
    except SyntaxError as exc:
        evidence.append(f"syntax error: {exc.msg}")
        return False, evidence


def _property_checks(code: str, properties: list[str]) -> tuple[list[str], list[str]]:
    violations: list[str] = []
    evidence: list[str] = []
    text = code.lower()

    if _SECRET_RX.search(text) and _LOG_SECRET_RX.search(text):
        violations.append("possible secret logging")

    for prop in properties:
        p = prop.lower()
        if p in {"no_double_payment", "idempotency", "dedupe", "exactly_once"}:
            if not any(k in text for k in ("idempotent", "dedupe", "dedup", "transaction", "atomic", "nonce", "idempotency key")):
                violations.append(f"{prop}: missing idempotency/deduplication evidence")
            else:
                evidence.append(f"{prop}: idempotency evidence found")
        elif p in {"no_data_leak", "no_secret_leak", "no_raw_secret_logging"}:
            if _SECRET_RX.search(text) and not re.search(r"(sanitize|redact|mask|hash|omit)", text):
                violations.append(f"{prop}: sensitive material referenced without redaction")
            else:
                evidence.append(f"{prop}: no obvious leak pattern")
        elif p in {"race_condition_mitigation", "concurrency_safe"}:
            if not any(k in text for k in ("lock", "mutex", "transaction", "atomic", "semaphore", "queue", "synchronized")):
                violations.append(f"{prop}: no concurrency mitigation evidence")
            else:
                evidence.append(f"{prop}: concurrency mitigation present")
        elif p in {"input_validation", "sanitization"}:
            if not any(k in text for k in ("validate", "sanitize", "allowlist", "denyl", "escape", "assert")):
                violations.append(f"{prop}: no validation/sanitization evidence")
            else:
                evidence.append(f"{prop}: validation/sanitization present")
        else:
            # For unknown properties, require a supporting comment or assert.
            if not re.search(re.escape(prop), code, re.I):
                violations.append(f"{prop}: no direct evidence in code")
            else:
                evidence.append(f"{prop}: direct evidence found")

    return violations, evidence


def verify_candidate(code: str, properties: list[str]) -> VerifyResult:
    ok, syntax_evidence = _has_py_syntax(code)
    violations, prop_evidence = _property_checks(code, properties)
    score = 1.0
    if not ok:
        score -= 0.35
    score -= 0.12 * len(violations)
    score = max(0.0, min(1.0, score))
    verified = ok and not violations and score >= 0.7
    return VerifyResult(
        verified=verified,
        score=score,
        violations=violations,
        evidence=syntax_evidence + prop_evidence,
    )
