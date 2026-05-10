from __future__ import annotations

import re
from typing import Any


_SQL_KEYWORDS_RE = re.compile(r"\b(select|insert|update|delete|with)\b", re.IGNORECASE)
_EXECUTE_CALL_RE = re.compile(r"\.?\bexecute\s*\(", re.IGNORECASE)
_EXECUTE_FSTRING_RE = re.compile(r"\.?\bexecute\s*\(\s*f[\"']", re.IGNORECASE)
_EXECUTE_CONCAT_RE = re.compile(r"\.?\bexecute\s*\([^)]*\+[^)]*\)", re.IGNORECASE | re.DOTALL)
_EXECUTE_PERCENT_RE = re.compile(r"\.?\bexecute\s*\([^)]*[\"']\s*%\s*[^,\)]", re.IGNORECASE | re.DOTALL)
_EXECUTE_FORMAT_RE = re.compile(r"\.?\bexecute\s*\([^)]*\.format\s*\(", re.IGNORECASE | re.DOTALL)
_ORM_RAW_RE = re.compile(r"\.\s*raw\s*\(", re.IGNORECASE)
_RAWSQL_RE = re.compile(r"\bRawSQL\s*\(", re.IGNORECASE)
_SQL_ASSIGN_DYNAMIC_RE = re.compile(
    r"(?im)^\+?\s*(?P<name>[a-z_][a-z0-9_]*)\s*=\s*"
    r"(?:f[\"'][^\"']*(?:select|insert|update|delete|with)[^\"']*[\"']|"
    r"[\"'][^\"']*(?:select|insert|update|delete|with)[^\"']*[\"']\s*(?:\+|%)|"
    r".*\.format\s*\()"
)
_VALIDATE_EMAIL_RE = re.compile(r"\bvalidate_email\s*\(", re.IGNORECASE)


def verify_sql_semantics(diff: str, *, require_validate_email: bool | None = None) -> dict[str, Any]:
    """
    Semantic-ish SQL guardrail for patches.

    Positive uncertainty movement in DevMind depends on proving that the patch
    removed the dangerous construction, not merely that a safer line appears
    somewhere else in the diff.
    """
    text = str(diff or "")
    sql_detected = bool(
        _SQL_KEYWORDS_RE.search(text)
        or _EXECUTE_CALL_RE.search(text)
        or _ORM_RAW_RE.search(text)
        or _RAWSQL_RE.search(text)
    )
    needs_email_validation = bool(require_validate_email) if require_validate_email is not None else (
        sql_detected and re.search(r"\bemail\b", text, re.IGNORECASE) is not None
    )

    checks: list[dict[str, Any]] = []
    violations: list[str] = []
    critical_violations: list[str] = []

    def add_check(name: str, ok: bool, evidence: str, critical: bool = False) -> None:
        checks.append({"name": name, "passed": ok, "evidence": evidence})
        if not ok:
            violations.append(name)
            if critical:
                critical_violations.append(name)

    if not sql_detected:
        return {
            "sql_detected": False,
            "verified": True,
            "checks": [],
            "violations": [],
            "critical_violations": [],
            "validate_email_present": False,
        }

    add_check(
        "no_execute_fstring",
        _EXECUTE_FSTRING_RE.search(text) is None,
        "execute(f\"...\") changes SQL structure with attacker-controlled text",
        critical=True,
    )
    add_check(
        "no_execute_concat",
        _EXECUTE_CONCAT_RE.search(text) is None,
        "execute(...) contains string concatenation",
        critical=True,
    )
    add_check(
        "no_execute_percent_format",
        _EXECUTE_PERCENT_RE.search(text) is None,
        "execute(...) contains percent formatting",
        critical=True,
    )
    add_check(
        "no_execute_dot_format",
        _EXECUTE_FORMAT_RE.search(text) is None,
        "execute(...) contains .format(...) interpolation",
        critical=True,
    )
    add_check(
        "no_orm_raw",
        _ORM_RAW_RE.search(text) is None,
        "ORM .raw(...) bypasses query construction guarantees",
        critical=True,
    )
    add_check(
        "no_rawsql",
        _RAWSQL_RE.search(text) is None,
        "RawSQL(...) embeds raw SQL expression",
        critical=True,
    )

    dynamic_assignments = [m.group("name") for m in _SQL_ASSIGN_DYNAMIC_RE.finditer(text)]
    execute_dynamic = any(
        re.search(rf"\.?\bexecute\s*\(\s*{re.escape(name)}\s*[,)]", text, re.IGNORECASE)
        for name in dynamic_assignments
    )
    add_check(
        "no_partial_sql_construction",
        not execute_dynamic,
        "dynamic SQL assignment is later passed to execute(...)",
        critical=True,
    )

    validate_email_present = _VALIDATE_EMAIL_RE.search(text) is not None
    if needs_email_validation:
        add_check(
            "validate_email_present",
            validate_email_present,
            "email-bearing SQL change must show validate_email(...) in the diff",
            critical=False,
        )

    return {
        "sql_detected": True,
        "verified": not critical_violations and (
            validate_email_present if needs_email_validation else True
        ),
        "checks": checks,
        "violations": violations,
        "critical_violations": critical_violations,
        "validate_email_present": validate_email_present,
    }
