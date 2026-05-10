from __future__ import annotations

import re
from typing import Any

from sandbox import run_sandbox
from runtime import VerificationTrap, traps_from_sandbox


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
SQL_UNSAFE = [
    r'''execute\s*\(.*["\'].*\+\s*\w+''',
    r'''execute\s*\(.*\.format\(''',
    r'''execute\s*\(\s*f["\']''',
]


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


def verify_candidate_evidence(candidate: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    sandbox_evidence = run_sandbox(candidate, context or {})
    traps = traps_from_sandbox(sandbox_evidence)
    violations = [_trap_to_violation(trap, sandbox_evidence) for trap in traps]
    text = "\n".join(
        str(candidate.get(key, "") or "")
        for key in ("diff", "code", "content", "strategy", "explanation")
    )
    for pat in SQL_UNSAFE:
        if re.search(pat, text, re.IGNORECASE | re.DOTALL):
            violations.append(
                {
                    "type": "sql_injection",
                    "severity": "critical",
                    "message": "SQL string concatenation/interpolation detectada",
                }
            )
            break
    return {
        "sandbox_evidence": sandbox_evidence,
        "traps": [trap.value for trap in traps],
        "violations": violations,
        "verified": not any(v["severity"] in {"high", "critical"} for v in violations),
    }


def _trap_to_violation(trap: VerificationTrap, evidence: dict[str, Any]) -> dict[str, Any]:
    severity = "high"
    message = f"Sandbox trap: {trap.value}"
    if trap == VerificationTrap.SYNTAX_ERROR:
        severity = "critical"
        message = str(evidence.get("syntax_error") or "Candidate has invalid Python syntax.")
    elif trap == VerificationTrap.SHELL_EXECUTION:
        severity = "critical"
        message = "Candidate uses shell execution or os.system."
    elif trap == VerificationTrap.UNSAFE_IMPORT:
        severity = "medium"
        imports = ", ".join((evidence.get("static_analysis") or {}).get("dangerous_imports") or [])
        message = f"Candidate imports dangerous modules: {imports}."
    elif trap == VerificationTrap.TEST_FAILURE:
        severity = "high"
        message = "Known repo tests failed in sandbox."
    elif trap == VerificationTrap.BANDIT_HIGH:
        severity = "high"
        message = "Bandit reported a high severity issue."

    return {
        "property": trap.value,
        "severity": severity,
        "message": message,
    }
