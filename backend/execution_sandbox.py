from __future__ import annotations

import ast
import re
from typing import Any


_PYTHON_EXTENSIONS = (".py", ".pyi")
_DANGEROUS_RUNTIME = re.compile(
    r"\beval\(|\bexec\(|shell\s*=\s*true|os\.system|pickle\.loads|yaml\.load\(|verify\s*=\s*false",
    re.IGNORECASE,
)


def verify_runtime_evidence(
    candidate: dict[str, Any],
    properties: list[str],
    representation: dict[str, Any],
) -> dict[str, Any]:
    """
    Deterministic local sandbox layer.

    This does not apply patches or touch production. It extracts the proposed added
    code and runs bounded checks that are safe inside the API process:
    syntax checks where possible, policy invariants, rollback markers, and
    property evidence. The result is shaped so a later container runner can plug
    into the same contract.
    """
    diff = str(candidate.get("diff") or "")
    filename = _candidate_filename(candidate, representation)
    added_code = _added_code(diff)
    checks: list[dict[str, Any]] = []

    checks.append(_syntax_check(filename, added_code))
    checks.append(_dangerous_runtime_check(added_code))
    checks.append(_property_evidence_check(properties, added_code))
    checks.append(_rollback_check(properties, added_code))

    failed = [check for check in checks if check["status"] == "fail"]
    warnings = [check for check in checks if check["status"] == "warn"]
    passed = [check for check in checks if check["status"] == "pass"]

    score = 1.0 - 0.22 * len(failed) - 0.08 * len(warnings)
    if checks and not passed:
        score -= 0.10
    score = max(0.0, min(1.0, score))

    return {
        "mode": "deterministic_local",
        "filename": filename,
        "status": "failed" if failed else "passed" if passed else "inconclusive",
        "score": round(score, 4),
        "checks": checks,
        "failed_checks": [check["name"] for check in failed],
        "warning_checks": [check["name"] for check in warnings],
    }


def _candidate_filename(candidate: dict[str, Any], representation: dict[str, Any]) -> str:
    diff = str(candidate.get("diff") or "")
    match = re.search(r"^diff --git a/\S+ b/(?P<right>\S+)", diff, re.MULTILINE)
    if match:
        return match.group("right")
    files = representation.get("files") or []
    if files:
        return str(files[0].get("filename") or "app.py")
    return "app.py"


def _added_code(diff: str) -> str:
    lines = []
    for line in diff.splitlines():
        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+"):
            lines.append(line[1:])
    return "\n".join(lines)


def _syntax_check(filename: str, code: str) -> dict[str, Any]:
    if not filename.lower().endswith(_PYTHON_EXTENSIONS):
        return {"name": "syntax", "status": "pass", "evidence": "Non-Python syntax delegated to policy checks."}

    if not code.strip():
        return {"name": "syntax", "status": "warn", "evidence": "No added Python code to parse."}

    try:
        ast.parse(code)
        return {"name": "syntax", "status": "pass", "evidence": "Added Python parses as a module."}
    except SyntaxError:
        try:
            ast.parse("if True:\n" + "\n".join(f"    {line}" for line in code.splitlines()))
            return {"name": "syntax", "status": "pass", "evidence": "Added Python parses as a block."}
        except SyntaxError as exc:
            return {"name": "syntax", "status": "warn", "evidence": f"Partial diff is not standalone parseable: {exc.msg}."}


def _dangerous_runtime_check(code: str) -> dict[str, Any]:
    match = _DANGEROUS_RUNTIME.search(code)
    if match:
        return {"name": "dangerous_runtime", "status": "fail", "evidence": match.group(0)}
    return {"name": "dangerous_runtime", "status": "pass", "evidence": "No direct dangerous runtime primitive detected."}


def _property_evidence_check(properties: list[str], code: str) -> dict[str, Any]:
    lower = code.lower()
    required_markers = {
        "secret_from_environment": ("os.environ", "os.getenv", "require_secret"),
        "parameterized_sql": ("execute(", "objects.filter", "%s"),
        "auth_guard_present": ("permission", "policy.", "is_admin", "requires_permission"),
        "least_privilege_infra": ("least_privilege", "private_cidr", "publicly_accessible = false", "sha256:"),
        "safe_ci_supply_chain": ("contents: read", "pin actions", "signature", "lockfile"),
        "dependency_policy": ("upgrade", "pin", "lockfile", "audit", "remove"),
        "data_safety_policy": ("backup", "pagination", "redact", "expand-contract", "rollback"),
        "runtime_safety_policy": ("bounded_timeout", "exponential_backoff", "payment_lock", "redact_sensitive"),
        "ai_safety_policy": ("sandbox", "rate limit", "sanitize", "access control", "secrets.token_urlsafe"),
        "human_review_policy": ("branch protection", "independent approval", "audit logs", "scoped role"),
    }
    active = [prop for prop in properties if prop in required_markers]
    if not active:
        return {"name": "property_evidence", "status": "pass", "evidence": "No runtime evidence marker required."}

    missing = [
        prop
        for prop in active
        if not any(marker in lower for marker in required_markers[prop])
    ]
    if missing:
        return {"name": "property_evidence", "status": "warn", "evidence": f"Missing markers: {', '.join(missing)}."}
    return {"name": "property_evidence", "status": "pass", "evidence": "Candidate contains expected safety markers."}


def _rollback_check(properties: list[str], code: str) -> dict[str, Any]:
    if "explicit_rollback_path" not in properties:
        return {"name": "rollback", "status": "pass", "evidence": "Rollback not required for this candidate."}

    lower = code.lower()
    if any(marker in lower for marker in ("rollback", "revert", "rollout undo", "previous module version", "terraform plan")):
        return {"name": "rollback", "status": "pass", "evidence": "Rollback marker present."}
    return {"name": "rollback", "status": "fail", "evidence": "Rollback property required but no rollback marker was found."}
