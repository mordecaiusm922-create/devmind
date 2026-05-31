from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any


@dataclass
class ResolvedDecision:
    action: str          # BLOCK / REVIEW / ALLOW
    reason: str          # razón principal
    confidence: str      # high / medium / low
    blocking_findings: list[str]
    risk_score: int
    policy_score: int
    why_chain: list[str]


_HARD_BLOCK_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(db[_-]?password|db[_-]?pass|secret[_-]?key|api[_-]?key|aws_secret_access_key)\b", re.I),
    re.compile(r"\bprivate key\b", re.I),
    re.compile(r"\beval\s*\(", re.I),
    re.compile(r"\|\s*bash\b", re.I),
    re.compile(r"curl\s+https?://", re.I),
    re.compile(r"\bverify\s*=\s*false\b", re.I),
    re.compile(r"\bdisable\s+ssl\b", re.I),
    re.compile(r"\bpublic-read\b", re.I),
    re.compile(r"\bwildcard\b", re.I),
    re.compile(r"\bprivileged\s*:\s*true\b", re.I),
    re.compile(r"\bhostnetwork\s*:\s*true\b", re.I),
    re.compile(r"\bforce_destroy\s*=\s*true\b", re.I),
    re.compile(r"\bremove input validation\b", re.I),
)

_TRIVIAL_SURFACE_HINTS = {
    "documentation",
    "comment_only",
    "frontend_only",
    "test_only",
    "dependency_only",
}

_AUTH_HINTS = {
    "oauth", "oauth2", "jwt", "authentication", "authorization",
    "login flow", "sso", "saml", "rbac", "session", "permissions",
}

_SENSITIVE_DOMAINS = {
    "payment", "billing", "auth", "credential", "token", "oauth", "security"
}

_BLOCK_INTENTS = {"sql_injection_fix", "secret_fix", "hardcoded_secret_fix"}
_REVIEW_INTENTS = {"secure_fix", "auth_fix"}

_CONTEXT_WEIGHTS: dict[str, float] = {
    "tests/": 0.15,
    "test_": 0.15,
    "_test.py": 0.15,
    "migrations/": 0.20,
    "docs/": 0.10,
    "scripts/": 0.30,
    ".md": 0.10,
    ".rst": 0.10,
    ".txt": 0.10,
    ".adoc": 0.10,
    "admin/": 0.70,
    "changelog": 0.10,
    "release": 0.20,
}

_CRITICAL_SEVERITIES = {"critical"}
_HIGH_SEVERITIES = {"high", "critical"}


def resolve_decision(
    *,
    calibrated_score: int = 0,
    legacy_merge_blocker: bool = False,
    severity_floor: int = 0,
    severity_reason: str = "",
    safety_decision: str = "",
    selected: dict[str, Any] | None = None,
    has_findings: bool = False,
    ast_taint_detected: bool = False,
    ast_findings: list[dict[str, Any]] | None = None,
    cve_block_merge: bool = False,
    cve_findings: list[dict[str, Any]] | None = None,
    infra_block_merge: bool = False,
    infra_score: int = 0,
    infra_findings: list[dict[str, Any]] | None = None,
    policy_decision: str = "",
    policy_reason: str = "",
    policy_why_chain: list[str] | None = None,
    pr_files: list[Any] | None = None,
) -> ResolvedDecision:
    selected = selected or {}
    ast_findings = ast_findings or []
    cve_findings = cve_findings or []
    infra_findings = infra_findings or []
    policy_why_chain = policy_why_chain or []
    pr_files = pr_files or []

    blocking_findings: list[str] = []
    why_chain = list(policy_why_chain)
    any_violations = bool(selected.get("violations") or selected.get("critical_violations"))

    surface = _detect_surface(pr_files)
    all_text = _build_text(
        selected=selected,
        ast_findings=ast_findings,
        cve_findings=cve_findings,
        infra_findings=infra_findings,
        pr_files=pr_files,
    )

    critical_finding = _has_critical_finding(ast_findings, infra_findings, cve_findings)
    if critical_finding:
        calibrated_score = max(calibrated_score, 90)

    attack_chain_score, attack_chain_path = _attack_chain_analysis(
        text=all_text,
        ast_taint_detected=ast_taint_detected,
        ast_findings=ast_findings,
        cve_findings=cve_findings,
        infra_findings=infra_findings,
        infra_score=infra_score,
        selected=selected,
    )
    if attack_chain_score >= 70:
        blocking_findings.append("attack_chain_detected")
        return ResolvedDecision(
            action="BLOCK",
            reason="Exploit chain detected across trust boundaries.",
            confidence="high",
            blocking_findings=blocking_findings,
            risk_score=max(calibrated_score, attack_chain_score),
            policy_score=100,
            why_chain=why_chain + attack_chain_path + ["deployment_policy_block"],
        )

    # Capa 1: triggers determinísticos
    if ast_taint_detected:
        blocking_findings.append("taint_flow_detected")
        why_chain.append("ast_taint_flow_critical")
        return ResolvedDecision(
            action="BLOCK",
            reason="Critical taint flow detected — user input reaches a dangerous sink without sanitization.",
            confidence="high",
            blocking_findings=blocking_findings,
            risk_score=max(calibrated_score, 95),
            policy_score=100,
            why_chain=why_chain + ["deployment_policy_block"],
        )

    if selected.get("critical_violations"):
        blocking_findings.append("critical_verification_violations")
        return ResolvedDecision(
            action="BLOCK",
            reason="Safety-flow found critical verification violations.",
            confidence="high",
            blocking_findings=blocking_findings,
            risk_score=max(calibrated_score, 90),
            policy_score=90,
            why_chain=why_chain + ["critical_violations", "deployment_policy_block"],
        )

    if cve_block_merge:
        critical_cves = [f for f in cve_findings if f.get("severity") in _CRITICAL_SEVERITIES]
        blocking_findings.append(f"{len(critical_cves)}_critical_cves")
        return ResolvedDecision(
            action="BLOCK",
            reason=f"Critical CVEs detected: {', '.join(f.get('cve_id', '') for f in critical_cves[:3])}",
            confidence="high",
            blocking_findings=blocking_findings,
            risk_score=max(calibrated_score, 95),
            policy_score=95,
            why_chain=why_chain + ["critical_cve_detected", "deployment_policy_block"],
        )

    if infra_block_merge or infra_score >= 80:
        critical_infra = [f for f in infra_findings if f.get("severity") in _CRITICAL_SEVERITIES]
        blocking_findings.append("critical_infra_findings")
        return ResolvedDecision(
            action="BLOCK",
            reason=f"Critical infrastructure findings: {', '.join(f.get('title', '') for f in critical_infra[:2])}",
            confidence="high",
            blocking_findings=blocking_findings,
            risk_score=max(calibrated_score, infra_score, 90),
            policy_score=max(infra_score, 90),
            why_chain=why_chain + ["infra_critical_finding", "deployment_policy_block"],
        )

    if legacy_merge_blocker or severity_floor >= 80 or calibrated_score >= 92:
        blocking_findings.append("risk_threshold_exceeded")
        return ResolvedDecision(
            action="BLOCK",
            reason=severity_reason or "Risk score exceeds deployment threshold.",
            confidence="high",
            blocking_findings=blocking_findings,
            risk_score=calibrated_score,
            policy_score=calibrated_score,
            why_chain=why_chain + ["risk_floor_exceeded", "deployment_policy_block"],
        )

    if safety_decision == "reject":
        blocking_findings.append("safety_flow_rejected")
        return ResolvedDecision(
            action="BLOCK",
            reason="Safety-flow rejected the best candidate.",
            confidence="high",
            blocking_findings=blocking_findings,
            risk_score=calibrated_score,
            policy_score=85,
            why_chain=why_chain + ["safety_flow_reject", "deployment_policy_block"],
        )

    # Capa 2: motor de policy
    if policy_decision == "BLOCK":
        blocking_findings.append(f"policy_block:{policy_reason}")
        return ResolvedDecision(
            action="BLOCK",
            reason=f"Policy engine: {policy_reason}",
            confidence="high",
            blocking_findings=blocking_findings,
            risk_score=calibrated_score,
            policy_score=80,
            why_chain=why_chain + ["policy_engine_block"],
        )

    if policy_decision == "REVISE":
        return ResolvedDecision(
            action="REVIEW",
            reason=f"Policy engine: {policy_reason}",
            confidence="medium",
            blocking_findings=[],
            risk_score=calibrated_score,
            policy_score=50,
            why_chain=why_chain + ["policy_engine_revise"],
        )

    if "auto_approve" in why_chain and not ast_taint_detected and not cve_block_merge and not infra_block_merge:
        return ResolvedDecision(
            action="ALLOW",
            reason="Policy engine auto-approved: trivial surface with no security signals.",
            confidence="high",
            blocking_findings=[],
            risk_score=calibrated_score,
            policy_score=calibrated_score,
            why_chain=why_chain + ["policy_auto_approve"],
        )

    # Capa 3: review
    trivial_surface = _is_trivial_surface(pr_files)
    is_trivial = trivial_surface and calibrated_score < 20 and not has_findings and not ast_taint_detected

    if safety_decision in {"revise", "needs_verification"} and not is_trivial:
        return ResolvedDecision(
            action="REVIEW",
            reason="Safety-flow requires verification before this change can be trusted.",
            confidence="medium",
            blocking_findings=[],
            risk_score=calibrated_score,
            policy_score=calibrated_score,
            why_chain=why_chain + ["safety_flow_revise", "verification_required"],
        )

    if selected.get("violations"):
        return ResolvedDecision(
            action="REVIEW",
            reason="Safety-flow found unresolved verification violations.",
            confidence="medium",
            blocking_findings=[],
            risk_score=calibrated_score,
            policy_score=calibrated_score,
            why_chain=why_chain + ["violations_present", "review_required"],
        )

    high_ast = [f for f in ast_findings if f.get("severity") in _HIGH_SEVERITIES]
    if high_ast:
        return ResolvedDecision(
            action="REVIEW",
            reason=f"High-severity code findings require review: {high_ast[0].get('title', '')}",
            confidence="medium",
            blocking_findings=[],
            risk_score=calibrated_score,
            policy_score=60,
            why_chain=why_chain + ["high_ast_findings", "review_required"],
        )

    if has_findings or calibrated_score >= 55:
        return ResolvedDecision(
            action="REVIEW",
            reason="Security findings or elevated risk require review.",
            confidence="medium",
            blocking_findings=[],
            risk_score=calibrated_score,
            policy_score=calibrated_score,
            why_chain=why_chain + ["elevated_risk", "review_required"],
        )

    # Capa 3.5: contexto del cambio
    if not ast_taint_detected and not cve_block_merge and not infra_block_merge:
        multiplier = _context_multiplier(pr_files, ast_findings, infra_findings)
        if multiplier < 1.0:
            calibrated_score = int(calibrated_score * multiplier)

    # Capa final: permitir solo si no hay señales relevantes
    if (
        not ast_taint_detected
        and not cve_block_merge
        and not infra_block_merge
        and not has_findings
        and not any_violations
        and calibrated_score < 55
        and not legacy_merge_blocker
    ):
        return ResolvedDecision(
            action="ALLOW",
            reason="No security findings, low risk floor, and no blocking signals.",
            confidence="high",
            blocking_findings=[],
            risk_score=calibrated_score,
            policy_score=calibrated_score,
            why_chain=why_chain + ["no_blocking_signals", "auto_approve"],
        )

    return ResolvedDecision(
        action="ALLOW",
        reason="No blocking findings. Selected candidate passed all checks.",
        confidence="high",
        blocking_findings=[],
        risk_score=calibrated_score,
        policy_score=calibrated_score,
        why_chain=why_chain + ["all_checks_passed", "auto_approve"],
    )


def _build_text(
    *,
    selected: dict[str, Any],
    ast_findings: list[dict[str, Any]],
    cve_findings: list[dict[str, Any]],
    infra_findings: list[dict[str, Any]],
    pr_files: list[Any],
) -> str:
    parts: list[str] = []

    parts.append(str(selected.get("reason", "")))
    parts.append(" ".join(map(str, selected.get("violations", []))))
    parts.append(" ".join(map(str, selected.get("critical_violations", []))))

    for finding in ast_findings + cve_findings + infra_findings:
        parts.append(" ".join(f"{k}={v}" for k, v in finding.items()))

    for item in pr_files:
        if isinstance(item, dict):
            parts.append(str(item.get("filename", "")))
            parts.append(str(item.get("path", "")))
            parts.append(str(item.get("content", "")))
        else:
            parts.append(str(item))

    return " ".join(parts).lower()


def _has_critical_finding(
    ast_findings: list[dict[str, Any]],
    infra_findings: list[dict[str, Any]],
    cve_findings: list[dict[str, Any]],
) -> bool:
    findings = ast_findings + infra_findings + cve_findings
    return any(
        f.get("severity") == "critical" or str(f.get("rule_id", "")).startswith("TAINT")
        for f in findings
    )


def _attack_chain_analysis(
    *,
    text: str,
    ast_taint_detected: bool,
    ast_findings: list[dict[str, Any]],
    cve_findings: list[dict[str, Any]],
    infra_findings: list[dict[str, Any]],
    infra_score: int,
    selected: dict[str, Any],
) -> tuple[int, list[str]]:
    score = 0
    chain: list[str] = []

    if ast_taint_detected:
        score += 45
        chain.append("taint_flow")

    if any(f.get("severity") in _HIGH_SEVERITIES for f in ast_findings):
        score += 20
        chain.append("high_ast_finding")

    if any(f.get("severity") in _HIGH_SEVERITIES for f in cve_findings):
        score += 30
        chain.append("critical_dependency_surface")

    if any(f.get("severity") in _HIGH_SEVERITIES for f in infra_findings):
        score += 25
        chain.append("infra_exposure")

    if infra_score >= 60:
        score += 20
        chain.append("infra_score_high")

    if selected.get("critical_violations"):
        score += 25
        chain.append("critical_verification_violations")

    if selected.get("violations"):
        score += 12
        chain.append("verification_violations")

    if _contains_any(text, {"password", "token", "secret", "credential", "api_key", "private key"}):
        score += 15
        chain.append("secret_surface")

    if _contains_any(text, _AUTH_HINTS):
        score += 10
        chain.append("auth_surface")

    if "eval(" in text or "| bash" in text or "curl http" in text:
        score += 35
        chain.append("dangerous_sink")

    if "public-read" in text or "0.0.0.0/0" in text or "privileged: true" in text:
        score += 30
        chain.append("exposure_surface")

    if score >= 70:
        chain.append("high_exploitability")
    elif score >= 45:
        chain.append("medium_exploitability")

    return min(100, score), chain


def _contains_any(text: str, phrases: set[str]) -> bool:
    return any(p in text for p in phrases)


def _is_trivial_surface(pr_files: list[Any]) -> bool:
    if not pr_files:
        return False

    paths = [_extract_path(item).lower() for item in pr_files if _extract_path(item)]
    if not paths:
        return False

    def match(path: str) -> float:
        w = 1.0
        for pat, val in _CONTEXT_WEIGHTS.items():
            if pat in path:
                w = min(w, val)
        return w

    weights = [match(p) for p in paths]
    if not weights:
        return False

    return max(weights) < 0.5


def _extract_path(item: Any) -> str:
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        return str(item.get("filename") or item.get("path") or "")
    return str(item)


def _context_multiplier(
    pr_files: list[Any],
    ast_findings: list[dict[str, Any]],
    infra_findings: list[dict[str, Any]],
) -> float:
    paths: list[str] = []

    for finding in ast_findings:
        path = str(finding.get("file", "") or finding.get("filename", "") or finding.get("path", ""))
        if path:
            paths.append(path)

    for finding in infra_findings:
        if isinstance(finding, str):
            paths.append(finding)

    if not paths:
        paths = [_extract_path(item) for item in pr_files if _extract_path(item)]

    if not paths:
        return 1.0

    weights = []
    for p in paths:
        path = p.lower()
        w = 1.0
        for pat, val in _CONTEXT_WEIGHTS.items():
            if pat in path:
                w = min(w, val)
        weights.append(w)

    return max(weights) if weights else 1.0