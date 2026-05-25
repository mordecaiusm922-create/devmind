from __future__ import annotations
from dataclasses import dataclass
from typing import Any


@dataclass
class ResolvedDecision:
    action: str          # BLOCK / REVIEW / ALLOW
    reason: str          # razon principal
    confidence: str      # high / medium / low
    blocking_findings: list[str]
    risk_score: int
    policy_score: int
    why_chain: list[str]


def resolve_decision(
    *,
    # Pipeline viejo
    calibrated_score: int = 0,
    legacy_merge_blocker: bool = False,
    severity_floor: int = 0,
    severity_reason: str = "",
    safety_decision: str = "",
    selected: dict[str, Any] = {},
    has_findings: bool = False,
    # Nuevas capas
    ast_taint_detected: bool = False,
    ast_findings: list[dict] = [],
    cve_block_merge: bool = False,
    cve_findings: list[dict] = [],
    infra_block_merge: bool = False,
    infra_score: int = 0,
    infra_findings: list[dict] = [],
    # Policy engine
    policy_decision: str = "",
    policy_reason: str = "",
    policy_why_chain: list[str] = [],
) -> ResolvedDecision:

    blocking_findings = []
    why_chain = list(policy_why_chain) if policy_why_chain else []
    

    # Calibrar score catastrófico (critical findings destruyen el score)
    critical_finding = any(
        f.get("severity") == "critical" or f.get("rule_id", "").startswith("TAINT")
        for f in ast_findings + infra_findings + cve_findings
    )
    if critical_finding:
        policy_score = min(policy_score, 20)
        risk_score = max(risk_score, 90)
    # ── CAPA 1: Triggers determinísticos (siempre BLOCK) ──────────────
    
    if ast_taint_detected:
        blocking_findings.append("taint_flow_detected")
        why_chain.append("ast_taint_flow_critical")
        return ResolvedDecision(
            action="BLOCK",
            reason="Critical taint flow detected — user input reaches dangerous sink without sanitization.",
            confidence="high",
            blocking_findings=blocking_findings,
            risk_score=calibrated_score,
            policy_score=100,
            why_chain=why_chain + ["deployment_policy_block"]
        )
    
    if selected.get("critical_violations"):
        blocking_findings.append("critical_verification_violations")
        return ResolvedDecision(
            action="BLOCK",
            reason="Safety-flow found critical verification violations.",
            confidence="high",
            blocking_findings=blocking_findings,
            risk_score=calibrated_score,
            policy_score=90,
            why_chain=why_chain + ["critical_violations", "deployment_policy_block"]
        )
    
    if cve_block_merge:
        critical_cves = [f for f in cve_findings if f.get("severity") == "critical"]
        blocking_findings.append(f"{len(critical_cves)}_critical_cves")
        return ResolvedDecision(
            action="BLOCK",
            reason=f"Critical CVEs detected in dependencies: {', '.join(f.get('cve_id','') for f in critical_cves[:3])}",
            confidence="high",
            blocking_findings=blocking_findings,
            risk_score=calibrated_score,
            policy_score=95,
            why_chain=why_chain + ["critical_cve_detected", "deployment_policy_block"]
        )

    if infra_block_merge or infra_score >= 80:
        critical_infra = [f for f in infra_findings if f.get("severity") == "critical"]
        blocking_findings.append("critical_infra_findings")
        return ResolvedDecision(
            action="BLOCK",
            reason=f"Critical infrastructure security findings: {', '.join(f.get('title','') for f in critical_infra[:2])}",
            confidence="high",
            blocking_findings=blocking_findings,
            risk_score=calibrated_score,
            policy_score=infra_score,
            why_chain=why_chain + ["infra_critical_finding", "deployment_policy_block"]
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
            why_chain=why_chain + ["risk_floor_exceeded", "deployment_policy_block"]
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
            why_chain=why_chain + ["safety_flow_reject", "deployment_policy_block"]
        )

    # ── CAPA 2: Policy engine (BLOCK o REVISE) ────────────────────────

    if policy_decision == "BLOCK":
        blocking_findings.append(f"policy_block:{policy_reason}")
        return ResolvedDecision(
            action="BLOCK",
            reason=f"Policy engine: {policy_reason}",
            confidence="high",
            blocking_findings=blocking_findings,
            risk_score=calibrated_score,
            policy_score=80,
            why_chain=why_chain + ["policy_engine_block"]
        )

    # ── CAPA 3: REVIEW conditions ─────────────────────────────────────

    if safety_decision in {"revise", "needs_verification"}:
        return ResolvedDecision(
            action="REVIEW",
            reason="Safety-flow requires verification before this change can be trusted.",
            confidence="medium",
            blocking_findings=[],
            risk_score=calibrated_score,
            policy_score=calibrated_score,
            why_chain=why_chain + ["safety_flow_revise", "verification_required"]
        )

    if selected.get("violations"):
        return ResolvedDecision(
            action="REVIEW",
            reason="Safety-flow found unresolved verification violations.",
            confidence="medium",
            blocking_findings=[],
            risk_score=calibrated_score,
            policy_score=calibrated_score,
            why_chain=why_chain + ["violations_present", "review_required"]
        )

    high_ast = [f for f in ast_findings if f.get("severity") in ("high", "critical")]
    if high_ast:
        return ResolvedDecision(
            action="REVIEW",
            reason=f"High-severity code findings require review: {high_ast[0].get('title','')}",
            confidence="medium",
            blocking_findings=[],
            risk_score=calibrated_score,
            policy_score=60,
            why_chain=why_chain + ["high_ast_findings", "review_required"]
        )

    if policy_decision == "REVISE":
        return ResolvedDecision(
            action="REVIEW",
            reason=f"Policy engine: {policy_reason}",
            confidence="medium",
            blocking_findings=[],
            risk_score=calibrated_score,
            policy_score=50,
            why_chain=why_chain + ["policy_engine_revise"]
        )

    if has_findings or calibrated_score >= 55:
        return ResolvedDecision(
            action="REVIEW",
            reason="Security findings or elevated risk require review.",
            confidence="medium",
            blocking_findings=[],
            risk_score=calibrated_score,
            policy_score=calibrated_score,
            why_chain=why_chain + ["elevated_risk", "review_required"]
        )

    # ── CAPA 4: ALLOW ─────────────────────────────────────────────────

    return ResolvedDecision(
        action="ALLOW",
        reason="No blocking findings. Selected candidate passed all checks.",
        confidence="high",
        blocking_findings=[],
        risk_score=calibrated_score,
        policy_score=calibrated_score,
        why_chain=why_chain + ["all_checks_passed", "auto_approve"]
    )
