"""
engines/infra_engine.py — DevMind Agent Governance
Infrastructure governance for Terraform, Kubernetes, and Helm changes.

Entry point: evaluate_change(change: AgentChange) -> GovernanceDecision

Decision ladder (mirrors policy_engine.py ordering):
    1. Hard blocks       — deterministic, no override (critical signals)
    2. Blast radius gate — ORG/ACCOUNT -> ESCALATE always
    3. Production escalation — critical signal + affects_production -> BLOCK
    4. Signal scoring    — weighted risk score from matched patterns
    5. Risk threshold    — >=85 BLOCK, >=30 REVIEW, else ALLOW

Never empty why_chain. Surface "*" signals apply across Terraform/K8s/Helm.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any

from core.types import (
    AgentChange,
    BlastRadius,
    ChangeType,
    Decision,
    GovernanceDecision,
    RiskBand,
)
from engines.terraform_semantic import (
    parse_terraform_plan,
    extract_semantic_signals,
    infer_blast_radius_from_plan,
)
from engines.k8s_semantic import (
    parse_k8s_manifest,
    extract_semantic_signals as extract_k8s_semantic_signals,
)

# =============================================================================
# Signal definitions — (name, severity_weight, surface, pattern)
# surface: "terraform" | "kubernetes" | "helm" | "*"
# =============================================================================

_SIGNALS: tuple[tuple[str, int, str, re.Pattern[str]], ...] = (
    # ---- Terraform ----------------------------------------------------
    ("iam_wildcard_action", 40, "terraform",
        re.compile(r'"Action"\s*:\s*"\*"|Action\s*=\s*(\["\*"\]|"\*")', re.IGNORECASE)),
    ("iam_wildcard_resource", 35, "terraform",
        re.compile(r'"Resource"\s*:\s*"\*"|Resource\s*=\s*(\["\*"\]|"\*")', re.IGNORECASE)),
    ("iam_admin_policy", 45, "terraform",
        re.compile(r'AdministratorAccess|arn:aws:iam::aws:policy/Administrator', re.IGNORECASE)),
    ("iam_assume_role_all", 35, "terraform",
        re.compile(r'sts:AssumeRole.*"\*"|Principal\s*=\s*"\*"', re.IGNORECASE | re.DOTALL)),
    ("public_s3_bucket", 40, "terraform",
        re.compile(r'acl\s*=\s*"public-read"|block_public_acls\s*=\s*false', re.IGNORECASE)),
    ("open_security_group", 40, "terraform",
        re.compile(r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]', re.IGNORECASE)),
    ("force_destroy", 25, "terraform",
        re.compile(r'force_destroy\s*=\s*true', re.IGNORECASE)),
    ("encryption_disabled", 30, "terraform",
        re.compile(r'encrypted\s*=\s*false|server_side_encryption_configuration\s*=\s*\{\s*\}', re.IGNORECASE)),
    ("hardcoded_secret", 45, "*",
        re.compile(r'(?i)(password|secret|api[_-]?key|token)\s*=\s*"[^"$]{6,}"')),
    ("prod_resource_name", 15, "*",
        re.compile(r'(?i)\b(prod|production)[-_][a-z0-9_-]+')),
    ("large_scale_change", 20, "terraform",
        re.compile(r'(?i)resources_changed\s*[:=]\s*([5-9]\d|\d{3,})')),

    # ---- Kubernetes -----------------------------------------------------
    ("privileged_container", 45, "kubernetes",
        re.compile(r'privileged\s*:\s*true', re.IGNORECASE)),
    ("host_network", 35, "kubernetes",
        re.compile(r'hostNetwork\s*:\s*true', re.IGNORECASE)),
    ("host_pid", 35, "kubernetes",
        re.compile(r'hostPID\s*:\s*true', re.IGNORECASE)),
    ("run_as_root", 25, "kubernetes",
        re.compile(r'runAsUser\s*:\s*0|runAsNonRoot\s*:\s*false', re.IGNORECASE)),
    ("privilege_escalation", 35, "kubernetes",
        re.compile(r'allowPrivilegeEscalation\s*:\s*true', re.IGNORECASE)),
    ("host_path_mount", 30, "kubernetes",
        re.compile(r'hostPath\s*:', re.IGNORECASE)),
    ("capabilities_add_all", 40, "kubernetes",
        re.compile(r'capabilities\s*:\s*\n?\s*add\s*:\s*\n?\s*-\s*ALL|add:\s*\["ALL"\]', re.IGNORECASE)),
    ("image_latest_tag", 15, "kubernetes",
        re.compile(r'image\s*:\s*[\w./-]+:latest\b', re.IGNORECASE)),
    ("excessive_replicas", 10, "kubernetes",
        re.compile(r'replicas\s*:\s*([1-9]\d{2,})', re.IGNORECASE)),
    ("cluster_admin_binding", 45, "kubernetes",
        re.compile(r'cluster-admin', re.IGNORECASE)),
    ("wildcard_rbac", 40, "kubernetes",
        re.compile(r'(?:verbs|resources|apiGroups)\s*:\s*\n?\s*-\s*"?\*"?', re.IGNORECASE)),
    ("kube_system_namespace", 20, "kubernetes",
        re.compile(r'namespace\s*:\s*kube-system', re.IGNORECASE)),
    ("secret_in_env", 35, "kubernetes",
        re.compile(r'(?i)(name\s*:\s*(password|secret|token|api_key)\s*\n\s*value\s*:)')),

    # ---- Helm -------------------------------------------------------------
    ("helm_production_target", 20, "helm",
        re.compile(r'(?i)(--namespace|namespace)\s*[:=]?\s*["\']?(prod|production)')),
    ("helm_privileged_values", 30, "helm",
        re.compile(r'securityContext.*privileged\s*:\s*true', re.IGNORECASE | re.DOTALL)),
    ("helm_image_latest", 15, "helm",
        re.compile(r'tag\s*:\s*["\']?latest["\']?', re.IGNORECASE)),
    ("helm_rbac_disabled", 20, "helm",
        re.compile(r'rbac\.create\s*[:=]\s*false|rbac:\s*\n\s*create:\s*false', re.IGNORECASE)),
    ("helm_tls_disabled", 25, "helm",
        re.compile(r'tls\.enabled\s*[:=]\s*false|tls:\s*\n\s*enabled:\s*false', re.IGNORECASE)),
)


# Signals that constitute a hard block regardless of score, when combined
# with production impact. These represent irreversible / org-wide exposure.
_CRITICAL_SIGNALS: frozenset[str] = frozenset({
    "iam_admin_policy",
    "iam_wildcard_action",
    "iam_wildcard_resource",
    "public_s3_bucket",
    "cluster_admin_binding",
    "privileged_container",
    "hardcoded_secret",
    "open_security_group",
})


# =============================================================================
# Surface routing — which signal surface applies to which ChangeType
# =============================================================================

_SURFACE_FOR_CHANGE: dict[ChangeType, str] = {
    ChangeType.TERRAFORM_PLAN:   "terraform",
    ChangeType.TERRAFORM_APPLY:  "terraform",
    ChangeType.K8S_MANIFEST:     "kubernetes",
    ChangeType.HELM_RELEASE:     "helm",
    ChangeType.IAM_CHANGE:       "terraform",
    ChangeType.SECRET_ROTATION:  "*",
    ChangeType.CONFIG_CHANGE:    "*",
    ChangeType.SCHEMA_MIGRATION: "*",
    ChangeType.CI_PIPELINE:      "*",
}


# =============================================================================
# Risk band mapping
# =============================================================================

def _band_for_score(score: int) -> RiskBand:
    if score >= 85:
        return RiskBand.CRITICAL
    if score >= 60:
        return RiskBand.HIGH
    if score >= 30:
        return RiskBand.MEDIUM
    if score >= 10:
        return RiskBand.LOW
    return RiskBand.MINIMAL


# =============================================================================
# Primary entry point
# =============================================================================

def evaluate_change(change: AgentChange) -> GovernanceDecision:
    """
    Evaluate an AgentChange (Terraform / Kubernetes / Helm) and return a
    GovernanceDecision.

    Ordering mirrors policy_engine.evaluate_action():
        1. Hard blocks (deterministic)
        2. Blast radius gate (ORG/ACCOUNT -> ESCALATE)
        3. Production escalation (critical signal + prod -> BLOCK)
        4. Signal-based risk scoring
        5. Risk threshold decision
    """
    why_chain: list[str] = []
    matched_signals: list[dict[str, Any]] = []

    target_surface = _SURFACE_FOR_CHANGE.get(change.change_type, "*")
    why_chain.append(
        f"Evaluating {change.change_type.value} on surface "
        f"'{change.surface.value}' (signal-surface: {target_surface})"
    )

    # -------------------------------------------------------------------
    # Step 0: Semantic parsing -- if payload is a real `terraform plan -json`
    # or Kubernetes Pod/Deployment YAML, extract structural signals with
    # certainty instead of relying only on regex over the raw string.
    # Additive: unparseable payloads fall through silently to regex matching.
    # -------------------------------------------------------------------
    score = 0
    critical_hit: str | None = None
    semantic_signals: list[dict[str, Any]] = []

    parsed_plan = parse_terraform_plan(change.payload)
    if parsed_plan is not None:
        semantic_signals = extract_semantic_signals(parsed_plan)
        if semantic_signals:
            why_chain.append(
                f"Semantic parse: valid terraform plan JSON detected, "
                f"{len(semantic_signals)} structural signal(s) found"
            )
        # Only fill in blast radius if caller left it at the default --
        # never override an explicitly declared value.
        if change.impact.blast_radius == BlastRadius.PROCESS:
            inferred = infer_blast_radius_from_plan(parsed_plan)
            if inferred is not None:
                change.impact.blast_radius = BlastRadius(inferred)
                why_chain.append(
                    f"Blast radius inferred from plan structure: {inferred} "
                    f"(no explicit blast_radius was declared)"
                )

    parsed_manifest = parse_k8s_manifest(change.payload)
    if parsed_manifest is not None:
        k8s_semantic_signals = extract_k8s_semantic_signals(parsed_manifest)
        semantic_signals.extend(k8s_semantic_signals)
        if k8s_semantic_signals:
            why_chain.append(
                f"Semantic parse: valid Kubernetes Pod/Deployment YAML detected, "
                f"{len(k8s_semantic_signals)} structural signal(s) found"
            )

    # -------------------------------------------------------------------
    # Step 1: Collect matched signals (regex, always run over raw payload)
    # -------------------------------------------------------------------
    for name, weight, sig_surface, pattern in _SIGNALS:
        if sig_surface != "*" and sig_surface != target_surface:
            continue
        if pattern.search(change.payload):
            score += weight
            matched_signals.append({
                "name": name,
                "severity": weight,
                "surface": sig_surface,
            })
            why_chain.append(f"Signal matched: {name} (+{weight})")
            if name in _CRITICAL_SIGNALS and critical_hit is None:
                critical_hit = name

    # -------------------------------------------------------------------
    # Step 1b: Fold in semantic signals from Step 0 (if any were found)
    # -------------------------------------------------------------------
    for sig in semantic_signals:
        score += sig["severity"]
        matched_signals.append(sig)
        why_chain.append(
            f"Semantic signal matched: {sig['name']} (+{sig['severity']}) -- {sig['detail']}"
        )

    score = min(score, 100)

    # -------------------------------------------------------------------
    # Step 2: Blast radius gate — ORG/ACCOUNT always escalate
    # -------------------------------------------------------------------
    if change.impact.blast_radius in (BlastRadius.ORG, BlastRadius.ACCOUNT):
        why_chain.append(
            f"Blast radius is {change.impact.blast_radius.value.upper()} "
            f"-> ESCALATE (irrecoverable scope, no override)"
        )
        return _decision(
            change, Decision.ESCALATE, score, why_chain, matched_signals,
            reason=(
                f"Change has {change.impact.blast_radius.value} blast radius. "
                f"Escalated for human review regardless of risk score."
            ),
            escalate_to="security-team",
        )

    # -------------------------------------------------------------------
    # Step 3: Hard blocks — critical signal alone, independent of env
    # -------------------------------------------------------------------
    # A critical signal with secrets exposure or IAM admin is always BLOCK,
    # even outside production, because the artifact itself is dangerous
    # (e.g. a hardcoded credential in a committed plan).
    if critical_hit in ("hardcoded_secret", "iam_admin_policy", "iam_wildcard_action", "iam_wildcard_resource"):
        why_chain.append(
            f"Hard block: '{critical_hit}' is a non-overridable critical signal"
        )
        return _decision(
            change, Decision.BLOCK, max(score, 90), why_chain, matched_signals,
            reason=f"Hard block triggered by critical signal: {critical_hit}",
        )

    # -------------------------------------------------------------------
    # Step 4: Production escalation — critical signal + prod -> BLOCK
    # -------------------------------------------------------------------
    if critical_hit and change.impact.affects_production:
        why_chain.append(
            f"Production escalation: critical signal '{critical_hit}' "
            f"+ affects_production=True -> BLOCK (no exceptions)"
        )
        return _decision(
            change, Decision.BLOCK, max(score, 90), why_chain, matched_signals,
            reason=(
                f"Critical signal '{critical_hit}' detected on a change "
                f"affecting production. Blocked unconditionally."
            ),
        )

    # -------------------------------------------------------------------
    # Step 5: Blast radius minimum for prod (SERVICE/CLUSTER -> min REVIEW)
    # -------------------------------------------------------------------
    if (
        change.impact.affects_production
        and change.impact.blast_radius in (BlastRadius.SERVICE, BlastRadius.CLUSTER)
        and score < 30
    ):
        why_chain.append(
            f"Production change with {change.impact.blast_radius.value} blast radius "
            f"-> minimum REVIEW regardless of low score ({score})"
        )
        return _decision(
            change, Decision.REVIEW, max(score, 30), why_chain, matched_signals,
            reason=(
                f"{change.impact.blast_radius.value.capitalize()}-scoped change "
                f"to production requires human review."
            ),
        )

    # -------------------------------------------------------------------
    # Step 6: Risk threshold decision
    # -------------------------------------------------------------------
    if score >= 85:
        decision = Decision.BLOCK
        reason = f"Cumulative risk score {score}/100 exceeds BLOCK threshold (85)."
    elif score >= 30:
        decision = Decision.REVIEW
        reason = f"Cumulative risk score {score}/100 exceeds REVIEW threshold (30)."
    else:
        decision = Decision.ALLOW
        reason = f"Cumulative risk score {score}/100 within acceptable bounds."

    why_chain.append(f"Final score {score}/100 -> {decision.value}")

    return _decision(change, decision, score, why_chain, matched_signals, reason=reason)


# =============================================================================
# Helper — build GovernanceDecision
# =============================================================================

def _decision(
    change: AgentChange,
    decision: Decision,
    score: int,
    why_chain: list[str],
    signals: list[dict[str, Any]],
    reason: str,
    escalate_to: str | None = None,
) -> GovernanceDecision:
    return GovernanceDecision(
        action_id=change.action_id or str(uuid.uuid4()),
        decision=decision,
        risk_score=score,
        band=_band_for_score(score),
        surface=change.surface,
        why_chain=why_chain,
        reason=reason,
        signals=signals,
        escalate_to=escalate_to,
    )
