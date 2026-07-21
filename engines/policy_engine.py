"""
engines/policy_engine.py â€” DevMind Agent Governance
Policy engine for AgentAction evaluation.

This replaces the PR-based policy_engine.py.
Input:  AgentAction
Output: GovernanceDecision

Decision ladder (first match wins):
    1. Org custom rules          â€” configured per organization
    2. Hard block signals        â€” deterministic, no override
    3. Surface + operation gate  â€” based on what the action touches
    4. Session context gate      â€” rising risk / restricted state
    5. Payload signals           â€” pattern-based risk scoring
    6. Risk score threshold      â€” probabilistic fallback
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any

from core.types import (
    AgentAction,
    AgentSession,
    ActionSurface,
    Decision,
    GovernanceDecision,
    PolicyRule,
    RiskBand,
    RiskTrend,
    SessionState,
)


# =============================================================================
# Surface classification
# =============================================================================

# Maps (tool, operation) pairs to ActionSurface.
# Unmatched pairs fall back to UNKNOWN.
_SURFACE_MAP: dict[tuple[str, str], ActionSurface] = {
    # Terminal
    ("terminal", "execute"):         ActionSurface.TERMINAL,
    ("bash", "execute"):             ActionSurface.TERMINAL,
    ("shell", "execute"):            ActionSurface.TERMINAL,
    # Filesystem
    ("filesystem", "write"):         ActionSurface.FILESYSTEM,
    ("filesystem", "delete"):        ActionSurface.FILESYSTEM,
    ("filesystem", "read"):          ActionSurface.FILESYSTEM,
    ("file", "write"):               ActionSurface.FILESYSTEM,
    ("file", "delete"):              ActionSurface.FILESYSTEM,
    # Git
    ("git", "push"):                 ActionSurface.GIT,
    ("git", "commit"):               ActionSurface.GIT,
    ("git", "force_push"):           ActionSurface.GIT,
    # Network
    ("http", "request"):             ActionSurface.NETWORK,
    ("fetch", "request"):            ActionSurface.NETWORK,
    ("curl", "execute"):             ActionSurface.NETWORK,
    # Database
    ("database", "execute"):         ActionSurface.DATABASE,
    ("db", "execute"):               ActionSurface.DATABASE,
    ("sql", "execute"):              ActionSurface.DATABASE,
    # Cloud
    ("cloud", "deploy"):             ActionSurface.CLOUD,
    ("cloud", "delete"):             ActionSurface.CLOUD,
    ("cloud", "update_policy"):      ActionSurface.CLOUD,
    ("aws", "execute"):              ActionSurface.CLOUD,
    ("gcp", "execute"):              ActionSurface.CLOUD,
    ("azure", "execute"):            ActionSurface.CLOUD,
    # Deployment
    ("deploy", "execute"):           ActionSurface.DEPLOYMENT,
    ("kubernetes", "apply"):         ActionSurface.DEPLOYMENT,
    ("helm", "install"):             ActionSurface.DEPLOYMENT,
    # Secrets
    ("secrets", "read"):             ActionSurface.SECRETS,
    ("secrets", "write"):            ActionSurface.SECRETS,
    ("vault", "read"):               ActionSurface.SECRETS,
    ("env", "write"):                ActionSurface.SECRETS,
    # Code
    ("editor", "write"):             ActionSurface.CODE,
    ("code", "write"):               ActionSurface.CODE,
}

_DESTRUCTIVE_OPERATIONS = {
    "delete", "drop", "destroy", "force_push", "truncate",
    "remove", "purge", "wipe", "format", "kill",
}

_HIGH_PRIVILEGE_OPERATIONS = {
    "deploy", "update_policy", "grant_permission",
    "add_admin", "disable_mfa", "rotate_secret",
}


def classify_surface(tool: str, operation: str) -> ActionSurface:
    """Map (tool, operation) to ActionSurface. Fuzzy fallback by tool name."""
    key = (tool.lower(), operation.lower())
    if key in _SURFACE_MAP:
        return _SURFACE_MAP[key]

    # Fuzzy fallback on tool name
    t = tool.lower()
    if any(x in t for x in ("bash", "shell", "terminal", "cmd")):
        return ActionSurface.TERMINAL
    if any(x in t for x in ("file", "fs", "disk", "path")):
        return ActionSurface.FILESYSTEM
    if any(x in t for x in ("db", "database", "sql", "postgres", "mysql", "mongo")):
        return ActionSurface.DATABASE
    if any(x in t for x in ("cloud", "aws", "gcp", "azure", "s3", "ec2")):
        return ActionSurface.CLOUD
    if any(x in t for x in ("git", "github", "gitlab")):
        return ActionSurface.GIT
    if any(x in t for x in ("secret", "vault", "env", "credential")):
        return ActionSurface.SECRETS
    if any(x in t for x in ("deploy", "k8s", "helm", "docker")):
        return ActionSurface.DEPLOYMENT

    return ActionSurface.UNKNOWN


# =============================================================================
# Signal definitions â€” what patterns in the payload indicate risk
# =============================================================================

@dataclass(frozen=True)
class Signal:
    name:     str
    severity: str      # critical | high | medium | low
    surface:  str      # ActionSurface value or "*"
    pattern:  re.Pattern[str]


SIGNALS: tuple[Signal, ...] = (
    # --- Secrets & credentials ---
    Signal("hardcoded_secret",      "critical", "secrets",
           re.compile(r"\b(api[_-]?key|secret[_-]?key|password|token|private[_-]?key)\s*=\s*['\"][^'\"]+['\"]", re.I)),
    Signal("private_key",           "critical", "secrets",
           re.compile(r"-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----", re.I)),
    Signal("aws_credentials",       "critical", "secrets",
           re.compile(r"\baws_(access_key_id|secret_access_key)\b|AKIA[0-9A-Z]{16}", re.I)),

    # --- Command injection ---
    Signal("pipe_to_shell",         "critical", "terminal",
           re.compile(r"\|\s*(bash|sh|zsh|fish|cmd)\b", re.I)),
    Signal("eval_execution",        "critical", "terminal",
           re.compile(r"\beval\s*\(|exec\s*\(|__import__", re.I)),
    Signal("curl_pipe_bash",        "critical", "terminal",
           re.compile(r"curl\s+https?://[^\s]+\s*\|", re.I)),
    Signal("base64_decode_exec",    "critical", "terminal",
           re.compile(r"base64\s*(-d|--decode)\s*\|", re.I)),

    # --- Filesystem ---
    Signal("sensitive_path_write",  "critical", "filesystem",
           re.compile(r"/(etc/passwd|etc/shadow|etc/sudoers|proc/|sys/kernel)", re.I)),
    Signal("home_secrets_write",    "high",     "filesystem",
           re.compile(r"\~/.ssh/|\.aws/credentials|\.netrc|\.pgpass", re.I)),
    Signal("recursive_delete",      "critical", "filesystem",
           re.compile(r"rm\s+-[rf]+\s+(\/|~|\*|\$HOME|\$PWD)", re.I)),

    # --- Database ---
    Signal("sql_drop",              "critical", "*",
           re.compile(r"\b(drop\s+table|drop\s+database|truncate\s+table)\b", re.I)),
    Signal("sql_injection_pattern", "critical", "database",
           re.compile(r"execute\s*\([^,\n]*(\+|%|\.format\(|f['\"])", re.I)),
    Signal("mass_delete",           "critical", "*",
           re.compile(r"delete\s+from\s+\w+", re.I)),
    Signal("truncate_any",          "critical", "*",
           re.compile(r"\btruncate\s+(table\s+)?\w+", re.I)),

    # --- Cloud / Infrastructure ---
    Signal("terraform_destroy_cli", "critical", "terminal",
           re.compile(r"\bterraform\b[^\r\n]*\bdestroy\b", re.I)),
    Signal("terraform_auto_approve_destructive", "critical", "terminal",
           re.compile(r"\bterraform\b[^\r\n]*\b(destroy|apply)\b[^\r\n]*-auto-approve\b", re.I)),
    Signal("kubectl_delete_cli",     "critical", "terminal",
           re.compile(r"\bkubectl\b[^\r\n]*\bdelete\b", re.I)),
    Signal("helm_uninstall_cli",     "critical", "terminal",
           re.compile(r"\bhelm\b[^\r\n]*\buninstall\b", re.I)),
    Signal("iam_wildcard",          "critical", "cloud",
           re.compile(r"['\"]?[Aa]ction['\"]?\s*[:=]\s*['\"]?\*['\"]?|['\"]?[Rr]esource['\"]?\s*[:=]\s*['\"]?\*['\"]?|\*:\*", re.I)),
    Signal("public_cloud_resource", "critical", "*",
           re.compile(r"publicly.accessible\s*[=:]\s*true|0\.0\.0\.0/0|public-read|acl\s*[=:]\s*['\"]?public", re.I)),
    Signal("force_destroy",         "critical", "cloud",
           re.compile(r"force.destroy\s*=\s*true|--force\s+--delete|rb\s+s3://.*--force", re.I)),
    Signal("privileged_container",  "critical", "*",
           re.compile(r"privileged\s*[:=]\s*true|allowPrivilegeEscalation\s*[:=]\s*true|runAsUser\s*[:=]\s*0", re.I)),
    Signal("prod_env_detected",     "high",     "*",
           re.compile(r"\bprod(uction)?(?=[_\W]|$)|\bprd\b", re.I)),

    # --- Data exfiltration ---
    Signal("curl_post_file",        "critical", "terminal",
           re.compile(r"curl\s+.*-d\s+@/", re.I)),
    Signal("curl_post_external",    "high",     "terminal",
           re.compile(r"curl\s+-X\s+POST\s+https?://", re.I)),

    # --- Git ---
    Signal("force_push",            "high",     "git",
           re.compile(r"--force|--force-with-lease|-f\s+origin", re.I)),
    Signal("main_branch_direct",    "medium",   "git",
           re.compile(r"push\s+origin\s+(main|master|release|production)\b", re.I)),

    # --- Network exfiltration ---
    Signal("external_data_post",    "high",     "network",
           re.compile(r"(curl|wget|http\.post|requests\.post).*\|\s*(python|node|ruby|php)", re.I)),
    Signal("dns_tunneling",         "high",     "network",
           re.compile(r"\.(dnscat|iodine|dns2tcp)\b", re.I)),

    # --- Supply chain ---
    Signal("supply_chain_risk",     "high",     "terminal",
           re.compile(r"uses:\s*[\w.-]+/[\w.-]+@(main|master|latest)|pip install.*--pre\b", re.I)),
    Signal("untrusted_registry",    "high",     "terminal",
           re.compile(r"npm install.*--registry|pip install.*(http://|--index-url)", re.I)),
)

SEVERITY_WEIGHT: dict[str, float] = {
    "critical": 1.00,
    "high":     0.72,
    "medium":   0.48,
    "low":      0.20,
}


def _scan_signals(payload: str, surface: ActionSurface) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    payload_l = payload.lower()
    for signal in SIGNALS:
        if signal.surface not in ("*", surface.value):
            # Still check if pattern matches â€” surface mismatch is a mismatch
            # but critical cross-surface patterns (e.g. hardcoded_secret in terminal)
            # should still fire.
            if signal.severity != "critical":
                continue
        if signal.pattern.search(payload):
            findings.append({
                "name":     signal.name,
                "severity": signal.severity,
                "surface":  signal.surface,
                "weight":   SEVERITY_WEIGHT[signal.severity],
            })
    return findings


# =============================================================================
# Hard block patterns â€” deterministic, no override possible
# =============================================================================

HARD_BLOCK_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\|\s*(bash|sh|zsh)\b.*curl",              re.I),
    re.compile(r"curl\s+https?://[^\s]+\s*\|",             re.I),
    re.compile(r"\beval\s*[\(\$\`].*base64",               re.I),  # eval(...), eval $(...), eval `...`
    re.compile(r"\beval\s+\$\(.*\)",                       re.I),  # eval $(any subshell)
    re.compile(r"rm\s+-rf\s+/\s*$",                        re.I),
    re.compile(r"drop\s+table\s+users",                    re.I),
    re.compile(r"truncate\s+table\s+users",                re.I),
    re.compile(r"-----BEGIN\s.*PRIVATE KEY-----",          re.I),
    re.compile(r"AKIA[0-9A-Z]{16}",                        re.I),  # live AWS key
    re.compile(r"action\s*=\s*['\"]?\*['\"]?.*resource\s*=\s*['\"]?\*['\"]?", re.I),
)


# =============================================================================
# Risk scoring
# =============================================================================

def _score_from_signals(signals: list[dict[str, Any]]) -> int:
    if not signals:
        return 8
    score = 10
    for s in signals:
        w = float(s.get("weight", 0.2))
        if s["severity"] == "critical":
            score += int(55 * w)
        elif s["severity"] == "high":
            score += int(28 * w)
        elif s["severity"] == "medium":
            score += int(16 * w)
        else:
            score += int(8 * w)
    return max(0, min(100, score))


def _band(score: int) -> RiskBand:
    if score >= 85: return RiskBand.CRITICAL
    if score >= 65: return RiskBand.HIGH
    if score >= 40: return RiskBand.MEDIUM
    if score >= 20: return RiskBand.LOW
    return RiskBand.MINIMAL


# =============================================================================
# Session context gate
# =============================================================================

def _session_gate(
    session: AgentSession | None,
    chain: list[str],
) -> Decision | None:
    """
    Elevate decision based on accumulated session state.
    Returns an override Decision, or None to continue normal evaluation.
    """
    if session is None:
        return None

    rp = session.risk_profile

    if session.state == SessionState.SUSPENDED:
        chain.append("session:suspended â†’ BLOCK")
        return Decision.BLOCK

    if session.state == SessionState.RESTRICTED:
        chain.append("session:restricted â†’ ESCALATE")
        return Decision.ESCALATE

    if rp.risk_trend == RiskTrend.CRITICAL:
        chain.append("session:risk_trend=critical â†’ ESCALATE")
        return Decision.ESCALATE

    if rp.policy_violations >= 3:
        chain.append(f"session:policy_violations={rp.policy_violations} â†’ REVIEW")
        return Decision.REVIEW

    return None


# =============================================================================
# Org rule evaluation
# =============================================================================

def _apply_org_rules(
    action: AgentAction,
    surface: ActionSurface,
    rules: list[PolicyRule],
    chain: list[str],
) -> Decision | None:
    """
    Evaluate organization-specific policy rules.
    Returns first matching Decision, or None.
    """
    for rule in rules:
        if not rule.enabled:
            continue
        surface_match = rule.surface in ("*", surface.value)
        op_match = rule.operation in ("*", action.operation.lower())
        if not surface_match or not op_match:
            continue
        try:
            if re.search(rule.condition, action.payload, re.I):
                chain.append(f"org_rule:{rule.rule_id}:{rule.description}")
                return rule.decision
        except re.error:
            continue
    return None


# =============================================================================
# Main policy engine
# =============================================================================

def evaluate_action(
    action: AgentAction,
    session: AgentSession | None = None,
    org_rules: list[PolicyRule] | None = None,
) -> GovernanceDecision:
    """
    Evaluate a single AgentAction and return a GovernanceDecision.

    Decision ladder:
        1. Org custom rules
        2. Hard block patterns
        3. Destructive / high-privilege operation gate
        4. Session context gate
        5. Payload signal scoring
        6. Risk score threshold fallback
    """
    t0 = time.perf_counter()

    surface = classify_surface(action.tool, action.operation)
    chain: list[str] = [
        f"surface:{surface.value}",
        f"tool:{action.tool}",
        f"operation:{action.operation}",
        f"agent:{action.agent}",
    ]

    # 1. Hard block â€” ALWAYS first, no rule can override this
    for pattern in HARD_BLOCK_PATTERNS:
        if pattern.search(action.payload):
            chain.append(f"hardblock:{pattern.pattern[:60]}")
            signals = _scan_signals(action.payload, surface)
            return _verdict(action, Decision.BLOCK, 98, surface, chain, signals, t0,
                            reason="hardblock_pattern")

    # 2. Org custom rules â€” evaluated after hard blocks
    if org_rules:
        org_decision = _apply_org_rules(action, surface, org_rules, chain)
        if org_decision is not None:
            signals = _scan_signals(action.payload, surface)
            score = _score_from_signals(signals)
            return _verdict(action, org_decision, score, surface, chain, signals, t0,
                            reason="org_policy_rule")

    # 3. Scan signals early â€” needed for production escalation in operation gates
    _early_signals = _scan_signals(action.payload, surface)
    _env = (action.context.environment or "").lower()
    _is_prod = "prod" in _env
    _has_critical = any(s["severity"] == "critical" for s in _early_signals)

    op = action.operation.lower()
    if op in _DESTRUCTIVE_OPERATIONS:
        if _is_prod:
            chain.append(f"destructive_op:{op} on environment:production")
            return _verdict(action, Decision.BLOCK, 95, surface, chain, _early_signals, t0,
                            reason="destructive_on_production")
        chain.append(f"destructive_op:{op}")
        score = max(_score_from_signals(_early_signals), 65)
        return _verdict(action, Decision.REVIEW, score, surface, chain, _early_signals, t0,
                        reason="destructive_operation")

    # High-privilege operations: BLOCK if critical signal in production, else REVIEW
    if op in _HIGH_PRIVILEGE_OPERATIONS:
        chain.append(f"high_privilege_op:{op}")
        if _has_critical and _is_prod:
            chain.append("critical_signal+production â†’ BLOCK")
            return _verdict(action, Decision.BLOCK, 90, surface, chain, _early_signals, t0,
                            reason="critical_signal_in_production")
        score = max(_score_from_signals(_early_signals), 55)
        return _verdict(action, Decision.REVIEW, score, surface, chain, _early_signals, t0,
                        reason="high_privilege_operation")

    # 4. Session context gate
    session_override = _session_gate(session, chain)
    if session_override is not None:
        signals = _scan_signals(action.payload, surface)
        score = _score_from_signals(signals)
        return _verdict(action, session_override, score, surface, chain, signals, t0,
                        reason="session_context_gate")

    # 5. Signal scoring
    signals = _scan_signals(action.payload, surface)
    score = _score_from_signals(signals)

    if signals:
        chain.append(f"signals_found:{[s['name'] for s in signals]}")
    else:
        chain.append("no_risk_signals")

    # 6. Risk score threshold
    # Critical signal in production â†’ always BLOCK
    env = (action.context.environment or "").lower()
    is_production = "prod" in env
    has_critical = any(s["severity"] == "critical" for s in signals)

    if has_critical and is_production:
        score = max(score, 90)
        chain.append(f"critical_signal_in_production â†’ BLOCK")
        return _verdict(action, Decision.BLOCK, score, surface, chain, signals, t0,
                        reason="critical_signal_in_production")

    if score >= 85:
        chain.append(f"risk_score:{score} â†’ BLOCK")
        return _verdict(action, Decision.BLOCK, score, surface, chain, signals, t0,
                        reason="risk_threshold_block")

    if score >= 30:
        chain.append(f"risk_score:{score} â†’ REVIEW")
        return _verdict(action, Decision.REVIEW, score, surface, chain, signals, t0,
                        reason="risk_threshold_review")

    chain.append(f"risk_score:{score} â†’ ALLOW")
    return _verdict(action, Decision.ALLOW, score, surface, chain, signals, t0,
                    reason="no_risk_signals")


# =============================================================================
# Helpers
# =============================================================================

def _verdict(
    action: AgentAction,
    decision: Decision,
    score: int,
    surface: ActionSurface,
    chain: list[str],
    signals: list[dict[str, Any]],
    t0: float,
    reason: str,
    rewrite: str | None = None,
    escalate_to: str | None = None,
) -> GovernanceDecision:
    return GovernanceDecision(
        action_id=action.action_id,
        decision=decision,
        risk_score=max(0, min(100, score)),
        band=_band(score),
        surface=surface,
        why_chain=chain,
        reason=reason,
        signals=signals,
        rewrite=rewrite,
        escalate_to=escalate_to,
        latency_ms=round((time.perf_counter() - t0) * 1000, 2),
    )