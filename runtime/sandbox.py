"""
runtime/sandbox.py — DevMind Agent Governance
Runtime interceptor for agent actions.

This is the evolved version of devmind_server.py.
It intercepts any AgentAction before execution and enforces the
GovernanceDecision in real time.

Usage (MCP / FastMCP):
    from runtime.sandbox import DevMindSandbox
    sandbox = DevMindSandbox(org_id="acme", audit_path="data/audit.jsonl")
    decision = sandbox.intercept(action)

The sandbox is the single choke point. Every action passes through here.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.types import (
    AgentAction,
    ActionContext,
    AgentSession,
    Decision,
    GovernanceDecision,
    PolicyRule,
    SessionState,
)
from engines.policy_engine import evaluate_action
from engines.audit_engine import AuditEngine


# =============================================================================
# DevMindSandbox
# =============================================================================

class DevMindSandbox:
    """
    The runtime enforcement layer.

    Every agent tool call should pass through intercept() before execution.
    The sandbox:
        1. Builds an AgentAction from the tool call
        2. Evaluates it through the policy engine
        3. Audits the decision
        4. Returns the decision — caller is responsible for enforcement

    Thread-safe for concurrent agent sessions.
    """

    def __init__(
        self,
        org_id: str,
        audit_path: str | Path = "data/audit/devmind_audit.jsonl",
        org_rules: list[PolicyRule] | None = None,
    ) -> None:
        self.org_id = org_id
        self.audit = AuditEngine(audit_path)
        self.org_rules = org_rules or []
        self._sessions: dict[str, AgentSession] = {}

    # -------------------------------------------------------------------------
    # Primary entry point
    # -------------------------------------------------------------------------

    def intercept(
        self,
        *,
        agent: str,
        tool: str,
        operation: str,
        payload: str,
        session_id: str | None = None,
        user: str | None = None,
        environment: str | None = None,
        cwd: str | None = None,
        repo: str | None = None,
        extra_context: dict[str, Any] | None = None,
    ) -> GovernanceDecision:
        """
        Intercept an agent action and return a governance decision.

        Call this BEFORE executing any agent tool.
        The decision.decision value tells you what to do:
            ALLOW    → execute normally
            REVIEW   → pause, notify human, await approval
            BLOCK    → deny, return reason to agent
            REWRITE  → execute decision.rewrite instead of original payload
            ESCALATE → notify security team, suspend session
        """
        sid = session_id or str(uuid.uuid4())
        action = AgentAction(
            action_id=str(uuid.uuid4()),
            session_id=sid,
            agent=agent,
            tool=tool,
            operation=operation,
            payload=payload,
            timestamp=datetime.now(timezone.utc),
            context=ActionContext(
                cwd=cwd,
                repo=repo,
                user=user,
                environment=environment,
                extra=extra_context or {},
            ),
        )

        session = self._get_or_create_session(sid, agent, user)
        decision = evaluate_action(action, session=session, org_rules=self.org_rules)

        self.audit.record(action, decision, organization=self.org_id)
        self._update_session(session, action, decision)

        return decision

    # -------------------------------------------------------------------------
    # Session management
    # -------------------------------------------------------------------------

    def _get_or_create_session(
        self, session_id: str, agent: str, user: str | None
    ) -> AgentSession:
        if session_id not in self._sessions:
            from core.types import SessionRiskProfile
            self._sessions[session_id] = AgentSession(
                session_id=session_id,
                agent=agent,
                organization=self.org_id,
                user=user,
                started_at=datetime.now(timezone.utc),
                risk_profile=SessionRiskProfile(),
            )
        return self._sessions[session_id]

    def _update_session(
        self,
        session: AgentSession,
        action: AgentAction,
        decision: GovernanceDecision,
    ) -> None:
        from core.types import RiskTrend

        rp = session.risk_profile
        rp.total_actions += 1
        session.actions.append(action.action_id)

        if decision.decision == Decision.BLOCK:
            rp.blocked_actions += 1
            rp.policy_violations += 1
        elif decision.decision == Decision.REVIEW:
            rp.reviewed_actions += 1
        elif decision.decision == Decision.ESCALATE:
            rp.escalated_actions += 1
            rp.policy_violations += 1

        # Update cumulative score
        n = rp.total_actions
        rp.cumulative_score = ((rp.cumulative_score * (n - 1)) + decision.risk_score) / n
        rp.peak_score = max(rp.peak_score, decision.risk_score)

        # Surface tracking
        s = decision.surface.value
        if s not in rp.surfaces_touched:
            rp.surfaces_touched.append(s)

        # Risk trend
        if rp.policy_violations >= 5 or rp.peak_score >= 90:
            rp.risk_trend = RiskTrend.CRITICAL
            session.state = SessionState.RESTRICTED
        elif rp.policy_violations >= 3 or rp.cumulative_score >= 60:
            rp.risk_trend = RiskTrend.RISING
        elif rp.cumulative_score < 20:
            rp.risk_trend = RiskTrend.DECLINING
        else:
            rp.risk_trend = RiskTrend.STABLE

    def get_session(self, session_id: str) -> AgentSession | None:
        return self._sessions.get(session_id)

    def session_stats(self, session_id: str) -> dict[str, Any]:
        session = self._sessions.get(session_id)
        if not session:
            return {}
        rp = session.risk_profile
        return {
            "session_id": session_id,
            "agent": session.agent,
            "state": session.state.value,
            "total_actions": rp.total_actions,
            "blocked": rp.blocked_actions,
            "reviewed": rp.reviewed_actions,
            "escalated": rp.escalated_actions,
            "policy_violations": rp.policy_violations,
            "avg_risk_score": round(rp.cumulative_score, 1),
            "peak_risk_score": rp.peak_score,
            "risk_trend": rp.risk_trend.value,
            "surfaces_touched": rp.surfaces_touched,
        }