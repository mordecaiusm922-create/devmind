"""
runtime/backend_connector.py — DevMind Agent Governance
Conector entre el sandbox local y el backend LLM en Render.

Flujo de decisión:
    1. policy_engine (local, <5ms)  →  BLOCK/ALLOW → definitivo
    2. Si REVIEW                    →  consulta /safety-flow en Render
                                        Groq LLM decide con contexto semántico
                                        → decisión final enriquecida

El backend solo se consulta para casos ambiguos (REVIEW).
Hard blocks y ALLOWs claros nunca llegan al LLM — son deterministas.

GovernedSandbox extends DevMindSandbox:
    - Reuses session management, audit, intercept_change(), intercept_release()
      from the base class — no duplicated _get_or_create_session/_update_session.
    - Overrides intercept() only to add LLM escalation for REVIEW cases.
    - intercept_change()/intercept_release() are inherited as-is: infra_engine
      and release_gate are deterministic (no REVIEW→LLM path), so no override
      is needed for those.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from core.types import (
    AgentAction,
    AgentSession,
    Decision,
    GovernanceDecision,
    PolicyRule,
)
from engines.policy_engine import evaluate_action
from runtime.sandbox import DevMindSandbox


# =============================================================================
# Config
# =============================================================================

BACKEND_URL     = os.getenv("DEVMIND_BACKEND_URL", "https://devmind-2cej.onrender.com")
BACKEND_API_KEY = os.getenv("DEVMIND_BACKEND_API_KEY", "")
BACKEND_TIMEOUT = int(os.getenv("DEVMIND_BACKEND_TIMEOUT", "10"))
LLM_ENABLED     = os.getenv("DEVMIND_LLM_ENABLED", "true").lower() == "true"


# =============================================================================
# LLM escalation result
# =============================================================================

@dataclass
class LLMVerdict:
    decision:   Decision
    risk_score: int
    reason:     str
    llm_raw:    dict[str, Any]
    latency_ms: float


# =============================================================================
# Backend calls
# =============================================================================

def _post(endpoint: str, payload: dict[str, Any]) -> dict[str, Any]:
    """
    Simple HTTP POST — no external dependencies, uses stdlib urllib only.
    Returns parsed JSON response or raises on error.
    """
    url = f"{BACKEND_URL}{endpoint}"
    data = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "x-api-key": BACKEND_API_KEY,
        },
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=BACKEND_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _review(action: AgentAction, local_decision: GovernanceDecision) -> LLMVerdict:
    """
    Call /review on the Render backend.
    Used for fast semantic evaluation of a single AgentAction.
    """
    t0 = time.perf_counter()

    prompt = (
        f"Agent governance decision required.\n\n"
        f"Agent: {action.agent}\n"
        f"Tool: {action.tool}\n"
        f"Operation: {action.operation}\n"
        f"Environment: {action.context.environment or 'unknown'}\n"
        f"Payload: {action.payload[:500]}\n\n"
        f"Local policy engine flagged this as REVIEW.\n"
        f"Local signals: {[s['name'] for s in local_decision.signals]}\n"
        f"Local risk score: {local_decision.risk_score}/100\n"
        f"Local why_chain: {' → '.join(local_decision.why_chain[-4:])}\n\n"
        f"Should this action be ALLOWED, BLOCKED, or requires REVIEW?\n"
        f"Respond with JSON: {{\"decision\": \"ALLOW|BLOCK|REVIEW\", "
        f"\"risk_score\": 0-100, \"reason\": \"...\"}}"
    )

    raw = _post("/review", {"prompt": prompt, "context": {
        "agent": action.agent,
        "tool": action.tool,
        "operation": action.operation,
        "environment": action.context.environment,
        "surface": local_decision.surface.value,
        "local_score": local_decision.risk_score,
        "local_signals": [s["name"] for s in local_decision.signals],
    }})

    latency_ms = round((time.perf_counter() - t0) * 1000, 2)
    return _parse_llm_verdict(raw, latency_ms)


def _safety_flow(action: AgentAction, local_decision: GovernanceDecision) -> LLMVerdict:
    """
    Call /safety-flow for deeper analysis.
    Used when action is ambiguous or involves complex context.
    """
    t0 = time.perf_counter()

    prompt = (
        f"Evaluate this agent action for security and governance:\n\n"
        f"Agent: {action.agent} | Tool: {action.tool} | Op: {action.operation}\n"
        f"Environment: {action.context.environment or 'unknown'}\n"
        f"Payload: {action.payload[:800]}\n\n"
        f"Context: {json.dumps(vars(action.context))}\n"
        f"Local policy signals: {[s['name'] for s in local_decision.signals]}\n"
        f"Risk score: {local_decision.risk_score}/100\n\n"
        f"Provide governance decision: ALLOW, BLOCK, or REVIEW with justification."
    )

    raw = _post("/safety-flow", {
        "prompt": prompt,
        "candidates": [{
            "id": action.action_id,
            "diff": action.payload,
            "strategy": action.operation,
            "explanation": f"{action.tool}:{action.operation}",
        }],
        "context": {
            "agent": action.agent,
            "environment": action.context.environment,
            "surface": local_decision.surface.value,
        },
        "mode": "secure",
        "repo": action.context.repo,
    })

    latency_ms = round((time.perf_counter() - t0) * 1000, 2)
    return _parse_llm_verdict(raw, latency_ms)


def _parse_llm_verdict(raw: dict[str, Any], latency_ms: float) -> LLMVerdict:
    """Extract decision, score and reason from backend response."""

    # Try to find decision in various response shapes
    decision_str = None
    risk_score = 50
    reason = "llm_evaluated"

    # Direct fields
    if "decision" in raw:
        decision_str = str(raw["decision"]).upper()
    if "risk_score" in raw:
        risk_score = int(raw.get("risk_score", 50))
    if "reason" in raw:
        reason = str(raw["reason"])

    # Nested in result/response/output
    for key in ("result", "response", "output", "evaluation", "verdict"):
        if key in raw and isinstance(raw[key], dict):
            sub = raw[key]
            if "decision" in sub and not decision_str:
                decision_str = str(sub["decision"]).upper()
            if "risk_score" in sub:
                risk_score = int(sub.get("risk_score", risk_score))
            if "reason" in sub:
                reason = str(sub.get("reason", reason))

    # Try to parse JSON from text field
    if not decision_str:
        for key in ("text", "content", "message", "summary"):
            if key in raw:
                text = str(raw[key])
                try:
                    parsed = json.loads(text)
                    if "decision" in parsed:
                        decision_str = str(parsed["decision"]).upper()
                        risk_score = int(parsed.get("risk_score", risk_score))
                        reason = str(parsed.get("reason", reason))
                        break
                except Exception:
                    # Scan for keywords
                    if "BLOCK" in text.upper():
                        decision_str = "BLOCK"
                    elif "ALLOW" in text.upper():
                        decision_str = "ALLOW"
                    elif "REVIEW" in text.upper():
                        decision_str = "REVIEW"

    # Map to Decision enum
    decision_map = {
        "BLOCK": Decision.BLOCK,
        "ALLOW": Decision.ALLOW,
        "REVIEW": Decision.REVIEW,
        "ESCALATE": Decision.ESCALATE,
        "REWRITE": Decision.REWRITE,
    }
    decision = decision_map.get(decision_str or "", Decision.REVIEW)

    return LLMVerdict(
        decision=decision,
        risk_score=max(0, min(100, risk_score)),
        reason=f"llm:{reason[:200]}",
        llm_raw=raw,
        latency_ms=latency_ms,
    )


# =============================================================================
# GovernedSandbox — local + LLM hybrid, built on DevMindSandbox
# =============================================================================

class GovernedSandbox(DevMindSandbox):
    """
    Hybrid governance sandbox.

    Decision pipeline for intercept() (AgentAction / tool calls):
        1. Hard blocks  →  BLOCK immediately (no LLM call)
        2. ALLOW        →  pass through (no LLM call)
        3. REVIEW       →  escalate to Render LLM backend
                           LLM verdict upgrades or confirms local decision

    intercept_change() and intercept_release() (AgentChange / infra & release)
    are inherited unchanged from DevMindSandbox — infra_engine and
    release_gate are fully deterministic (BLOCK/REVIEW/ESCALATE/ALLOW with
    no ambiguous middle ground that needs LLM judgment), so no LLM
    escalation path applies there.

    This keeps latency low for safe actions and hard violations,
    while using LLM judgment only where it matters.
    """

    def __init__(
        self,
        org_id: str,
        audit_path: str = "data/audit/devmind_audit.jsonl",
        org_rules: list[PolicyRule] | None = None,
        llm_enabled: bool | None = None,
    ) -> None:
        super().__init__(org_id=org_id, audit_path=audit_path, org_rules=org_rules)
        self.llm_on = llm_enabled if llm_enabled is not None else LLM_ENABLED

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
        import uuid
        from datetime import datetime, timezone
        from core.types import ActionContext

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
                cwd=cwd, repo=repo, user=user,
                environment=environment,
                extra=extra_context or {},
            ),
        )

        session = self._get_or_create_session(sid, agent, user)

        # Step 1: local policy engine
        local = evaluate_action(action, session=session, org_rules=self.org_rules)

        # Step 2: LLM escalation only for REVIEW
        final = local
        if local.decision == Decision.REVIEW and self.llm_on:
            final = self._escalate_to_llm(action, local)

        self.audit.record(action, final, organization=self.org_id)
        self._update_session(session, action, final)
        return final

    def _escalate_to_llm(
        self,
        action: AgentAction,
        local: GovernanceDecision,
    ) -> GovernanceDecision:
        """Call Render backend and merge verdict with local decision."""
        try:
            verdict = _review(action, local)
        except urllib.error.URLError as e:
            # Backend unreachable — fail safe: keep local REVIEW
            local.why_chain.append(f"llm_unreachable:{e} → keep_local_review")
            return local
        except Exception as e:
            local.why_chain.append(f"llm_error:{type(e).__name__} → keep_local_review")
            return local

        # Merge: take the stricter of local vs LLM
        decisions_rank = {
            Decision.ALLOW: 0,
            Decision.REVIEW: 1,
            Decision.REWRITE: 2,
            Decision.ESCALATE: 3,
            Decision.BLOCK: 4,
        }
        final_decision = (
            verdict.decision
            if decisions_rank.get(verdict.decision, 1) >= decisions_rank.get(local.decision, 1)
            else local.decision
        )

        final_score = max(local.risk_score, verdict.risk_score)
        why_chain = local.why_chain + [
            f"llm_verdict:{verdict.decision.value}",
            f"llm_score:{verdict.risk_score}",
            f"llm_latency:{verdict.latency_ms}ms",
            f"final:{final_decision.value}",
        ]

        from engines.policy_engine import _band
        return GovernanceDecision(
            action_id=local.action_id,
            decision=final_decision,
            risk_score=final_score,
            band=_band(final_score),
            surface=local.surface,
            why_chain=why_chain,
            reason=verdict.reason,
            signals=local.signals,
            latency_ms=(local.latency_ms or 0) + verdict.latency_ms,
        )