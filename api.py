"""
api.py -- DevMind Governance API
FastAPI wrapper over the governance engines.

Endpoints:
    POST /evaluate          -- AgentAction -> GovernanceDecision
    POST /evaluate-change   -- AgentChange (Terraform/K8s/Helm) -> GovernanceDecision
    POST /release-gate      -- SessionAudit -> ReleaseDecision
    GET  /health            -- liveness check
    GET  /simulate          -- run 28 real-world scenarios, return report
"""
from __future__ import annotations

import uuid
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from core.types import (
    AgentAction,
    AgentChange,
    AgentSession,
    ActionContext,
    ActionSurface,
    BlastRadius,
    ChangeImpact,
    ChangeType,
    Decision,
    GovernanceDecision,
    Organization,
    SessionRiskProfile,
    SessionState,
)
from engines.policy_engine import evaluate_action
from engines.infra_engine import evaluate_change
from engines.release_gate import evaluate_release, SessionAudit, ArtifactScan
from engines.audit_engine import SupabaseAuditEngine

import time
from collections import defaultdict
from fastapi import Depends

# -- Simple in-memory rate limiter (per-IP sliding window) --
# Not distributed-safe (resets if the process restarts, and does not
# share state across multiple Render instances) -- sufficient for a
# single free-tier instance. Revisit with a shared store (Redis) if
# this service ever scales to multiple processes.
_rate_limit_buckets: dict[str, list[float]] = defaultdict(list)
RATE_LIMIT_MAX_REQUESTS = 20
RATE_LIMIT_WINDOW_SECONDS = 60


async def rate_limit(request: Request) -> None:
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    bucket = _rate_limit_buckets[client_ip]
    while bucket and now - bucket[0] > RATE_LIMIT_WINDOW_SECONDS:
        bucket.pop(0)
    if len(bucket) >= RATE_LIMIT_MAX_REQUESTS:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded: max {RATE_LIMIT_MAX_REQUESTS} requests per {RATE_LIMIT_WINDOW_SECONDS}s.",
        )
    bucket.append(now)

# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="DevMind Governance API",
    description="Runtime governance for autonomous AI agents.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


audit = SupabaseAuditEngine()

async def resolve_org_from_token(request: Request) -> tuple[str, str | None] | None:
    """Phase 1 permissive auth: use the real org_id (and, if the
    credential is scoped to one, the agent_id) from a valid Bearer
    token if present; otherwise return None so callers fall back to
    the body-supplied org_id (today's behavior), logged loudly for
    visibility.

    Returns (org_id, agent_id) where agent_id is None if the
    credential is not scoped to a single agent (org-wide token).
    """
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        print("AUTH: no bearer token -- falling back to body org_id")
        return None
    raw_token = auth_header.removeprefix("Bearer ").strip()
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    if audit._client is None:
        print("AUTH: no Supabase client -- falling back to body org_id")
        return None
    try:
        result = (
            audit._client.table("api_credentials")
            .select("org_id, agent_id, revoked_at")
            .eq("token_hash", token_hash)
            .single()
            .execute()
        )
    except Exception as e:
        print(f"AUTH: token lookup failed: {e}")
        return None
    if not result.data or result.data.get("revoked_at") is not None:
        raise HTTPException(status_code=401, detail="Invalid or revoked token")
    try:
        audit._client.table("api_credentials").update(
            {"last_used_at": datetime.now(timezone.utc).isoformat()}
        ).eq("token_hash", token_hash).execute()
    except Exception:
        pass
    return result.data["org_id"], result.data.get("agent_id")


# ── Request schemas ───────────────────────────────────────────────────────────

class EvaluateActionRequest(BaseModel):
    agent_id: str                           # e.g. "cursor-agent", "claude-code"
    tool: str                               # e.g. "database", "filesystem", "cloud"
    operation: str                          # e.g. "execute", "delete", "write"
    payload: str                            # raw action content
    session_id: Optional[str] = None
    org_id: Optional[str] = None
    environment: Optional[str] = None
    user: Optional[str] = None

class EvaluateChangeRequest(BaseModel):
    agent_id: str
    change_type: str                        # DELETE, CREATE, MODIFY, DEPLOY, SCALE
    surface: str                            # terraform, kubernetes, helm, database
    payload: str                            # raw change content / diff summary
    affects_production: bool = False
    blast_radius: Optional[str] = None     # process, service, cluster, account, org
    session_id: Optional[str] = None
    diff_summary: Optional[str] = None
    org_id: Optional[str] = None

class ReleaseGateRequest(BaseModel):
    agent_id: str
    session_id: Optional[str] = None
    change_type: str = "release_publish"
    payload: str = ""
    diff_summary: Optional[str] = None
    artifact_ref: Optional[str] = None
    affects_production: bool = False
    org_id: Optional[str] = None
    total_actions: int = 0
    policy_violations: int = 0
    blocked_actions: int = 0
    escalated_actions: int = 0
    cumulative_score: float = 0.0
    peak_score: int = 0

class DecisionResponse(BaseModel):
    decision: str
    risk_score: float
    why: List[str]
    escalation_required: bool
    audit_id: str
    agent_id: str
    timestamp: str

# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_session(agent_id: str, session_id: Optional[str], org_id: Optional[str]) -> AgentSession:
    return AgentSession(
        session_id=session_id or str(uuid.uuid4()),
        agent=agent_id,
        organization=org_id or "default",
        user=None,
        started_at=datetime.now(timezone.utc),
    )

def _decision_response(decision: GovernanceDecision, agent_id: str) -> DecisionResponse:
    return DecisionResponse(
        decision=decision.decision.value,
        risk_score=float(decision.risk_score),
        why=decision.why_chain,
        escalation_required=(decision.decision.value in ("ESCALATE", "BLOCK")),
        audit_id=decision.action_id,
        agent_id=agent_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.api_route("/health", methods=["GET", "HEAD"])
def health():
    return {"status": "ok", "service": "devmind-governance-api", "version": "1.0.0"}


@app.post("/evaluate", response_model=DecisionResponse, dependencies=[Depends(rate_limit)])
async def evaluate(request: Request, req: EvaluateActionRequest):
    """
    Evaluate an AgentAction against the policy engine.

    Example (PocketOS scenario):
        {
            "agent_id": "cursor-agent",
            "tool": "cloud",
            "operation": "delete_volume",
            "payload": "railway-production-volume",
            "affects_production": true
        }
    """
    resolved = await resolve_org_from_token(request)
    if resolved is not None:
        resolved_org, bound_agent_id = resolved
        req.org_id = resolved_org
        if bound_agent_id is not None and bound_agent_id != req.agent_id:
            raise HTTPException(
                status_code=403,
                detail=f"This credential is scoped to agent '{bound_agent_id}', not '{req.agent_id}'.",
            )

    session_id = req.session_id or str(uuid.uuid4())

    context = ActionContext(
        user=req.user,
        environment=req.environment,
    )

    action = AgentAction(
        action_id=str(uuid.uuid4()),
        session_id=session_id,
        agent=req.agent_id,
        tool=req.tool,
        operation=req.operation,
        payload=req.payload,
        timestamp=datetime.now(timezone.utc),
        context=context,
    )
    session = _make_session(req.agent_id, session_id, req.org_id)

    try:
        decision = evaluate_action(action, session)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    audit.record(action, decision, organization=req.org_id)

    return _decision_response(decision, req.agent_id)


@app.post("/evaluate-change", response_model=DecisionResponse, dependencies=[Depends(rate_limit)])
async def evaluate_infra_change(request: Request, req: EvaluateChangeRequest):
    """
    Evaluate an infrastructure change (Terraform, K8s, Helm, DB) against the infra engine.

    Example (PocketOS scenario):
        {
            "agent_id": "cursor-agent",
            "change_type": "DELETE",
            "surface": "database",
            "payload": "deleteVolume railway-production-volume",
            "affects_production": true,
            "blast_radius": "org"
        }
    """
    resolved = await resolve_org_from_token(request)
    if resolved is not None:
        resolved_org, bound_agent_id = resolved
        req.org_id = resolved_org
        if bound_agent_id is not None and bound_agent_id != req.agent_id:
            raise HTTPException(
                status_code=403,
                detail=f"This credential is scoped to agent '{bound_agent_id}', not '{req.agent_id}'.",
            )
    try:
        change_type = ChangeType(req.change_type.lower())
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid change_type: {req.change_type}. Valid: {[e.value for e in ChangeType]}"
        )

    try:
        surface = ActionSurface(req.surface.lower())
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid surface: {req.surface}. Valid: {[e.value for e in ActionSurface]}"
        )

    impact = ChangeImpact()
    if req.affects_production:
        impact.affects_production = True
    if req.blast_radius:
        try:
            impact.blast_radius = BlastRadius(req.blast_radius.lower())
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid blast_radius: {req.blast_radius}. Valid: {[e.value for e in BlastRadius]}"
            )

    change = AgentChange(
        action_id=str(uuid.uuid4()),
        session_id=req.session_id or str(uuid.uuid4()),
        agent=req.agent_id,
        change_type=change_type,
        surface=surface,
        payload=req.payload,
        timestamp=datetime.now(timezone.utc),
        impact=impact,
        diff_summary=req.diff_summary,
    )

    try:
        decision = evaluate_change(change)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    audit.record_change(change, decision, organization=req.org_id)

    return _decision_response(decision, req.agent_id)


@app.post("/release-gate", response_model=DecisionResponse, dependencies=[Depends(rate_limit)])
async def release_gate(request: Request, req: ReleaseGateRequest):
    """Run the release gate: evaluate_release derives SessionAudit + ArtifactScan internally."""
    resolved = await resolve_org_from_token(request)
    if resolved is not None:
        resolved_org, bound_agent_id = resolved
        req.org_id = resolved_org
        if bound_agent_id is not None and bound_agent_id != req.agent_id:
            raise HTTPException(
                status_code=403,
                detail=f"This credential is scoped to agent '{bound_agent_id}', not '{req.agent_id}'.",
            )
    try:
        change_type = ChangeType(req.change_type.lower())
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid change_type: {req.change_type}. Valid: release_publish, release_promote"
        )

    change = AgentChange(
        action_id=str(uuid.uuid4()),
        session_id=req.session_id or str(uuid.uuid4()),
        agent=req.agent_id,
        change_type=change_type,
        surface=ActionSurface.RELEASE,
        payload=req.payload,
        timestamp=datetime.now(timezone.utc),
        impact=ChangeImpact(affects_production=req.affects_production),
        diff_summary=req.diff_summary,
        artifact_ref=req.artifact_ref,
    )

    session = AgentSession(
        session_id=req.session_id or change.session_id,
        agent=req.agent_id,
        organization=req.org_id or "default",
        user=None,
        started_at=datetime.now(timezone.utc),
        risk_profile=SessionRiskProfile(
            total_actions=req.total_actions,
            policy_violations=req.policy_violations,
            blocked_actions=req.blocked_actions,
            escalated_actions=req.escalated_actions,
            cumulative_score=req.cumulative_score,
            peak_score=req.peak_score,
        ),
    )

    try:
        decision = evaluate_release(change, session)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    audit.record_change(change, decision, organization=req.org_id)

    return _decision_response(decision, req.agent_id)


@app.get("/simulate")
def simulate():
    """Run the 28 real-world risk scenarios and return the full report."""
    import subprocess
    import sys
    import json as _json
    import pathlib

    try:
        result = subprocess.run(
            [sys.executable, "simulate_real_risks.py"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        report_path = pathlib.Path("data/audit/simulation_summary.json")
        if report_path.exists():
            return JSONResponse(
                content=_json.loads(report_path.read_text(encoding="utf-8"))
            )
        return JSONResponse(content={
            "status": "ok",
            "stdout": result.stdout[-3000:] if result.stdout else "",
            "returncode": result.returncode,
        })
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Simulation timed out")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))