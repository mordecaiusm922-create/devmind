"""
engines/audit_engine.py -- DevMind Agent Governance
Permanent audit trail for every AgentAction and GovernanceDecision.

Every action that passes through DevMind produces an AuditRecord.
These records answer:
    - What agent did this?
    - What did it try to do?
    - What did DevMind decide?
    - Why?
    - When?
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from core.types import AgentAction, AgentChange, ChangeType, GovernanceDecision


# =============================================================================
# AuditRecord Ã¢â‚¬â€ the immutable record of one governance event
# =============================================================================

@dataclass(frozen=True)
class AuditRecord:
    record_id:      str
    timestamp:      str           # ISO 8601 UTC
    action_id:      str
    session_id:     str
    agent:          str
    tool:           str
    operation:      str
    payload_hash:   str           # SHA-256 of payload, never the raw payload
    surface:        str
    decision:       str
    risk_score:     int
    band:           str
    reason:         str
    why_chain:      list[str]
    signals:        list[dict[str, Any]]
    latency_ms:     float | None
    environment:    str | None
    user:           str | None
    organization:   str | None


# =============================================================================
# AuditEngine
# =============================================================================

class AuditEngine:
    """
    Writes AuditRecords to a JSONL file (one record per line).
    JSONL is append-only, streaming-friendly, and trivially queryable.

    For production: swap _write() to insert into Supabase / ClickHouse.
    """

    def __init__(self, log_path: Path | str) -> None:
        self._path = Path(log_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def record(
        self,
        action: AgentAction,
        decision: GovernanceDecision,
        organization: str | None = None,
    ) -> AuditRecord:
        import hashlib
        import uuid

        payload_hash = hashlib.sha256(
            action.payload.encode("utf-8", errors="replace")
        ).hexdigest()

        rec = AuditRecord(
            record_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            action_id=action.action_id,
            session_id=action.session_id,
            agent=action.agent,
            tool=action.tool,
            operation=action.operation,
            payload_hash=payload_hash,
            surface=decision.surface.value,
            decision=decision.decision.value,
            risk_score=decision.risk_score,
            band=decision.band.value,
            reason=decision.reason,
            why_chain=decision.why_chain,
            signals=decision.signals,
            latency_ms=decision.latency_ms,
            environment=action.context.environment,
            user=action.context.user,
            organization=organization,
        )
        self._write(rec)
        return rec

    def record_change(
        self,
        change: AgentChange,
        decision: GovernanceDecision,
        organization: str | None = None,
    ) -> AuditRecord:
        """
        Audit entry point for AgentChange events (infrastructure / release).

        Mirrors record() but maps AgentChange's fields onto AuditRecord:
            - tool      -> change category ("infrastructure" | "release")
            - operation -> change.change_type.value

        AgentChange has no `tool`/`operation` because those are AgentAction
        concepts (tool calls). The mapping below derives the closest
        equivalent without forcing AgentChange to carry fields it doesn't
        conceptually own.
        """
        import hashlib
        import uuid

        _RELEASE_TYPES = (ChangeType.RELEASE_PUBLISH, ChangeType.RELEASE_PROMOTE)
        tool_category = "release" if change.change_type in _RELEASE_TYPES else "infrastructure"

        payload_hash = hashlib.sha256(
            change.payload.encode("utf-8", errors="replace")
        ).hexdigest()

        rec = AuditRecord(
            record_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            action_id=change.action_id,
            session_id=change.session_id,
            agent=change.agent,
            tool=tool_category,
            operation=change.change_type.value,
            payload_hash=payload_hash,
            surface=decision.surface.value,
            decision=decision.decision.value,
            risk_score=decision.risk_score,
            band=decision.band.value,
            reason=decision.reason,
            why_chain=decision.why_chain,
            signals=decision.signals,
            latency_ms=decision.latency_ms,
            environment=change.context.environment,
            user=change.context.user,
            organization=organization,
        )
        self._write(rec)
        return rec

    def _write(self, record: AuditRecord) -> None:
        row = {k: v for k, v in asdict(record).items()}
        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    def query(
        self,
        *,
        session_id: str | None = None,
        agent: str | None = None,
        decision: str | None = None,
        since: datetime | None = None,
        limit: int = 100,
    ) -> list[AuditRecord]:
        """Simple in-process query. Replace with DB query in production."""
        if not self._path.exists():
            return []

        results: list[AuditRecord] = []
        with self._path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if session_id and row.get("session_id") != session_id:
                    continue
                if agent and row.get("agent") != agent:
                    continue
                if decision and row.get("decision") != decision:
                    continue
                if since:
                    ts = datetime.fromisoformat(row.get("timestamp", ""))
                    if ts < since:
                        continue

                results.append(AuditRecord(**row))
                if len(results) >= limit:
                    break

        return results

    def stats(self, session_id: str | None = None) -> dict[str, Any]:
        """Aggregate stats Ã¢â‚¬â€ useful for session risk profiles."""
        records = self.query(session_id=session_id, limit=10_000)
        if not records:
            return {"total": 0}

        decisions: dict[str, int] = {}
        total_score = 0
        peak_score = 0

        for r in records:
            decisions[r.decision] = decisions.get(r.decision, 0) + 1
            total_score += r.risk_score
            peak_score = max(peak_score, r.risk_score)

        return {
            "total": len(records),
            "decisions": decisions,
            "avg_risk_score": round(total_score / len(records), 1),
            "peak_risk_score": peak_score,
        }

# =============================================================================
# SupabaseAuditEngine Ã¢â‚¬â€ production backend, survives Render redeploys
# =============================================================================

class SupabaseAuditEngine:
    """
    Same interface as AuditEngine (record, record_change, query, stats),
    backed by the 'audit_records' table in Supabase instead of a local
    JSONL file. Required because Render's free-tier filesystem is
    ephemeral -- anything written to disk is lost on every redeploy.

    Fails closed on write: if Supabase is unreachable, the governance
    decision itself is NOT blocked (the decision already happened), but
    the failure is printed so it's visible in Render logs instead of
    silently vanishing.
    """

    def __init__(self) -> None:
        self._client = None
        try:
            from supabase import create_client
            url = os.getenv("SUPABASE_URL")
            key = os.getenv("SUPABASE_KEY") or os.getenv("SUPABASE_SERVICE_KEY")
            if url and key:
                self._client = create_client(url, key)
            else:
                print("SupabaseAuditEngine: SUPABASE_URL/SUPABASE_KEY not set -- audit trail and token resolution disabled")
        except Exception as e:
            print(f"SupabaseAuditEngine: client init failed: {e}")

    def record(
        self,
        action: AgentAction,
        decision: GovernanceDecision,
        organization: str | None = None,
    ) -> AuditRecord | None:
        import hashlib
        import uuid

        payload_hash = hashlib.sha256(
            action.payload.encode("utf-8", errors="replace")
        ).hexdigest()

        rec = AuditRecord(
            record_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            action_id=action.action_id,
            session_id=action.session_id,
            agent=action.agent,
            tool=action.tool,
            operation=action.operation,
            payload_hash=payload_hash,
            surface=decision.surface.value,
            decision=decision.decision.value,
            risk_score=decision.risk_score,
            band=decision.band.value,
            reason=decision.reason,
            why_chain=decision.why_chain,
            signals=decision.signals,
            latency_ms=decision.latency_ms,
            environment=action.context.environment,
            user=action.context.user,
            organization=organization,
        )
        self._write(rec)
        return rec

    def record_change(
        self,
        change: AgentChange,
        decision: GovernanceDecision,
        organization: str | None = None,
    ) -> AuditRecord | None:
        import hashlib
        import uuid

        _RELEASE_TYPES = (ChangeType.RELEASE_PUBLISH, ChangeType.RELEASE_PROMOTE)
        tool_category = "release" if change.change_type in _RELEASE_TYPES else "infrastructure"

        payload_hash = hashlib.sha256(
            change.payload.encode("utf-8", errors="replace")
        ).hexdigest()

        rec = AuditRecord(
            record_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            action_id=change.action_id,
            session_id=change.session_id,
            agent=change.agent,
            tool=tool_category,
            operation=change.change_type.value,
            payload_hash=payload_hash,
            surface=decision.surface.value,
            decision=decision.decision.value,
            risk_score=decision.risk_score,
            band=decision.band.value,
            reason=decision.reason,
            why_chain=decision.why_chain,
            signals=decision.signals,
            latency_ms=decision.latency_ms,
            environment=change.context.environment,
            user=change.context.user,
            organization=organization,
        )
        self._write(rec)
        return rec

    def _write(self, record: AuditRecord) -> None:
        if self._client is None:
            print("SupabaseAuditEngine: no client, audit record dropped")
            return
        row = {k: v for k, v in asdict(record).items()}
        row["created_at"] = row.pop("timestamp")
        try:
            self._client.table("audit_records").insert(row).execute()
        except Exception as e:
            print(f"SupabaseAuditEngine: insert failed: {e}")

    def query(
        self,
        *,
        session_id: str | None = None,
        agent: str | None = None,
        decision: str | None = None,
        organization: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        if self._client is None:
            return []
        q = self._client.table("audit_records").select("*")
        if session_id:
            q = q.eq("session_id", session_id)
        if agent:
            q = q.eq("agent", agent)
        if decision:
            q = q.eq("decision", decision)
        if organization:
            q = q.eq("organization", organization)
        q = q.order("created_at", desc=True).limit(limit)
        try:
            result = q.execute()
            return result.data or []
        except Exception as e:
            print(f"SupabaseAuditEngine: query failed: {e}")
            return []

    def stats(self, organization: str | None = None) -> dict[str, Any]:
        records = self.query(organization=organization, limit=10_000)
        if not records:
            return {"total": 0}

        decisions: dict[str, int] = {}
        total_score = 0
        peak_score = 0
        for r in records:
            d = r.get("decision", "unknown")
            decisions[d] = decisions.get(d, 0) + 1
            total_score += r.get("risk_score", 0)
            peak_score = max(peak_score, r.get("risk_score", 0))

        return {
            "total": len(records),
            "decisions": decisions,
            "avg_risk_score": round(total_score / len(records), 1),
            "peak_risk_score": peak_score,
        }
