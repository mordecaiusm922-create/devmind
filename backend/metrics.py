from __future__ import annotations
import os
import uuid
import json
from datetime import datetime, timezone
from typing import Any

def _get_supabase():
    try:
        from supabase import create_client
        url = os.getenv("SUPABASE_URL")
        key = os.getenv("SUPABASE_KEY") or os.getenv("SUPABASE_SERVICE_KEY")
        if not url or not key:
            return None
        return create_client(url, key)
    except Exception:
        return None

def record_decision(
    repo: str,
    pr_number: int,
    trace_id: str,
    action: str,
    reason: str,
    risk_score: int,
    policy_score: int,
    surface: str,
    intent: str,
    blocking_findings: list,
    ast_findings_count: int = 0,
    cve_findings_count: int = 0,
    infra_findings_count: int = 0,
    why_chain: list = [],
) -> bool:
    """Guarda cada decision de DevMind en Supabase para metricas."""
    try:
        sb = _get_supabase()
        if not sb:
            return False

        record = {
            "id": str(uuid.uuid4()),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "repo": repo,
            "pr_number": pr_number,
            "trace_id": trace_id,
            "action": action,
            "reason": reason,
            "risk_score": risk_score,
            "policy_score": policy_score,
            "surface": surface,
            "intent": intent,
            "blocking_findings": json.dumps(blocking_findings),
            "ast_findings_count": ast_findings_count,
            "cve_findings_count": cve_findings_count,
            "infra_findings_count": infra_findings_count,
            "why_chain": json.dumps(why_chain),
            "human_override": None,
            "override_reason": None,
            "was_correct": None,
        }

        sb.table("devmind_decisions").insert(record).execute()
        return True
    except Exception as e:
        print(f"metrics_record_failed: {e}")
        return False

def record_override(
    trace_id: str,
    override_type: str,
    override_reason: str = "",
) -> bool:
    """Registra cuando un humano hace override de una decision."""
    try:
        sb = _get_supabase()
        if not sb:
            return False
        sb.table("devmind_decisions").update({
            "human_override": override_type,
            "override_reason": override_reason,
        }).eq("trace_id", trace_id).execute()
        return True
    except Exception as e:
        print(f"metrics_override_failed: {e}")
        return False

def get_metrics(repo: str = None) -> dict:
    """Calcula metricas de precision del sistema."""
    try:
        sb = _get_supabase()
        if not sb:
            return {}

        query = sb.table("devmind_decisions").select("*")
        if repo:
            query = query.eq("repo", repo)
        result = query.execute()
        decisions = result.data or []

        if not decisions:
            return {"total": 0}

        total = len(decisions)
        blocks = sum(1 for d in decisions if d.get("action") == "BLOCK")
        approves = sum(1 for d in decisions if d.get("action") == "ALLOW")
        reviews = sum(1 for d in decisions if d.get("action") == "REVIEW")
        overrides = sum(1 for d in decisions if d.get("human_override"))
        override_rate = round(overrides / total * 100, 1) if total else 0

        by_surface = {}
        for d in decisions:
            s = d.get("surface", "unknown")
            if s not in by_surface:
                by_surface[s] = {"total": 0, "block": 0, "approve": 0}
            by_surface[s]["total"] += 1
            if d.get("action") == "BLOCK":
                by_surface[s]["block"] += 1
            elif d.get("action") == "ALLOW":
                by_surface[s]["approve"] += 1

        return {
            "total": total,
            "blocks": blocks,
            "approves": approves,
            "reviews": reviews,
            "override_rate_pct": override_rate,
            "overrides": overrides,
            "block_rate_pct": round(blocks / total * 100, 1),
            "by_surface": by_surface,
        }
    except Exception as e:
        print(f"metrics_get_failed: {e}")
        return {}
'@ | Out-File metrics.py -Encoding UTF8
echo "OK - metrics.py creado"