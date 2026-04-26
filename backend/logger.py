import os
import json
from datetime import datetime, timezone
from pathlib import Path
import httpx

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")

# Fallback local log
LOG_DIR = Path(__file__).parent / "logs"
LOG_FILE = LOG_DIR / "analyses.jsonl"


def log_analysis(
    repo: str,
    pr_number: int,
    pr_data: dict,
    summary: dict,
    pre_analysis,
    evaluation,
) -> None:
    try:
        risk = summary.get("risk") or {}
        files = pr_data.get("files", [])
        tags = set(pre_analysis.risk_tags)

        payload = {
            "repo": repo,
            "pr_number": pr_number,
            "files_changed": [f.get("filename", "") for f in files],
            "lines_added": pr_data.get("additions", 0),
            "lines_removed": pr_data.get("deletions", 0),
            "files_count": pr_data.get("changed_files", 0),
            "touches_auth": "auth" in tags,
            "touches_payment": "payments" in tags,
            "complexity_score": float(evaluation.specificity_score),
            "risk_score": float(evaluation.confidence_score),
            "risk_level": risk.get("level", "unknown"),
            "factors": pre_analysis.risk_tags,
            "vulnerabilities": summary.get("vulnerabilities") or [],
        }

        if SUPABASE_URL and SUPABASE_KEY:
            httpx.post(
                f"{SUPABASE_URL}/rest/v1/pr_analysis",
                headers={
                    "apikey": SUPABASE_KEY,
                    "Authorization": f"Bearer {SUPABASE_KEY}",
                    "Content-Type": "application/json",
                    "Prefer": "return=minimal",
                },
                json=payload,
                timeout=5,
            )

        # Always save locally as backup
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "ts": datetime.now(timezone.utc).isoformat(),
                **payload
            }) + "\n")

    except Exception:
        pass


def read_recent_logs(n: int = 20) -> list[dict]:
    if not LOG_FILE.exists():
        return []
    try:
        lines = LOG_FILE.read_text(encoding="utf-8").strip().splitlines()
        records = []
        for line in reversed(lines[-n * 2:]):
            try:
                records.append(json.loads(line))
                if len(records) >= n:
                    break
            except json.JSONDecodeError:
                continue
        return records
    except Exception:
        return []
