"""
logger.py — lightweight append-only JSONL logger for DevMind analyses.

Each analysis writes one JSON line to logs/analyses.jsonl.
No database, no external deps — just the stdlib.

Schema per line:
{
  "ts":                  ISO-8601 timestamp,
  "repo":                "owner/repo",
  "pr_number":           int,
  "input": {
    "changed_files":     int,
    "files_with_diff":   int,
    "files_skipped_noise":   int,
    "files_skipped_budget":  int,
    "total_diff_chars":  int,
    "is_large_pr":       bool,
    "used_chunking":     bool,
    "chunks_count":      int | null,
    "risk_tags_detected": [str],
  },
  "output": {
    "summary_total_chars":  int,
    "what_chars":           int,
    "key_changes_count":    int,
    "risk_level":           str,
    "confidence":           str,
    "confidence_score":     float,
    "specificity_score":    float,
    "generic_penalty":      int,
    "is_flagged":           bool,
    "flag_reason":          str | null,
  }
}
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

LOG_DIR = Path(__file__).parent / "logs"
LOG_FILE = LOG_DIR / "analyses.jsonl"


def log_analysis(
    repo: str,
    pr_number: int,
    pr_data: dict,
    summary: dict,
    pre_analysis,   # evaluator.PreAnalysis
    evaluation,     # evaluator.Evaluation
) -> None:
    """
    Appends one line to logs/analyses.jsonl.
    Silently swallows any I/O error — logging must never crash the main path.
    """
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)

        summary_text = " ".join([
            summary.get("what", ""),
            summary.get("why", ""),
            summary.get("impact", ""),
            summary.get("review_focus", ""),
            " ".join(summary.get("key_changes") or []),
            (summary.get("risk") or {}).get("reason", ""),
        ])

        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "repo": repo,
            "pr_number": pr_number,
            "input": {
                "changed_files":          pr_data.get("changed_files", 0),
                "files_with_diff":        pre_analysis.files_with_diff,
                "files_skipped_noise":    pre_analysis.files_skipped_noise,
                "files_skipped_budget":   pre_analysis.files_skipped_budget,
                "total_diff_chars":       pre_analysis.total_diff_chars,
                "is_large_pr":            pr_data.get("is_large_pr", False),
                "used_chunking":          bool(summary.get("analysed_in_chunks")),
                "chunks_count":           summary.get("analysed_in_chunks"),
                "risk_tags_detected":     pre_analysis.risk_tags,
            },
            "output": {
                "summary_total_chars":    len(summary_text),
                "what_chars":             len(summary.get("what", "")),
                "key_changes_count":      len(summary.get("key_changes") or []),
                "risk_level":             (summary.get("risk") or {}).get("level", "unknown"),
                "confidence":             evaluation.confidence,
                "confidence_score":       evaluation.confidence_score,
                "specificity_score":      evaluation.specificity_score,
                "generic_penalty":        evaluation.generic_penalty,
                "is_flagged":             evaluation.is_flagged,
                "flag_reason":            evaluation.flag_reason,
            },
        }

        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

    except Exception:
        # Logging must never crash the main request path
        pass


def read_recent_logs(n: int = 20) -> list[dict]:
    """Returns the last n log entries, newest first. Used by /logs endpoint."""
    if not LOG_FILE.exists():
        return []
    try:
        lines = LOG_FILE.read_text(encoding="utf-8").strip().splitlines()
        records = []
        for line in reversed(lines[-n * 2:]):  # read a buffer, take last n valid
            try:
                records.append(json.loads(line))
                if len(records) >= n:
                    break
            except json.JSONDecodeError:
                continue
        return records
    except Exception:
        return []
