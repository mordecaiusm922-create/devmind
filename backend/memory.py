from __future__ import annotations

import json
from collections import defaultdict, Counter
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DATA_DIR = Path("data")
MEMORY_DIR = DATA_DIR / "memory"
EVENTS_DIR = DATA_DIR / "events"

MEMORY_DIR.mkdir(parents=True, exist_ok=True)
EVENTS_DIR.mkdir(parents=True, exist_ok=True)


def _sanitize_repo(repo: str) -> str:
    return repo.replace("/", "__").replace(":", "__")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _repo_file(repo: str) -> Path:
    return MEMORY_DIR / f"{_sanitize_repo(repo)}.jsonl"


def _events_file(repo: str) -> Path:
    return EVENTS_DIR / f"{_sanitize_repo(repo)}.jsonl"


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def _append_jsonl(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")


@dataclass(frozen=True)
class MemoryEvent:
    repo: str
    event_type: str
    entity: str
    text: str
    label: str | None = None
    risk: float | None = None
    decision: str | None = None
    outcome: str | None = None
    metadata: dict[str, Any] | None = None
    timestamp: str | None = None

    def to_row(self) -> dict[str, Any]:
        row = asdict(self)
        if row["metadata"] is None:
            row["metadata"] = {}
        if row["timestamp"] is None:
            row["timestamp"] = _now_iso()
        return row


def store_event(
    repo: str,
    event_type: str,
    entity: str,
    text: str,
    *,
    label: str | None = None,
    risk: float | None = None,
    decision: str | None = None,
    outcome: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    event = MemoryEvent(
        repo=repo,
        event_type=event_type,
        entity=entity,
        text=text,
        label=label,
        risk=risk,
        decision=decision,
        outcome=outcome,
        metadata=metadata or {},
    ).to_row()

    _append_jsonl(_events_file(repo), event)
    _append_jsonl(_repo_file(repo), event)
    return event


def load_events(repo: str) -> list[dict[str, Any]]:
    return _read_jsonl(_events_file(repo))


def load_memory(repo: str) -> list[dict[str, Any]]:
    return _read_jsonl(_repo_file(repo))


def latest_events(repo: str, limit: int = 50) -> list[dict[str, Any]]:
    events = load_events(repo)
    return events[-limit:]


def count_by_label(repo: str) -> dict[str, int]:
    events = load_events(repo)
    counts: Counter[str] = Counter()
    for e in events:
        label = str(e.get("label") or "unlabeled")
        counts[label] += 1
    return dict(counts)


def count_by_event_type(repo: str) -> dict[str, int]:
    events = load_events(repo)
    counts: Counter[str] = Counter()
    for e in events:
        et = str(e.get("event_type") or "unknown")
        counts[et] += 1
    return dict(counts)


def historical_risk_profile(repo: str) -> dict[str, Any]:
    events = load_events(repo)
    risks = [float(e["risk"]) for e in events if e.get("risk") is not None]
    if not risks:
        return {
            "repo": repo,
            "n": 0,
            "avg_risk": None,
            "max_risk": None,
            "min_risk": None,
            "trend": "unknown",
        }

    avg_risk = sum(risks) / len(risks)
    trend = "stable"
    if len(risks) >= 5:
        left = sum(risks[: len(risks) // 2]) / max(1, len(risks) // 2)
        right = sum(risks[len(risks) // 2 :]) / max(1, len(risks) - len(risks) // 2)
        if right > left + 0.05:
            trend = "increasing"
        elif right < left - 0.05:
            trend = "decreasing"

    return {
        "repo": repo,
        "n": len(risks),
        "avg_risk": round(avg_risk, 4),
        "max_risk": round(max(risks), 4),
        "min_risk": round(min(risks), 4),
        "trend": trend,
    }


def dev_profile(repo: str) -> dict[str, Any]:
    events = load_events(repo)
    if not events:
        return {
            "repo": repo,
            "profile": "unknown",
            "n_events": 0,
        }

    labels = Counter(str(e.get("label") or "unlabeled") for e in events)
    outcomes = Counter(str(e.get("outcome") or "unknown") for e in events)
    decisions = Counter(str(e.get("decision") or "unknown") for e in events)

    critical = labels.get("critical", 0)
    high = labels.get("high", 0)
    medium = labels.get("medium", 0)

    if critical >= 3 or high >= 8:
        profile = "high_risk"
    elif high >= 3 or medium >= 8:
        profile = "moderate_risk"
    elif len(events) >= 10:
        profile = "stable"
    else:
        profile = "unknown"

    return {
        "repo": repo,
        "profile": profile,
        "n_events": len(events),
        "labels": dict(labels),
        "decisions": dict(decisions),
        "outcomes": dict(outcomes),
    }


def record_analysis_result(
    repo: str,
    *,
    pr_number: int,
    trace_id: str,
    risk: float,
    decision: str,
    label: str,
    explanation: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return store_event(
        repo=repo,
        event_type="analysis",
        entity=f"pr#{pr_number}",
        text=explanation,
        label=label,
        risk=risk,
        decision=decision,
        outcome=None,
        metadata={
            "trace_id": trace_id,
            "pr_number": pr_number,
            **(metadata or {}),
        },
    )


def record_outcome(
    repo: str,
    *,
    pr_number: int,
    outcome: str,
    text: str = "",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return store_event(
        repo=repo,
        event_type="outcome",
        entity=f"pr#{pr_number}",
        text=text,
        label=outcome,
        risk=None,
        decision=None,
        outcome=outcome,
        metadata={
            "pr_number": pr_number,
            **(metadata or {}),
        },
    )


def summarize_repo_memory(repo: str) -> dict[str, Any]:
    events = load_events(repo)
    return {
        "repo": repo,
        "n_events": len(events),
        "by_label": count_by_label(repo),
        "by_event_type": count_by_event_type(repo),
        "risk_profile": historical_risk_profile(repo),
        "dev_profile": dev_profile(repo),
        "recent_events": events[-10:],
    }


def clear_repo_memory(repo: str) -> None:
    for path in (_repo_file(repo), _events_file(repo)):
        if path.exists():
            path.unlink()


def bootstrap_memory(repo: str, rows: list[dict[str, Any]]) -> None:
    for row in rows:
        store_event(
            repo=repo,
            event_type=str(row.get("event_type", "bootstrap")),
            entity=str(row.get("entity", "unknown")),
            text=str(row.get("text", "")),
            label=row.get("label"),
            risk=row.get("risk"),
            decision=row.get("decision"),
            outcome=row.get("outcome"),
            metadata=row.get("metadata") or {},
        )

def record_strategy_result(
    repo: str,
    *,
    pr_number: int,
    strategy: str,
    intent: str,
    utility: float,
    security: float,
    verified: bool,
    decision: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return store_event(
        repo=repo,
        event_type="strategy_result",
        entity=f"pr#{pr_number}",
        text=f"{intent}:{strategy}",
        label=strategy,
        risk=round(1.0 - utility, 4),
        decision=decision,
        outcome="verified" if verified else "unverified",
        metadata={
            "strategy": strategy,
            "intent": intent,
            "utility": utility,
            "security": security,
            "verified": verified,
            "pr_number": pr_number,
            **(metadata or {}),
        },
    )


def strategy_priors(repo: str, intent: str) -> dict[str, float]:
    """
    Returns historical success rate per strategy for a given intent.
    Used as Bayesian prior in safety_flow scoring.
    """
    events = load_events(repo)
    relevant = [
        e for e in events
        if e.get("event_type") == "strategy_result"
        and str(e.get("metadata", {}).get("intent", "")) == intent
    ]
    if not relevant:
        return {}

    totals: dict[str, list[float]] = defaultdict(list)
    for e in relevant:
        strategy = str(e.get("label") or "unknown")
        utility = float(e.get("metadata", {}).get("utility", 0.5))
        totals[strategy].append(utility)

    return {
        strategy: round(sum(vals) / len(vals), 4)
        for strategy, vals in totals.items()
    }


def get_prior_for_prompt(repo: str, prompt: str) -> dict[str, Any]:
    """
    Given a prompt, infer intent and return strategy priors.
    """
    text = prompt.lower()
    if any(k in text for k in ("secret", "token", "password", "api_key")):
        intent = "secure_fix"
    elif any(k in text for k in ("sql", "injection", "query")):
        intent = "sql_fix"
    elif any(k in text for k in ("auth", "permission", "rbac")):
        intent = "auth_fix"
    else:
        intent = "general_fix"

    priors = strategy_priors(repo, intent)
    return {
        "intent": intent,
        "priors": priors,
        "n_observations": len(priors),
    }