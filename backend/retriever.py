from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DATA_DIR = Path("data")
MEMORY_DIR = DATA_DIR / "memory"
REPO_DOCS_DIR = DATA_DIR / "repo_docs"

TOKEN_RE = re.compile(r"[A-Za-z0-9_./\-]{2,}")
WORD_RE = re.compile(r"[A-Za-z0-9_]{2,}")

SECURITY_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"pull_request_target", re.IGNORECASE), "ci_cd_pr_target"),
    (re.compile(r"workflow_run", re.IGNORECASE), "ci_cd_workflow_run"),
    (re.compile(r"secrets?\.", re.IGNORECASE), "secret_access"),
    (re.compile(r"AWS_SECRET|AWS_KEY|SECRET_KEY|API_KEY|TOKEN", re.IGNORECASE), "hardcoded_secret"),
    (re.compile(r"configure-aws-credentials", re.IGNORECASE), "aws_credentials"),
    (re.compile(r"permissions\s*:\s*", re.IGNORECASE), "permissions_block"),
    (re.compile(r"run:\s*", re.IGNORECASE), "shell_execution"),
    (re.compile(r"eval\(|exec\(|subprocess|os\.system", re.IGNORECASE), "code_execution"),
    (re.compile(r"curl\s+|wget\s+|http", re.IGNORECASE), "external_call"),
    (re.compile(r"password|passwd|pwd", re.IGNORECASE), "sensitive_data"),
    (re.compile(r"SECRET|TOKEN|KEY", re.IGNORECASE), "secret_surface"),
)

HIGH_SIGNAL_KEYS = {
    "ci_cd_pr_target",
    "ci_cd_workflow_run",
    "secret_access",
    "hardcoded_secret",
    "aws_credentials",
    "code_execution",
}


@dataclass(frozen=True)
class RetrievedItem:
    source: str
    score: float
    kind: str
    text: str
    metadata: dict[str, Any]


def _sanitize_repo(repo: str) -> str:
    return repo.replace("/", "__").replace(":", "__")


def _tokenize(text: str) -> list[str]:
    return [t.lower() for t in TOKEN_RE.findall(text or "")]


def _word_set(text: str) -> set[str]:
    return set(w.lower() for w in WORD_RE.findall(text or ""))


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
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


def _load_repo_docs(repo: str) -> list[dict[str, Any]]:
    """
    Expected optional layout:
      data/repo_docs/<repo_sanitized>.jsonl
    Each row:
      {
        "path": "...",
        "kind": "doc|code|workflow|history",
        "text": "...",
        "metadata": {...}
      }
    """
    repo_file = REPO_DOCS_DIR / f"{_sanitize_repo(repo)}.jsonl"
    return _load_jsonl(repo_file)


def _load_repo_memory(repo: str) -> list[dict[str, Any]]:
    """
    Expected optional layout:
      data/memory/<repo_sanitized>.jsonl
    Each row:
      {
        "event_type": "pr|deploy|incident|rollback|hotfix",
        "text": "...",
        "label": "...",
        "risk": 0.0,
        "metadata": {...}
      }
    """
    mem_file = MEMORY_DIR / f"{_sanitize_repo(repo)}.jsonl"
    return _load_jsonl(mem_file)


def _score_overlap(query_tokens: set[str], text_tokens: list[str]) -> float:
    if not query_tokens or not text_tokens:
        return 0.0
    text_set = set(text_tokens)
    overlap = len(query_tokens & text_set)
    coverage = overlap / max(1, len(query_tokens))
    density = overlap / max(1, len(text_set))
    return 0.7 * coverage + 0.3 * density


def _score_security_signals(text: str) -> tuple[float, list[str]]:
    hits: list[str] = []
    score = 0.0
    for pattern, tag in SECURITY_PATTERNS:
        if pattern.search(text):
            hits.append(tag)
            score += 0.12 if tag in HIGH_SIGNAL_KEYS else 0.05
    return min(score, 1.0), hits


def _score_recency(metadata: dict[str, Any]) -> float:
    ts = metadata.get("timestamp") or metadata.get("analysed_at") or metadata.get("created_at")
    if not ts:
        return 0.0
    # Light heuristic only, no hard dependency on date parsing.
    if isinstance(ts, str) and len(ts) >= 4:
        return 0.05
    return 0.0


def retrieve_context(
    repo: str,
    query: str,
    limit: int = 8,
) -> dict[str, Any]:
    """
    Returns contextual evidence for probabilistic inference:
    - historical repo memory
    - repo docs / code snippets
    - security-relevant signals
    """
    query_tokens = set(_tokenize(query))
    docs = _load_repo_docs(repo)
    memory = _load_repo_memory(repo)

    candidates: list[RetrievedItem] = []

    for row in docs:
        text = str(row.get("text", ""))
        kind = str(row.get("kind", "doc"))
        metadata = dict(row.get("metadata") or {})
        overlap = _score_overlap(query_tokens, _tokenize(text))
        sec_score, sec_hits = _score_security_signals(text)
        recency = _score_recency(metadata)
        score = overlap + sec_score + recency
        if score > 0:
            candidates.append(
                RetrievedItem(
                    source=str(row.get("path", "repo_doc")),
                    score=round(score, 4),
                    kind=kind,
                    text=text[:1500],
                    metadata={**metadata, "security_hits": sec_hits},
                )
            )

    for row in memory:
        text = str(row.get("text", ""))
        kind = str(row.get("event_type", "memory"))
        metadata = dict(row.get("metadata") or {})
        overlap = _score_overlap(query_tokens, _tokenize(text))
        sec_score, sec_hits = _score_security_signals(text)
        recency = _score_recency(metadata)
        label_bonus = 0.1 if str(row.get("label", "")).lower() in {"incident", "rollback", "hotfix"} else 0.0
        score = overlap + sec_score + recency + label_bonus
        if score > 0:
            candidates.append(
                RetrievedItem(
                    source=str(metadata.get("source", "repo_memory")),
                    score=round(score, 4),
                    kind=kind,
                    text=text[:1500],
                    metadata={**metadata, "label": row.get("label"), "risk": row.get("risk"), "security_hits": sec_hits},
                )
            )

    candidates.sort(key=lambda x: x.score, reverse=True)
    top = candidates[:limit]

    return {
        "repo": repo,
        "query": query,
        "hits": [
            {
                "source": item.source,
                "score": item.score,
                "kind": item.kind,
                "text": item.text,
                "metadata": item.metadata,
            }
            for item in top
        ],
        "signals": {
            "hit_count": len(top),
            "has_security_hits": any(item.metadata.get("security_hits") for item in top),
        },
    }


def retrieve_security_signals(repo: str, pr_data: dict[str, Any]) -> dict[str, Any]:
    """
    Extract reusable security signals for the quantitative core.
    """
    files = pr_data.get("files", []) or []
    full_text_parts: list[str] = [
        str(pr_data.get("title", "")),
        str(pr_data.get("body", "")),
        " ".join(pr_data.get("commit_messages", []) or []),
    ]

    for f in files:
        full_text_parts.append(str(f.get("filename", "")))
        full_text_parts.append(str(f.get("diff", "")))

    full_text = "\n".join(full_text_parts)

    security_hits: list[str] = []
    for pattern, tag in SECURITY_PATTERNS:
        if pattern.search(full_text):
            security_hits.append(tag)

    ci_cd_surface = any(
        tag in security_hits
        for tag in {"ci_cd_pr_target", "ci_cd_workflow_run", "aws_credentials", "permissions_block"}
    )

    secret_surface = any(
        tag in security_hits
        for tag in {"secret_access", "hardcoded_secret", "secret_surface"}
    )

    code_exec_surface = any(
        tag in security_hits
        for tag in {"code_execution", "shell_execution", "external_call"}
    )

    repo_context = retrieve_context(
        repo=repo,
        query=f"{pr_data.get('title', '')} {pr_data.get('body', '')}",
        limit=5,
    )

    return {
        "repo": repo,
        "security_hits": list(dict.fromkeys(security_hits)),
        "signals": {
            "ci_cd_surface": ci_cd_surface,
            "secret_surface": secret_surface,
            "code_exec_surface": code_exec_surface,
            "has_repo_context_hits": bool(repo_context["hits"]),
        },
        "context": repo_context,
    }


def store_memory(
    repo: str,
    *,
    event_type: str,
    text: str,
    label: str | None = None,
    risk: float | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    """
    Append a structured memory event to disk.
    """
    MEMORY_DIR.mkdir(parents=True, exist_ok=True)
    path = MEMORY_DIR / f"{_sanitize_repo(repo)}.jsonl"
    row = {
        "event_type": event_type,
        "text": text,
        "label": label,
        "risk": risk,
        "metadata": metadata or {},
    }
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")


def index_repository_docs(repo: str, docs: list[dict[str, Any]]) -> None:
    """
    Optional helper to bootstrap repo docs into the retriever index.
    """
    REPO_DOCS_DIR.mkdir(parents=True, exist_ok=True)
    path = REPO_DOCS_DIR / f"{_sanitize_repo(repo)}.jsonl"
    with path.open("w", encoding="utf-8") as f:
        for doc in docs:
            f.write(json.dumps(doc, ensure_ascii=False) + "\n")