"""
main.py -- DevMind SaaS API

Production-grade FastAPI application with:
  - Strict typing
  - Structured JSON logging with trace IDs
  - Layered error taxonomy
  - Timeout isolation around analysis
  - Queue-based async webhook processing
  - Idempotency for GitHub deliveries
  - Hard payload limits
  - Strong schema validation
  - Circuit breaker around fragile stages
  - Metrics endpoint
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Annotated, Any

import httpx
from dotenv import load_dotenv
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from evaluator import evaluate, enforce_risk_floor
from feature_extractor import extract_features
from github import get_pr_data
from github_app import (
    get_installation_token,
    post_commit_status,
    post_pr_comment,
    verify_webhook_signature,
)
from logger import log_analysis, read_recent_logs
from parser import parse_pr_file
from summarizer import summarize_pr

load_dotenv()

# =============================================================================
# 1. LIMITS / CONSTANTS
# =============================================================================

MAX_FILES_PER_PR = 100
MAX_DIFF_CHARS_PER_PR = 250_000
MAX_WEBHOOK_BODY_BYTES = 2_000_000
JOB_QUEUE_MAXSIZE = 500
IDEMPOTENCY_TTL_HOURS = 24
CACHE_TTL_MINUTES = 30
ANALYSIS_CACHE_MAX = 256

# =============================================================================
# 2. STRUCTURED LOGGING
# =============================================================================

_STANDARD_LOG_ATTRS = {
    "name",
    "msg",
    "args",
    "levelname",
    "levelno",
    "pathname",
    "filename",
    "module",
    "exc_info",
    "exc_text",
    "stack_info",
    "lineno",
    "funcName",
    "created",
    "msecs",
    "relativeCreated",
    "thread",
    "threadName",
    "processName",
    "process",
    "message",
    "asctime",
}


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "time": self.formatTime(record, "%Y-%m-%dT%H:%M:%SZ"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _STANDARD_LOG_ATTRS and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, ensure_ascii=False)


def _configure_logging() -> logging.Logger:
    handler = logging.StreamHandler()
    handler.setFormatter(_JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    return logging.getLogger("devmind")


log = _configure_logging()

# =============================================================================
# 3. CONFIGURATION
# =============================================================================


@dataclass(frozen=True)
class _Config:
    frontend_origin: str
    webhook_secret: str
    static_api_keys: frozenset[str]
    supabase_url: str
    supabase_key: str
    rate_limit_requests: int
    rate_limit_window_s: int
    analysis_timeout_s: int
    environment: str

    @classmethod
    def from_env(cls) -> "_Config":
        raw_keys = os.getenv("API_KEYS", "dev-key-insecure")
        keys = frozenset(k.strip() for k in raw_keys.split(",") if k.strip())
        return cls(
            frontend_origin=os.getenv("FRONTEND_ORIGIN", "http://localhost:5173"),
            webhook_secret=os.getenv("GITHUB_WEBHOOK_SECRET", ""),
            static_api_keys=keys,
            supabase_url=os.getenv("SUPABASE_URL", ""),
            supabase_key=os.getenv("SUPABASE_SERVICE_KEY", ""),
            rate_limit_requests=int(os.getenv("RATE_LIMIT_REQUESTS", "20")),
            rate_limit_window_s=int(os.getenv("RATE_LIMIT_WINDOW_S", "60")),
            analysis_timeout_s=int(os.getenv("ANALYSIS_TIMEOUT_S", "120")),
            environment=os.getenv("ENVIRONMENT", "production"),
        )

    @property
    def is_dev(self) -> bool:
        return self.environment == "development"


CFG = _Config.from_env()

# =============================================================================
# 4. ERROR TAXONOMY
# =============================================================================


class ErrorCode(str, Enum):
    MISSING_API_KEY = "MISSING_API_KEY"
    INVALID_API_KEY = "INVALID_API_KEY"
    RATE_LIMITED = "RATE_LIMITED"
    PR_NOT_FOUND = "PR_NOT_FOUND"
    INVALID_PAYLOAD = "INVALID_PAYLOAD"
    INVALID_WEBHOOK_SIG = "INVALID_WEBHOOK_SIG"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    ANALYSIS_TIMEOUT = "ANALYSIS_TIMEOUT"
    GITHUB_AUTH_FAILURE = "GITHUB_AUTH_FAILURE"
    UPSTREAM_ERROR = "UPSTREAM_ERROR"
    INTERNAL_ERROR = "INTERNAL_ERROR"


def _err(
    http_status: int,
    code: ErrorCode,
    detail: str,
    *,
    trace_id: str | None = None,
) -> HTTPException:
    return HTTPException(
        status_code=http_status,
        detail={
            "error": code.value,
            "message": detail,
            "trace_id": trace_id,
        },
    )

# =============================================================================
# 5. STORAGE / CACHES
# =============================================================================


class TTLSet:
    def __init__(self, ttl: timedelta, maxsize: int = 4096) -> None:
        self.ttl = ttl
        self.maxsize = maxsize
        self._store: dict[str, datetime] = {}
        self._order: deque[str] = deque()
        self._lock = threading.Lock()

    def _purge(self) -> None:
        now = datetime.now(timezone.utc)
        while self._order:
            key = self._order[0]
            ts = self._store.get(key)
            if ts is None or now - ts > self.ttl:
                self._order.popleft()
                self._store.pop(key, None)
            else:
                break

    def add(self, key: str) -> None:
        with self._lock:
            self._purge()
            if key in self._store:
                self._store[key] = datetime.now(timezone.utc)
                return
            if len(self._store) >= self.maxsize and self._order:
                old = self._order.popleft()
                self._store.pop(old, None)
            self._store[key] = datetime.now(timezone.utc)
            self._order.append(key)

    def contains(self, key: str) -> bool:
        with self._lock:
            self._purge()
            return key in self._store


class TTLCache:
    def __init__(self, ttl: timedelta, maxsize: int = 256) -> None:
        self.ttl = ttl
        self.maxsize = maxsize
        self._store: dict[str, tuple[datetime, Any]] = {}
        self._order: deque[str] = deque()
        self._lock = threading.Lock()

    def get(self, key: str) -> Any | None:
        with self._lock:
            self._purge()
            item = self._store.get(key)
            return None if item is None else item[1]

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._purge()
            if len(self._store) >= self.maxsize and self._order:
                old = self._order.popleft()
                self._store.pop(old, None)
            self._store[key] = (datetime.now(timezone.utc), value)
            self._order.append(key)

    def _purge(self) -> None:
        now = datetime.now(timezone.utc)
        while self._order:
            key = self._order[0]
            item = self._store.get(key)
            if item is None or now - item[0] > self.ttl:
                self._order.popleft()
                self._store.pop(key, None)
            else:
                break


class CircuitBreaker:
    def __init__(self, threshold: int = 5, cooldown_s: int = 30) -> None:
        self.threshold = threshold
        self.cooldown_s = cooldown_s
        self.failures = 0
        self.open_until = 0.0
        self._lock = threading.Lock()

    def allow(self) -> bool:
        with self._lock:
            if time.monotonic() < self.open_until:
                return False
            return True

    def success(self) -> None:
        with self._lock:
            self.failures = 0
            self.open_until = 0.0

    def failure(self) -> None:
        with self._lock:
            self.failures += 1
            if self.failures >= self.threshold:
                self.open_until = time.monotonic() + self.cooldown_s
                self.failures = 0


analysis_cache = TTLCache(timedelta(minutes=CACHE_TTL_MINUTES), maxsize=ANALYSIS_CACHE_MAX)
processed_deliveries = TTLSet(timedelta(hours=IDEMPOTENCY_TTL_HOURS))
analysis_breaker = CircuitBreaker(threshold=5, cooldown_s=30)
workflow_breaker = CircuitBreaker(threshold=8, cooldown_s=20)

# =============================================================================
# 6. SUPABASE CLIENT
# =============================================================================


class SupabaseClient:
    def __init__(self, url: str, key: str) -> None:
        self._url = url
        self._key = key
        self._headers = {"apikey": key, "Authorization": f"Bearer {key}"}
        self._http = httpx.Client(timeout=httpx.Timeout(3.0), headers=self._headers)

    def key_exists(self, api_key: str) -> bool:
        if not self._url or not self._key:
            return False
        try:
            resp = self._http.get(
                f"{self._url}/rest/v1/users",
                params={"api_key": f"eq.{api_key}", "select": "api_key", "limit": "1"},
            )
            return resp.status_code == 200 and len(resp.json()) > 0
        except Exception as exc:
            log.warning("supabase_key_lookup_failed", extra={"exc": str(exc)})
            return False

    def close(self) -> None:
        self._http.close()


_supabase = SupabaseClient(CFG.supabase_url, CFG.supabase_key)

# =============================================================================
# 7. RATE LIMITER
# =============================================================================


class _SlidingWindowRateLimiter:
    def __init__(self, max_requests: int, window_s: int) -> None:
        self._max = max_requests
        self._window = window_s
        self._store: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def check(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            timestamps = [t for t in self._store[key] if now - t < self._window]
            if len(timestamps) >= self._max:
                raise _err(
                    status.HTTP_429_TOO_MANY_REQUESTS,
                    ErrorCode.RATE_LIMITED,
                    f"Limit: {self._max} requests per {self._window}s.",
                )
            timestamps.append(now)
            self._store[key] = timestamps


_limiter = _SlidingWindowRateLimiter(CFG.rate_limit_requests, CFG.rate_limit_window_s)

# =============================================================================
# 8. AUTH DEPENDENCY
# =============================================================================


def _require_api_key(
    x_api_key: Annotated[str | None, Header(alias="x-api-key")] = None,
) -> str:
    if not x_api_key:
        raise _err(status.HTTP_401_UNAUTHORIZED, ErrorCode.MISSING_API_KEY, "Pass X-Api-Key header.")
    valid = x_api_key in CFG.static_api_keys or _supabase.key_exists(x_api_key)
    if not valid:
        raise _err(status.HTTP_401_UNAUTHORIZED, ErrorCode.INVALID_API_KEY, "API key not recognized.")
    _limiter.check(x_api_key)
    return x_api_key

# =============================================================================
# 9. REQUEST CONTEXT
# =============================================================================

_ctx = threading.local()


def _get_trace_id() -> str:
    return getattr(_ctx, "trace_id", "unknown")

# =============================================================================
# 10. DOMAIN MODELS
# =============================================================================


class AnalysePRRequest(BaseModel):
    repo: str
    pr_number: int

    @field_validator("repo")
    @classmethod
    def _validate_repo(cls, v: str) -> str:
        parts = v.strip().split("/")
        if len(parts) != 2 or not all(parts):
            raise ValueError("repo must be 'owner/repo'")
        return v.strip()

    @field_validator("pr_number")
    @classmethod
    def _validate_pr(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("pr_number must be a positive integer")
        return v


class RiskNote(BaseModel):
    model_config = ConfigDict(extra="forbid")
    level: str
    reason: str = ""


class PermissionAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")
    permissions_block_present: bool = False
    scopes_granted: list[str] = Field(default_factory=list)
    secrets_accessed_before_validation: bool = False
    github_token_scope: str = "not_applicable"
    trust_boundary_respected: bool = True


class Vulnerability(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str
    severity: str
    location: str
    description: str
    fix: str
    exploit_path: str | None = None
    blast_radius: str | None = None


class CiCdRisk(BaseModel):
    model_config = ConfigDict(extra="forbid")
    trigger: str
    risk: str
    severity: str
    line: str
    permissions_block_missing: bool = False
    secrets_exposed: bool = False
    evidence_snippet: str | None = None


class AttackPath(BaseModel):
    model_config = ConfigDict(extra="forbid")
    entry_point: str
    attacker_control_verified: bool = False
    exploit_steps: list[str] = Field(default_factory=list)
    sink: str
    blast_radius: str
    impact: str


class SummarySchema(BaseModel):
    model_config = ConfigDict(extra="ignore")
    what: str = ""
    why: str = ""
    impact: str = ""
    risk_note: RiskNote
    permissions_analysis: PermissionAnalysis | None = None
    attack_path: AttackPath | None = None
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    ci_cd_risks: list[CiCdRisk] = Field(default_factory=list)
    key_changes: list[str] = Field(default_factory=list)
    review_focus: str = ""
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    triage: str | None = None
    merge_blocker: bool = False
    merge_block_reason: str | None = None
    analysed_in_chunks: int | None = None
    hallucination_warning: list[str] | None = None


# =============================================================================
# 11. METRICS
# =============================================================================

METRICS: dict[str, int] = defaultdict(int)

def _metric(name: str, delta: int = 1) -> None:
    METRICS[name] += delta

# =============================================================================
# 12. HELPERS
# =============================================================================


def _build_cache_key(repo: str, pr_number: int) -> str:
    return f"{repo}#{pr_number}"


def _build_job_key(repo: str, pr_number: int, delivery_id: str) -> str:
    return f"{repo}#{pr_number}:{delivery_id}"


def _check_payload_limits(pr_data: dict[str, Any]) -> None:
    files = pr_data.get("files", [])
    diff_chars = sum(len(f.get("diff") or "") for f in files)
    if len(files) > MAX_FILES_PER_PR:
        raise _err(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, ErrorCode.INVALID_PAYLOAD, "PR has too many files.")
    if diff_chars > MAX_DIFF_CHARS_PER_PR:
        raise _err(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, ErrorCode.INVALID_PAYLOAD, "PR diff is too large.")


def _normalize_summary(summary: dict[str, Any]) -> dict[str, Any]:
    data = dict(summary or {})
    risk_raw = data.get("risk_note") or data.get("risk") or {}
    if isinstance(risk_raw, str):
        parts = risk_raw.split("--", 1)
        level = parts[0].strip().lower()
        reason = parts[1].strip() if len(parts) > 1 else risk_raw.strip()
        data["risk_note"] = {"level": level, "reason": reason}
    elif isinstance(risk_raw, dict):
        data["risk_note"] = {
            "level": str(risk_raw.get("level", "low")).lower(),
            "reason": str(risk_raw.get("reason", "")).strip(),
        }
    else:
        data["risk_note"] = {"level": "low", "reason": ""}
    data.pop("risk", None)
    return data


def _validate_summary(summary: dict[str, Any]) -> SummarySchema:
    normalized = _normalize_summary(summary)
    return SummarySchema.model_validate(normalized)


def _score_to_merge_state(level: str) -> str:
    return "failure" if level in ("critical", "high") else "success"


def _build_pr_comment(result: dict[str, Any]) -> str:
    s = result.get("summary", {})
    re_obj = result.get("risk_engine", {})
    level = re_obj.get("band", "low")
    score = re_obj.get("score", 0)
    top_factors = re_obj.get("top_factors", [])
    vulns = s.get("vulnerabilities") or []
    triage = s.get("triage", "P3")
    merge_block = s.get("merge_blocker", False)
    merge_reason = s.get("merge_block_reason")
    emoji = {"critical": "??", "high": "??", "medium": "??", "low": "??", "minimal": "?"}.get(level, "?")

    vuln_lines = []
    for v in vulns:
        sev = str(v.get("severity", "unknown")).upper()
        loc = v.get("location", "-")
        desc = v.get("description", "")
        fix = v.get("fix", "")
        path = v.get("exploit_path", "")
        vuln_lines.append(
            f"> **[{sev}]** `{loc}`\n"
            f"> {desc}\n"
            + (f"> **Exploit path:** {path}\n" if path else "")
            + f"> **Fix:** {fix}"
        )

    factors_md = "\n".join(f"- {f}" for f in top_factors) if top_factors else "- None detected"
    vulns_md = "\n\n".join(vuln_lines) if vuln_lines else "_No vulnerabilities detected_"
    blocker_md = "Merge blocked. Critical risk detected." if merge_block else ""
    breakdown = re_obj.get("breakdown", {})
    scores_md = (
        f"| Metric | Score |\n|--------|-------|\n"
        f"| Risk Score | `{score}/100` |\n"
        f"| Probability | `{breakdown.get('probability', 0)}` |\n"
        f"| Impact | `{breakdown.get('impact', 0)}` |\n"
        f"| Confidence | `{breakdown.get('confidence', 0)}` |"
    )

    return f"""## {emoji} DevMind Risk Analysis

**{triage}** — Risk Score `{score}/100` — **{level.upper()}**
{blocker_md}

### Risk Breakdown
{scores_md}

### Top Risk Factors
{factors_md}

### Vulnerabilities
{vulns_md}

### Summary
**What:** {s.get("what", "N/A")}
**Impact:** {s.get("impact", "N/A")}
**Review focus:** {s.get("review_focus", "N/A")}

---
_Analyzed by DevMind · trace `{result.get("trace_id", "")}`_"""


async def _run_pipeline(repo: str, pr_number: int, trace_id: str) -> dict[str, Any]:
    cache_key = _build_cache_key(repo, pr_number)
    cached = analysis_cache.get(cache_key)
    if cached is not None:
        _metric("analysis_cache_hit")
        return cached

    if not analysis_breaker.allow():
        raise _err(503, ErrorCode.UPSTREAM_ERROR, "Analysis circuit breaker open.", trace_id=trace_id)

    _metric("analysis_start")
    log.info("analysis_start", extra={"repo": repo, "pr": pr_number, "trace_id": trace_id})

    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(_pipeline_sync, repo, pr_number, trace_id),
            timeout=CFG.analysis_timeout_s,
        )
        analysis_breaker.success()
        analysis_cache.set(cache_key, result)
        _metric("analysis_success")
        return result
    except asyncio.TimeoutError:
        analysis_breaker.failure()
        _metric("analysis_timeout")
        raise _err(504, ErrorCode.ANALYSIS_TIMEOUT, f"Analysis timed out after {CFG.analysis_timeout_s}s.", trace_id=trace_id)
    except HTTPException:
        analysis_breaker.failure()
        raise
    except ValueError as exc:
            analysis_breaker.failure()
            _metric("analysis_validation_error")
            log.error("validation_error_detail", extra={"exc": str(exc), "trace_id": trace_id}, exc_info=True)
            raise _err(422, ErrorCode.VALIDATION_ERROR, str(exc), trace_id=trace_id)
    except Exception as exc:
        analysis_breaker.failure()
        msg = str(exc)
        if "404" in msg or "Not Found" in msg:
            raise _err(404, ErrorCode.PR_NOT_FOUND, f"PR not found: {repo}#{pr_number}", trace_id=trace_id)
        if any(code in msg for code in ("401", "403")):
            raise _err(401, ErrorCode.GITHUB_AUTH_FAILURE, "GitHub API auth failed. Check GITHUB_TOKEN.", trace_id=trace_id)
        log.error("analysis_error", extra={"exc": msg, "trace_id": trace_id}, exc_info=True)
        raise _err(400, ErrorCode.UPSTREAM_ERROR, msg, trace_id=trace_id)


def _pipeline_sync(repo: str, pr_number: int, trace_id: str) -> dict[str, Any]:
    _ctx.trace_id = trace_id

    def _timed(label: str, fn, *args, **kwargs):
        t0 = time.monotonic()
        result = fn(*args, **kwargs)
        log.info(
            "pipeline_step",
            extra={
                "step": label,
                "duration_ms": round((time.monotonic() - t0) * 1000),
                "trace_id": trace_id,
            },
        )
        return result

    pr_data = _timed("get_pr_data", get_pr_data, repo, pr_number)
    _check_payload_limits(pr_data)

    summary, pre, ev = _timed("summarize", summarize_pr, pr_data)
    summary = _normalize_summary(summary)
    validated_summary = _validate_summary(summary).model_dump()

    validated_summary = enforce_risk_floor(validated_summary, pre)

    all_parsed: list[dict[str, Any]] = []
    for f in pr_data.get("files", []):
        fname = f.get("filename", "")
        patch = f.get("raw_patch", "") or f.get("diff", "")
        if not patch or f.get("is_noise"):
            continue
        try:
            parsed = parse_pr_file(fname, patch, None)
            all_parsed.append(parsed)
        except Exception as exc:
            log.warning("parse_file_failed", extra={"file": fname, "exc": str(exc), "trace_id": trace_id})

    combined: dict[str, list] = {"functions_changed": [], "calls": []}
    for p in all_parsed:
        combined["functions_changed"].extend(p.get("functions_changed", []))
        combined["calls"].extend(p.get("calls", []))

    diff_stats = {
        "additions": pr_data.get("additions", 0),
        "deletions": pr_data.get("deletions", 0),
        "changed_files": pr_data.get("changed_files", 0),
    }
    features = _timed("extract_features", extract_features, combined, diff_stats)

    permissions = validated_summary.get("permissions_analysis", {}) or {}
    vulns = validated_summary.get("vulnerabilities", []) or []
    risk_band = str(validated_summary.get("risk_note", {}).get("level", "low")).lower()
    risk_floor = pre.risk_floor

    merge_blocker, reason = decide_merge_blocker(
        risk_band=risk_band,
        risk_floor=risk_floor,
        vulnerabilities=vulns,
        permissions=permissions,
    )

    validated_summary["merge_blocker"] = merge_blocker
    validated_summary["merge_block_reason"] = reason

    risk = ev.get("risk_signals", {})

    response = _build_response(
        repo=repo,
        pr_number=pr_number,
        pr_data=pr_data,
        summary=validated_summary,
        pre=pre,
        ev=ev,
        risk=risk,
        features=features,
        parsed_fns=combined["functions_changed"],
        trace_id=trace_id,
    )
    _metric("analysis_done")
    return response


def _build_response(
    *,
    repo: str,
    pr_number: int,
    pr_data: dict[str, Any],
    summary: dict[str, Any],
    pre: Any,
    ev: dict[str, Any],
    risk: dict[str, Any] | None,
    features: dict[str, Any],
    parsed_fns: list[Any],
    trace_id: str,
) -> dict[str, Any]:
    evaluation = ev.get("evaluation", {})
    response: dict[str, Any] = {
        "schema_version": "1.3.0",
        "trace_id": trace_id,
        "pr_number": pr_number,
        "repo": repo,
        "title": pr_data.get("title", ""),
        "author": pr_data.get("author", ""),
        "changed_files": pr_data.get("changed_files", 0),
        "additions": pr_data.get("additions", 0),
        "deletions": pr_data.get("deletions", 0),
        "is_large_pr": pr_data.get("is_large_pr", False),
        "analysed_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "what": summary.get("what"),
            "why": summary.get("why"),
            "impact": summary.get("impact"),
            "risk_note": summary.get("risk_note"),
            "permissions_analysis": summary.get("permissions_analysis"),
            "attack_path": summary.get("attack_path"),
            "vulnerabilities": summary.get("vulnerabilities", []),
            "ci_cd_risks": summary.get("ci_cd_risks", []),
            "key_changes": summary.get("key_changes", []),
            "review_focus": summary.get("review_focus"),
            "evidence": summary.get("evidence", []),
            "triage": summary.get("triage"),
            "merge_blocker": summary.get("merge_blocker", False),
            "merge_block_reason": summary.get("merge_block_reason"),
            "analysed_in_chunks": summary.get("analysed_in_chunks"),
            "hallucination_warning": summary.get("hallucination_warning"),
        },
        "evaluation": {
            "confidence": evaluation.get("confidence"),
            "confidence_score": evaluation.get("confidence_score", 0),
            "specificity_score": evaluation.get("specificity_score", 0),
            "is_flagged": evaluation.get("is_flagged", False),
            "flag_reason": evaluation.get("flag_reason"),
            "generic_phrases_found": evaluation.get("generic_phrases_found", []),
        },
        "pre_analysis": {
            "risk_floor": pre.risk_floor,
            "risk_tags": list(pre.risk_tags),
            "flagged_files": list(pre.flagged_files),
            "trivially_touched": list(pre.trivially_touched),
            "files_with_diff": pre.files_with_diff,
            "files_skipped_budget": pre.files_skipped_budget,
            "files_skipped_noise": pre.files_skipped_noise,
            "total_diff_chars": pre.total_diff_chars,
        },
        "code_features": features,
        "parsed_functions": parsed_fns[:10],
    }

    if risk is not None:
        response["risk_engine"] = {
            "score": risk.get("risk_score", 0),
            "band": risk.get("risk_band", "low"),
            "label": risk.get("risk_label", ""),
            "top_factors": risk.get("top_factors", []),
            "breakdown": {
                "probability": round(risk.get("p_score", 0), 3),
                "impact": round(risk.get("i_score", 0), 3),
                "confidence": round(risk.get("c_score", 0), 3),
            },
        }

    return response

# =============================================================================
# 13. DECISION LOGIC
# =============================================================================


def decide_merge_blocker(
    *,
    risk_band: str,
    risk_floor: str,
    vulnerabilities: list,
    permissions: dict | None,
) -> tuple[bool, str]:
    if risk_band in ("critical", "high"):
        return True, "High or critical risk detected"

    if vulnerabilities:
        severe = [v for v in vulnerabilities if str(v.get("severity", "")).lower() in ("high", "critical")]
        if severe:
            return True, "High severity vulnerabilities detected"

    if risk_floor == "medium":
        if permissions and not permissions.get("trust_boundary_respected", True):
            return True, "Permissions cross trust boundary"
        if permissions and permissions.get("secrets_accessed_before_validation"):
            return True, "Secrets used before validation"

    return False, "No blocking conditions met"

# =============================================================================
# 14. BACKGROUND JOBS
# =============================================================================

@dataclass(frozen=True)
class AnalysisJob:
    repo: str
    pr_number: int
    trace_id: str
    installation_id: int
    commit_sha: str
    delivery_id: str


job_queue: asyncio.Queue[AnalysisJob] | None = None


async def _job_worker() -> None:
    assert job_queue is not None
    while True:
        job = await job_queue.get()
        try:
            token = get_installation_token(job.installation_id)
            result = await _run_pipeline(job.repo, job.pr_number, trace_id=job.trace_id)
            comment = _build_pr_comment(result)
            post_pr_comment(job.repo, job.pr_number, comment, token)

            re_obj = result.get("risk_engine", {})
            level = re_obj.get("band", "low")
            score = re_obj.get("score", 0)
            state = _score_to_merge_state(str(level))
            post_commit_status(
                job.repo,
                job.commit_sha,
                token,
                state,
                f"Risk {score}/100 - {str(level).upper()}",
            )
            _metric("job_success")
        except Exception as exc:
            _metric("job_failure")
            log.error(
                "job_failed",
                extra={"repo": job.repo, "pr": job.pr_number, "exc": str(exc), "trace_id": job.trace_id},
                exc_info=True,
            )
        finally:
            job_queue.task_done()

# =============================================================================
# 15. APP LIFECYCLE
# =============================================================================


@asynccontextmanager
async def _lifespan(application: FastAPI):
    global job_queue
    job_queue = asyncio.Queue(maxsize=JOB_QUEUE_MAXSIZE)
    worker = asyncio.create_task(_job_worker())
    log.info("startup", extra={"env": CFG.environment, "version": application.version})
    try:
        yield
    finally:
        worker.cancel()
        _supabase.close()
        log.info("shutdown")


app = FastAPI(
    title="DevMind API",
    version="1.3.0",
    docs_url="/docs" if CFG.is_dev else None,
    redoc_url=None,
    lifespan=_lifespan,
)

allowed_origins = [CFG.frontend_origin]
if CFG.is_dev:
    allowed_origins.extend(["http://localhost:5173", "http://127.0.0.1:5173"])

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# =============================================================================
# 16. MIDDLEWARE / ERROR HANDLERS
# =============================================================================


@app.middleware("http")
async def _observability(request: Request, call_next):
    trace_id = request.headers.get("x-trace-id") or str(uuid.uuid4())[:12]
    _ctx.trace_id = trace_id
    t0 = time.monotonic()

    response = await call_next(request)

    elapsed = round((time.monotonic() - t0) * 1000)
    log.info(
        "http_request",
        extra={
            "method": request.method,
            "path": request.url.path,
            "status": response.status_code,
            "elapsed_ms": elapsed,
            "trace_id": trace_id,
        },
    )
    response.headers["X-Trace-Id"] = trace_id
    return response


@app.exception_handler(Exception)
async def _unhandled_exception(request: Request, exc: Exception):
    tid = _get_trace_id()
    log.error(
        "unhandled_exception",
        extra={"path": request.url.path, "exc": str(exc), "trace_id": tid},
        exc_info=True,
    )
    return JSONResponse(
        status_code=500,
        content={"error": ErrorCode.INTERNAL_ERROR.value, "message": str(exc), "trace_id": tid},
    )

# =============================================================================
# 17. ENDPOINTS
# =============================================================================


@app.api_route("/health", methods=["GET", "HEAD"])
async def healthcheck():
    return {
        "status": "ok",
        "version": app.version,
        "env": CFG.environment,
        "queue_size": 0 if job_queue is None else job_queue.qsize(),
        "metrics": METRICS,
    }


@app.get("/")
async def root():
    return {"service": "DevMind", "status": "ok", "version": app.version}


@app.get("/metrics")
async def metrics():
    return {"metrics": METRICS}


@app.post("/analyze-pr", dependencies=[Depends(_require_api_key)])
async def analyze_pr(req: AnalysePRRequest, request: Request):
    trace_id = request.headers.get("x-trace-id") or _get_trace_id()
    log.info("analyze_pr_request", extra={"repo": req.repo, "pr": req.pr_number, "trace_id": trace_id})
    return await _run_pipeline(req.repo, req.pr_number, trace_id=trace_id)


@app.get("/logs")
async def get_logs(n: int = 50):
    return {"logs": read_recent_logs(n)}


if CFG.is_dev:
    @app.get("/debug/keys")
    def debug_keys():
        return {"static_keys_count": len(CFG.static_api_keys)}

    @app.post("/debug/auth")
    def debug_auth(request: Request):
        return {"headers": dict(request.headers)}

# =============================================================================
# 18. GITHUB WEBHOOK
# =============================================================================

_HANDLED_ACTIONS = frozenset({"opened", "synchronize", "reopened"})


@app.post("/webhook/github", status_code=202)
async def github_webhook(
    request: Request,
    x_github_event: Annotated[str | None, Header()] = None,
    x_hub_signature_256: Annotated[str | None, Header()] = None,
    x_github_delivery: Annotated[str | None, Header()] = None,
):
    body = await request.body()

    if len(body) > MAX_WEBHOOK_BODY_BYTES:
        raise _err(413, ErrorCode.INVALID_PAYLOAD, "Webhook payload too large.")

    if not verify_webhook_signature(body, x_hub_signature_256 or ""):
        raise _err(401, ErrorCode.INVALID_WEBHOOK_SIG, "Signature mismatch.")

    if x_github_event != "pull_request":
        return {"accepted": False, "reason": f"event '{x_github_event}' not handled"}

    try:
        payload: dict[str, Any] = json.loads(body)
    except json.JSONDecodeError:
        raise _err(400, ErrorCode.INVALID_PAYLOAD, "Body is not valid JSON.")

    action = payload.get("action", "")
    if action not in _HANDLED_ACTIONS:
        return {"accepted": False, "reason": f"action '{action}' not handled"}

    pr = payload.get("pull_request", {})
    repo = payload.get("repository", {}).get("full_name", "")
    pr_number = pr.get("number")
    commit_sha = pr.get("head", {}).get("sha", "")
    installation_id = payload.get("installation", {}).get("id")
    delivery_id = x_github_delivery or str(uuid.uuid4())
    trace_id = delivery_id[:12]

    if not repo or not pr_number or not installation_id:
        raise _err(400, ErrorCode.INVALID_PAYLOAD, "Missing repo, pr number, or installation_id.")

    if processed_deliveries.contains(delivery_id):
        _metric("webhook_deduped")
        return {"accepted": True, "deduped": True, "trace_id": trace_id}

    processed_deliveries.add(delivery_id)
    log.info("webhook_received", extra={"action": action, "repo": repo, "pr": pr_number, "trace_id": trace_id})

    if job_queue is None:
        raise _err(503, ErrorCode.UPSTREAM_ERROR, "Job queue not ready.", trace_id=trace_id)

    job = AnalysisJob(
        repo=repo,
        pr_number=pr_number,
        trace_id=trace_id,
        installation_id=installation_id,
        commit_sha=commit_sha,
        delivery_id=delivery_id,
    )

    try:
        token_pending = get_installation_token(installation_id)
        post_commit_status(repo, commit_sha, token_pending, "pending", "DevMind is analyzing this PR...")
    except Exception as exc:
        log.warning("pending_status_failed", extra={"exc": str(exc), "trace_id": trace_id})

    try:
        job_queue.put_nowait(job)
    except asyncio.QueueFull:
        raise _err(429, ErrorCode.RATE_LIMITED, "Analysis queue is full.", trace_id=trace_id)

    return {"accepted": True, "repo": repo, "pr": pr_number, "action": action, "trace_id": trace_id}
