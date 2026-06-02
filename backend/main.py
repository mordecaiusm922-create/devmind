"""
main.py -- DevMind SaaS API (Mitnick-style defensive rewrite v2)

Focus:
- adversarial defense mindset
- exploit-chain aware decisioning
- strict typing
- structured JSON logging
- idempotent GitHub webhook handling
- queue-based background processing
- rate limiting
- timeout isolation
- payload limits
- explicit merge-blocker decisions
- production-safe defaults
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
from typing import Any, Annotated, Optional

import httpx
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from agent import AgentConfig, DevMindAgent
from calibration import expected_calibration_error
from evaluator import compute_risk_score, enforce_risk_floor
from evaluate import evaluate_payload
from feature_extractor import extract_features
from github import get_pr_data
from github_app import get_installation_token, post_commit_status, post_pr_comment, verify_webhook_signature
from logger import read_recent_logs
from memory import get_prior_for_prompt, record_outcome, record_strategy_result, summarize_repo_memory
from parser import parse_pr_file
from prob_engine import GenerateRequest, RepairRequest, VerifyRequest, generate_request, repair_request, verify_candidate
from safety_flow import SafetyFlowRequest, run_safety_flow
from sandbox import run_sandbox
from policy import decide_policy, to_dict as policy_to_dict
from decision_resolver import resolve_decision

load_dotenv()

# =============================================================================
# 1. CONSTANTS / LIMITS
# =============================================================================

MAX_FILES_PER_PR = 100
MAX_DIFF_CHARS_PER_PR = 250_000
MAX_WEBHOOK_BODY_BYTES = 2_000_000
JOB_QUEUE_MAXSIZE = 500
IDEMPOTENCY_TTL_HOURS = 24
CACHE_TTL_MINUTES = 30
ANALYSIS_CACHE_MAX = 256

# =============================================================================
# 2. LOGGING
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


class JsonFormatter(logging.Formatter):
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


def configure_logging() -> logging.Logger:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    return logging.getLogger("devmind")


log = configure_logging()

# =============================================================================
# 3. CONFIG
# =============================================================================


@dataclass(frozen=True)
class Config:
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
    def from_env(cls) -> "Config":
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


CFG = Config.from_env()

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


def err(http_status: int, code: ErrorCode, detail: str, *, trace_id: str | None = None) -> HTTPException:
    return HTTPException(
        status_code=http_status,
        detail={"error": code.value, "message": detail, "trace_id": trace_id},
    )

# =============================================================================
# 5. TTL STORAGE / CIRCUIT BREAKER
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


class CircuitBreaker:
    def __init__(self, threshold: int = 5, cooldown_s: int = 30) -> None:
        self.threshold = threshold
        self.cooldown_s = cooldown_s
        self.failures = 0
        self.open_until = 0.0
        self._lock = threading.Lock()

    def allow(self) -> bool:
        with self._lock:
            return time.monotonic() >= self.open_until

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

# =============================================================================
# 6. SUPABASE LOOKUP
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


class SlidingWindowRateLimiter:
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
                raise err(status.HTTP_429_TOO_MANY_REQUESTS, ErrorCode.RATE_LIMITED, f"Limit: {self._max} requests per {self._window}s.")
            timestamps.append(now)
            self._store[key] = timestamps


_limiter = SlidingWindowRateLimiter(CFG.rate_limit_requests, CFG.rate_limit_window_s)

# =============================================================================
# 8. AUTH
# =============================================================================


def require_api_key(x_api_key: Annotated[str | None, Header(alias="x-api-key")] = None) -> str:
    if not x_api_key:
        raise err(status.HTTP_401_UNAUTHORIZED, ErrorCode.MISSING_API_KEY, "Pass X-Api-Key header.")

    valid = x_api_key in CFG.static_api_keys or _supabase.key_exists(x_api_key)
    if not valid:
        raise err(status.HTTP_401_UNAUTHORIZED, ErrorCode.INVALID_API_KEY, "API key not recognized.")

    _limiter.check(x_api_key)
    return x_api_key

# =============================================================================
# 9. REQUEST CONTEXT
# =============================================================================

_ctx = threading.local()


def get_trace_id() -> str:
    return getattr(_ctx, "trace_id", "unknown")

# =============================================================================
# 10. DOMAIN MODELS
# =============================================================================


class AnalysePRRequest(BaseModel):
    repo: str
    pr_number: int

    @field_validator("repo")
    @classmethod
    def validate_repo(cls, v: str) -> str:
        parts = v.strip().split("/")
        if len(parts) != 2 or not all(parts):
            raise ValueError("repo must be 'owner/repo'")
        return v.strip()

    @field_validator("pr_number")
    @classmethod
    def validate_pr(cls, v: int) -> int:
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


class EvaluateRequest(BaseModel):
    prompt: str
    candidates: list[dict[str, Any]] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)
    mode: str = Field(default="balanced")
    intent: dict[str, Any] = Field(default_factory=dict)
    evidence: dict[str, Any] = Field(default_factory=dict)
    history: list[dict[str, Any]] = Field(default_factory=list)
    files: list[dict[str, Any]] = Field(default_factory=list)
    repo: Optional[str] = Field(default=None)


class SandboxRequest(BaseModel):
    candidate: dict[str, Any] = Field(default_factory=dict)
    context: dict[str, Any] = Field(default_factory=dict)


class OutcomeRequest(BaseModel):
    repo: str = Field(default="")
    pr_number: int = Field(default=0)
    outcome: str = Field(default="")
    text: str = Field(default="")
    metadata: dict[str, Any] = Field(default_factory=dict)


# =============================================================================
# 11. AGENT
# =============================================================================

analysis_agent = DevMindAgent(config=AgentConfig(retry_on_failure=True, max_retries=1, verbose=False))

# =============================================================================
# 12. METRICS
# =============================================================================

METRICS: dict[str, int] = defaultdict(int)


def metric(name: str, delta: int = 1) -> None:
    METRICS[name] += delta

# =============================================================================
# 13. HELPERS
# =============================================================================


def build_cache_key(repo: str, pr_number: int) -> str:
    return f"{repo}#{pr_number}"


def check_payload_limits(pr_data: dict[str, Any]) -> None:
    files = pr_data.get("files", [])
    diff_chars = sum(len(f.get("diff") or "") for f in files)
    if len(files) > MAX_FILES_PER_PR:
        raise err(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, ErrorCode.INVALID_PAYLOAD, "PR has too many files.")
    if diff_chars > MAX_DIFF_CHARS_PER_PR:
        raise err(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, ErrorCode.INVALID_PAYLOAD, "PR diff is too large.")


def normalize_summary(summary: dict[str, Any]) -> dict[str, Any]:
    data = dict(summary or {})
    risk_raw = data.get("risk_note") or data.get("risk") or {}
    if isinstance(risk_raw, str):
        parts = risk_raw.split("--", 1)
        level = parts[0].strip().lower()
        reason = parts[1].strip() if len(parts) > 1 else risk_raw.strip()
        data["risk_note"] = {"level": level, "reason": reason}
    elif isinstance(risk_raw, dict):
        data["risk_note"] = {"level": str(risk_raw.get("level", "low")).lower(), "reason": str(risk_raw.get("reason", "")).strip()}
    else:
        data["risk_note"] = {"level": "low", "reason": ""}
    data.pop("risk", None)
    return data


def validate_summary(summary: dict[str, Any]) -> SummarySchema:
    return SummarySchema.model_validate(normalize_summary(summary))


def score_to_merge_state(level: str) -> str:
    return "failure" if level in ("critical", "high") else "success"


def _build_pr_comment(result: dict[str, Any], sf_result: dict[str, Any] | None = None) -> str:
    summary = result.get("summary", {})
    risk_engine = result.get("risk_engine", {})
    unified_risk = result.get("risk", {})
    unified_decision = result.get("decision", {})
    level = unified_risk.get("band", risk_engine.get("band", "low"))
    score = unified_risk.get("score", risk_engine.get("score", 0))
    top_factors = risk_engine.get("top_factors", [])
    vulns = summary.get("vulnerabilities") or []
    triage = result.get("triage", summary.get("triage", "P3"))
    merge_block = unified_decision.get("action") == "BLOCK" or summary.get("merge_blocker", False)
    merge_reason = unified_decision.get("reason") or summary.get("merge_block_reason")
    emoji = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "minimal": "MINIMAL"}.get(level, "LOW")

    vuln_lines: list[str] = []
    for v in vulns:
        sev = str(v.get("severity", "unknown")).upper()
        loc = v.get("location", "-")
        desc = v.get("description", "")
        fix = v.get("fix", "")
        path = v.get("exploit_path", "")
        block = f"**[{sev}]** `{loc}`\n{desc}\n"
        if path:
            block += f"**Exploit path:** {path}\n"
        block += f"**Fix:** {fix}"
        vuln_lines.append(block)

    factors_md = "\n".join(f"- {f}" for f in top_factors) if top_factors else "- None detected"
    vulns_md = "\n\n".join(vuln_lines) if vuln_lines else "_No vulnerabilities detected_"
    blocker_md = f"Merge blocked. {merge_reason}" if merge_block else ""
    breakdown = risk_engine.get("breakdown", {})
    scores_md = (
        f"| Metric | Score |\n"
        f"|--------|-------|\n"
        f"| Risk Score | `{score}/100` |\n"
        f"| Decision | `{unified_decision.get('action', 'N/A')}` |\n"
        f"| Exploit probability | `{unified_risk.get('p_exploit', 0)}` |\n"
        f"| Probability | `{breakdown.get('probability', 0)}` |\n"
        f"| Impact | `{breakdown.get('impact', 0)}` |\n"
        f"| Confidence | `{breakdown.get('confidence', 0)}` |"
    )

    sf_section = ""
    if sf_result and sf_result.get("selected"):
        sel = sf_result["selected"]
        dec = sf_result.get("decision", {})
        sf_section = f"""
### Safety Flow
**Decision:** `{dec.get('action', 'N/A')}` — Candidate `{sel.get('candidate', 'N/A')}`
**Risk-adjusted utility:** `{sel.get('risk_adjusted_utility', 0)}`
**Security:** `{sel.get('security', 0)}`
**Verified:** `{sel.get('verified', False)}`
**Rationale:** {', '.join(sel.get('rationale', [])[:3])}
"""

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
**What:** {summary.get('what', 'N/A')}
**Impact:** {summary.get('impact', 'N/A')}
**Review focus:** {summary.get('review_focus', 'N/A')}
{sf_section}
---
_Analyzed by DevMind • trace `{result.get('trace_id', '')}`_
"""


def _build_code_features(pr_data: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    parsed_all: list[dict[str, Any]] = []
    for f in pr_data.get("files", []):
        fname = f.get("filename", "")
        patch = f.get("raw_patch", "") or f.get("diff", "")
        if not patch or f.get("is_noise"):
            continue
        try:
            parsed = parse_pr_file(fname, patch, None)
            parsed_all.append(parsed)
        except Exception as exc:
            log.warning("parse_file_failed", extra={"file": fname, "exc": str(exc)})

    combined: dict[str, list] = {"functions_changed": [], "calls": []}
    for p in parsed_all:
        combined["functions_changed"].extend(p.get("functions_changed", []))
        combined["calls"].extend(p.get("calls", []))

    diff_stats = {"additions": pr_data.get("additions", 0), "deletions": pr_data.get("deletions", 0), "changed_files": pr_data.get("changed_files", 0)}
    features = extract_features(combined, diff_stats)
    return features, combined["functions_changed"]


def detect_attack_chain(pr_data: dict[str, Any], summary: dict[str, Any], safety_flow: dict[str, Any] | None) -> tuple[int, list[str]]:
    """
    Adversarial defense heuristic: detect whether separate low/medium signals
    compose into a practical exploit path.
    """
    text_parts = [
        str(summary.get("what", "")),
        str(summary.get("why", "")),
        str(summary.get("impact", "")),
        str(summary.get("review_focus", "")),
        json.dumps(summary.get("vulnerabilities", []), default=str),
        json.dumps(summary.get("ci_cd_risks", []), default=str),
        json.dumps(pr_data.get("files", []), default=str),
    ]
    if safety_flow:
        text_parts.append(json.dumps(safety_flow.get("representation", {}), default=str))
        text_parts.append(json.dumps(safety_flow.get("risk", {}), default=str))
        text_parts.append(json.dumps(safety_flow.get("runtime_evidence", {}), default=str))
    text = " ".join(text_parts).lower()

    score = 0
    chain: list[str] = []

    if any(k in text for k in ("secret", "token", "credential", "api_key", "private key", "client_secret")):
        score += 15
        chain.append("secret_surface")
    if any(k in text for k in ("auth", "authorization", "authentication", "rbac", "session", "jwt", "oauth", "saml")):
        score += 12
        chain.append("auth_surface")
    if any(k in text for k in ("eval(", "| bash", "curl http", "subprocess", "os.system", "shell=true")):
        score += 35
        chain.append("dangerous_sink")
    if any(k in text for k in ("public-read", "0.0.0.0/0", "privileged: true", "hostnetwork", "wildcard", "allowprivilegeescalation")):
        score += 30
        chain.append("exposure_surface")
    if any(k in text for k in ("pull_request_target", "workflow_run", "github_token", "secrets.", "write-all")):
        score += 25
        chain.append("ci_trust_boundary")
    if any(k in text for k in ("drop table", "drop column", "delete from", "force_destroy", "truncate")):
        score += 30
        chain.append("destructive_change")

    if {"secret_surface", "auth_surface"}.issubset(chain):
        score += 12
        chain.append("credential_to_identity_chain")
    if {"auth_surface", "dangerous_sink"}.issubset(chain):
        score += 10
        chain.append("identity_to_sink_chain")
    if {"ci_trust_boundary", "secret_surface"}.issubset(chain):
        score += 14
        chain.append("ci_secret_exposure_chain")
    if {"exposure_surface", "dangerous_sink"}.issubset(chain):
        score += 10
        chain.append("remote_reachability_chain")

    if safety_flow:
        selected = safety_flow.get("selected") or {}
        if selected.get("critical_violations"):
            score += 25
            chain.append("critical_verification_violations")
        if selected.get("violations"):
            score += 12
            chain.append("verification_violations")
        if str((safety_flow.get("decision") or {}).get("action", "")).lower() in {"reject", "revise"}:
            score += 15
            chain.append("policy_restriction")
        if float((safety_flow.get("risk") or {}).get("p_exploit", 0.0) or 0.0) >= 0.7:
            score += 10
            chain.append("high_exploit_probability")

    return min(100, score), chain


# =============================================================================
# 14. PIPELINE
# =============================================================================


async def run_pipeline(repo: str, pr_number: int, trace_id: str) -> dict[str, Any]:
    cache_key = build_cache_key(repo, pr_number)
    cached = analysis_cache.get(cache_key)
    if cached is not None:
        metric("analysis_cache_hit")
        return cached

    if not analysis_breaker.allow():
        raise err(503, ErrorCode.UPSTREAM_ERROR, "Analysis circuit breaker open.", trace_id=trace_id)

    metric("analysis_start")
    log.info("analysis_start", extra={"repo": repo, "pr": pr_number, "trace_id": trace_id})

    try:
        result = await asyncio.wait_for(asyncio.to_thread(pipeline_sync, repo, pr_number, trace_id), timeout=CFG.analysis_timeout_s)
        analysis_breaker.success()
        analysis_cache.set(cache_key, result)
        metric("analysis_success")
        return result
    except asyncio.TimeoutError:
        analysis_breaker.failure()
        metric("analysis_timeout")
        raise err(504, ErrorCode.ANALYSIS_TIMEOUT, f"Analysis timed out after {CFG.analysis_timeout_s}s.", trace_id=trace_id)
    except HTTPException:
        analysis_breaker.failure()
        raise
    except ValueError as exc:
        analysis_breaker.failure()
        metric("analysis_validation_error")
        log.error("validation_error_detail", extra={"exc": str(exc), "trace_id": trace_id}, exc_info=True)
        raise err(422, ErrorCode.VALIDATION_ERROR, str(exc), trace_id=trace_id)
    except Exception as exc:
        analysis_breaker.failure()
        msg = str(exc)
        if "404" in msg or "Not Found" in msg:
            raise err(404, ErrorCode.PR_NOT_FOUND, f"PR not found: {repo}#{pr_number}", trace_id=trace_id)
        if any(code in msg for code in ("401", "403")):
            raise err(401, ErrorCode.GITHUB_AUTH_FAILURE, "GitHub API auth failed. Check GITHUB_TOKEN.", trace_id=trace_id)
        log.error("analysis_error", extra={"exc": msg, "trace_id": trace_id}, exc_info=True)
        raise err(400, ErrorCode.UPSTREAM_ERROR, msg, trace_id=trace_id)


def pipeline_sync(repo: str, pr_number: int, trace_id: str) -> dict[str, Any]:
    _ctx.trace_id = trace_id

    def timed(label: str, fn, *args, **kwargs):
        t0 = time.monotonic()
        result = fn(*args, **kwargs)
        log.info("pipeline_step", extra={"step": label, "duration_ms": round((time.monotonic() - t0) * 1000), "trace_id": trace_id})
        return result

    pr_data = timed("get_pr_data", get_pr_data, repo, pr_number)
    check_payload_limits(pr_data)

    agent_result = timed("agent_run", analysis_agent.run, pr_data)
    summary = normalize_summary(agent_result.summary)
    pre = agent_result.pre_analysis
    if pre is None:
        class _Pre:
            risk_floor = 'low'
            risk_tags = frozenset()
            flagged_files = frozenset()
            trivially_touched = frozenset()
            files_with_diff = 0
            files_skipped_budget = 0
            files_skipped_noise = 0
            total_diff_chars = 0
        pre = _Pre()
    ev = agent_result.evaluation

    validated_summary = validate_summary(summary).model_dump()
    if pre is None:
        class _FallbackPre:
            risk_floor="low"; risk_tags=frozenset(); flagged_files=frozenset()
            trivially_touched=frozenset(); files_with_diff=0
            files_skipped_budget=0; files_skipped_noise=0; total_diff_chars=0
        pre = _FallbackPre()
    validated_summary = enforce_risk_floor(validated_summary, pre)

    permissions = validated_summary.get("permissions_analysis", {}) or {}
    vulns = validated_summary.get("vulnerabilities", []) or []
    ci_cd_risks = validated_summary.get("ci_cd_risks", []) or []
    risk_band = str(validated_summary.get("risk_note", {}).get("level", "low")).lower()
    risk_floor = pre.risk_floor

    features, parsed_functions = _build_code_features(pr_data)

    ev_obj = ev
    if isinstance(ev, dict):
        from evaluator import Evaluation

        ev_inner = ev.get("evaluation", ev)
        ev_obj = Evaluation(
            confidence=ev_inner.get("confidence", "low"),
            confidence_score=ev_inner.get("confidence_score", 0.0),
            specificity_score=ev_inner.get("specificity_score", 0.0),
            generic_phrases_found=tuple(ev_inner.get("generic_phrases_found", [])),
            generic_penalty=ev_inner.get("generic_penalty", 0),
            is_flagged=ev_inner.get("is_flagged", False),
            flag_reason=ev_inner.get("flag_reason", None),
        )

    risk_signals = compute_risk_score(pre, summary, ev_obj, pr_data) if pre and ev_obj else None

    response = build_response(repo=repo, risk_signals=risk_signals, pr_number=pr_number, pr_data=pr_data, summary=validated_summary, pre=pre, ev=ev, trace_id=trace_id, features=features, parsed_fns=parsed_functions)
    safety_flow = run_pr_safety_flow(repo, pr_number, pr_data, response, trace_id)

    attack_chain_score, attack_chain_path = 0, []

    merge_blocker = attack_chain_score >= 70 or bool(vulns) or bool(ci_cd_risks)
    merge_reason = (
        "Exploit chain detected." if attack_chain_score >= 70
        else "Security findings require review." if (vulns or ci_cd_risks)
        else "No blocking conditions met."
    )

    policy_dec = decide_policy(ev, selected=(safety_flow or {}).get("selected"), mode="secure")
    _POLICY_MAP = {"APPROVE": "approve", "REJECT": "reject", "REVIEW": "review", "REVISE": "revise", "NEEDS_VERIFICATION": "needs_verification", "NEEDS_REPAIR": "revise", "ABSTAIN": ""}
    policy_str = _POLICY_MAP.get(policy_dec.action.value.upper(), "")

    resolved = resolve_decision(
        calibrated_score=min(attack_chain_score, 30) if not merge_blocker else attack_chain_score,
        legacy_merge_blocker=merge_blocker,
        severity_floor=0,
        severity_reason=merge_reason,
        safety_decision=str((safety_flow or {}).get("decision", {}).get("action", "") or ""),
        selected=(safety_flow or {}).get("selected") or {},
        has_findings=bool(vulns or ci_cd_risks),
        policy_decision=policy_str.upper() if policy_str else ("BLOCK" if policy_dec.action.value.upper() in ("REJECT",) else "REVIEW" if policy_dec.action.value.upper() in ("NEEDS_REPAIR", "NEEDS_VERIFICATION", "REVISE", "REVIEW") else ""),
        policy_reason=policy_dec.reason,
        policy_why_chain=list(policy_dec.reasons or []),
        pr_files=[{"filename": f.get("filename", "")} for f in pr_data.get("files", []) if f.get("filename")],
    )

    response["attack_chain"] = {"score": attack_chain_score, "path": attack_chain_path, "merge_blocker": resolved.action == "BLOCK", "reason": resolved.reason}
    response["summary"]["merge_blocker"] = resolved.action == "BLOCK"
    response["summary"]["merge_block_reason"] = resolved.reason

    attach_unified_decision(response, safety_flow, attack_chain_score, resolved.reason)
    response["decision"] = {
        "action": resolved.action,
        "confidence": resolved.confidence,
        "reason": resolved.reason,
        "merge_blocker": resolved.action == "BLOCK",
        "blocking_findings": resolved.blocking_findings,
        "why_chain": resolved.why_chain,
        "policy": policy_to_dict(policy_dec),
    }
    response["policy_score"] = resolved.policy_score
    metric("analysis_done")
    return response


def build_response(*, repo: str, risk_signals: Any = None, pr_number: int, pr_data: dict[str, Any], summary: dict[str, Any], pre: Any, ev: Any, trace_id: str, features: dict[str, Any], parsed_fns: list[Any]) -> dict[str, Any]:
    evaluation = ev.get("evaluation", {}) if isinstance(ev, dict) else {}
    return {
        "schema_version": "1.5.0",
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
        "probabilistic": ev.get("probabilistic", {}) if isinstance(ev, dict) else {},
        "risk_engine": {
            "score": risk_signals.risk_score if risk_signals else 0,
            "band": risk_signals.risk_band if risk_signals else "low",
            "label": risk_signals.risk_label if risk_signals else "",
            "top_factors": list(risk_signals.top_factors) if risk_signals else [],
            "breakdown": {
                "probability": risk_signals.p_score if risk_signals else 0,
                "impact": risk_signals.i_score if risk_signals else 0,
                "confidence": risk_signals.c_score if risk_signals else 0,
            },
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


def run_pr_safety_flow(repo: str, pr_number: int, pr_data: dict[str, Any], response: dict[str, Any], trace_id: str) -> dict[str, Any] | None:
    req = SafetyFlowRequest(
        prompt=build_pr_safety_prompt(repo, pr_number, pr_data, response),
        mode="secure",
        repo=repo,
        context={
            "repo": repo,
            "pr_number": pr_number,
            "title": pr_data.get("title", ""),
            "filename": first_relevant_filename(response, pr_data),
            "risk_engine": response.get("risk_engine", {}),
            "triage": response.get("summary", {}).get("triage"),
            "merge_blocker": response.get("summary", {}).get("merge_blocker", False),
            "vulnerabilities": response.get("summary", {}).get("vulnerabilities", []),
            "ci_cd_risks": response.get("summary", {}).get("ci_cd_risks", []),
            "permissions_analysis": response.get("summary", {}).get("permissions_analysis", {}),
        },
        intent={"label": "pr_decision", "confidence": 0.82},
        evidence={
            "summary_evidence": response.get("summary", {}).get("evidence", []),
            "risk_engine": response.get("risk_engine", {}),
            "pre_analysis": response.get("pre_analysis", {}),
        },
        files=normalize_pr_files_for_safety(pr_data),
        n_candidates=3,
        max_repair_attempts=1,
    )
    try:
        return run_safety_flow(req)
    except Exception as exc:
        log.warning("safety_flow_failed", extra={"exc": str(exc), "trace_id": trace_id})
        return None


def build_pr_safety_prompt(repo: str, pr_number: int, pr_data: dict[str, Any], response: dict[str, Any]) -> str:
    summary = response.get("summary", {})
    vulns = summary.get("vulnerabilities") or []
    ci_cd = summary.get("ci_cd_risks") or []
    vuln_lines = [f"- {v.get('severity', 'unknown')} {v.get('type', 'vulnerability')} at {v.get('location', '-')}: {v.get('description', '')}. Fix: {v.get('fix', '')}" for v in vulns]
    ci_lines = [f"- trigger={r.get('trigger', '-')}; severity={r.get('severity', '-')}; risk={r.get('risk', '')}; line={r.get('line', '-')}" for r in ci_cd]
    return "\n".join([
        f"Analyze and repair security risk for PR {repo}#{pr_number}: {pr_data.get('title', '')}",
        f"What changed: {summary.get('what', '')}",
        f"Why: {summary.get('why', '')}",
        f"Impact: {summary.get('impact', '')}",
        f"Review focus: {summary.get('review_focus', '')}",
        "Vulnerabilities:",
        "\n".join(vuln_lines) if vuln_lines else "- none reported",
        "CI/CD risks:",
        "\n".join(ci_lines) if ci_lines else "- none reported",
        "Generate fix candidates, verify safety properties, and decide whether this PR should be blocked, reviewed, or allowed.",
    ])


def normalize_pr_files_for_safety(pr_data: dict[str, Any]) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    for f in pr_data.get("files", []) or []:
        filename = str(f.get("filename") or "")
        if not filename:
            continue
        files.append({"filename": filename, "diff": str(f.get("diff") or f.get("patch") or f.get("raw_patch") or ""), "raw_patch": str(f.get("raw_patch") or f.get("diff") or ""), "status": str(f.get("status") or "modified"), "additions": int(f.get("additions") or 0), "deletions": int(f.get("deletions") or 0)})
    return files


def first_relevant_filename(response: dict[str, Any], pr_data: dict[str, Any]) -> str:
    summary = response.get("summary", {})
    for item in summary.get("vulnerabilities") or []:
        location = str(item.get("location") or "")
        if ":" in location:
            return location.split(":", 1)[0]
        if location:
            return location
    for item in summary.get("key_changes") or []:
        text = str(item)
        if ":" in text:
            candidate = text.split(":", 1)[0].strip()
            if "." in candidate:
                return candidate
    for f in pr_data.get("files", []) or []:
        filename = str(f.get("filename") or "")
        if filename:
            return filename
    return "app.py"


def attach_unified_decision(response: dict[str, Any], safety_flow: dict[str, Any] | None, attack_chain_score: int, attack_chain_reason: str) -> None:
    unified = build_unified_decision(response, safety_flow, attack_chain_score, attack_chain_reason)
    response["decision"] = unified["decision"]
    response["risk"] = unified["risk"]
    response["fix_candidates"] = unified["fix_candidates"]
    response["triage"] = unified["triage"]
    response["safety_flow"] = unified["safety_flow"]
    summary = response.setdefault("summary", {})
    summary["triage"] = unified["triage"]
    if unified["decision"]["action"] == "BLOCK":
        summary["merge_blocker"] = True
        summary["merge_block_reason"] = unified["decision"]["reason"]


def build_unified_decision(response: dict[str, Any], safety_flow: dict[str, Any] | None, attack_chain_score: int, attack_chain_reason: str) -> dict[str, Any]:
    summary = response.get("summary", {})
    risk_engine = response.get("risk_engine", {})
    vulns = summary.get("vulnerabilities") or []
    ci_cd_risks = summary.get("ci_cd_risks") or []
    legacy_score = as_int(risk_engine.get("score"), 0)
    legacy_probability = as_float((risk_engine.get("breakdown") or {}).get("probability"), 0.0)

    selected = (safety_flow or {}).get("selected") or {}
    sf_decision = (safety_flow or {}).get("decision") or {}
    sf_risk = (safety_flow or {}).get("risk") or {}
    sf_score = max(safety_flow_risk_score(selected, sf_decision), as_int(sf_risk.get("score"), 0))
    severity_floor, severity_reason = finding_severity_floor(vulns, ci_cd_risks, summary)

    calibrated_score = max(legacy_score, sf_score, severity_floor, attack_chain_score)
    verified = bool(selected.get("verified", False))
    has_findings = bool(vulns or ci_cd_risks)
    if verified and not has_findings and str(sf_decision.get("action", "")).lower() == "approve":
        calibrated_score = max(0, calibrated_score - 8)

    calibrated_score = max(0, min(100, calibrated_score))
    action, reason = unified_action(calibrated_score=calibrated_score, legacy_merge_blocker=bool(summary.get("merge_blocker", False)), severity_floor=severity_floor, severity_reason=severity_reason, safety_decision=str(sf_decision.get("action") or ""), selected=selected, has_findings=has_findings, attack_chain_score=attack_chain_score, attack_chain_reason=attack_chain_reason)
    triage = triage_for_unified_decision(action, calibrated_score, severity_floor)
    confidence = unified_confidence(response, safety_flow, calibrated_score)
    p_exploit = calibrated_exploit_probability(legacy_probability=legacy_probability, calibrated_score=calibrated_score, selected=selected, vulns=vulns, ci_cd_risks=ci_cd_risks, safety_flow_risk=sf_risk, attack_chain_score=attack_chain_score)

    return {
        "decision": {"action": action, "confidence": confidence, "reason": reason, "merge_blocker": action == "BLOCK"},
        "risk": {"score": calibrated_score, "band": band_for_score(calibrated_score), "p_exploit": p_exploit, "source_scores": {"analyze_pr": legacy_score, "safety_flow": sf_score, "finding_floor": severity_floor, "attack_chain": attack_chain_score}, "calibration": "max(analyze_pr, safety_flow_expected_loss, severity_floor, attack_chain)", "safety_flow_calibration": sf_risk.get("calibration", {})},
        "fix_candidates": extract_fix_candidates(safety_flow),
        "triage": triage,
        "safety_flow": compact_safety_flow(safety_flow),
    }


def safety_flow_risk_score(selected: dict[str, Any], decision: dict[str, Any]) -> int:
    if not selected:
        return 0
    expected_loss = as_float(selected.get("expected_loss"), None)
    if expected_loss is None:
        expected_loss = 1.0 - as_float(selected.get("risk_adjusted_utility"), 0.0)
    score = int(round(max(0.0, min(1.0, expected_loss)) * 100))
    action = str(decision.get("action") or "").lower()
    if action == "reject":
        score = max(score, 90)
    elif action == "revise":
        score = max(score, 70)
    elif action == "needs_verification":
        score = max(score, 55)
    if selected.get("critical_violations"):
        score = max(score, 88)
    elif selected.get("violations"):
        score = max(score, 62)
    return max(0, min(100, score))


def finding_severity_floor(vulns: list[dict[str, Any]], ci_cd_risks: list[dict[str, Any]], summary: dict[str, Any]) -> tuple[int, str]:
    floor = 0
    reason = "No security findings require a floor."
    for vuln in vulns:
        severity = str(vuln.get("severity", "low")).lower()
        if severity == "critical" and floor < 88:
            floor, reason = 88, "Critical vulnerability reported by analyze-pr."
        elif severity == "high" and floor < 74:
            floor, reason = 74, "High vulnerability reported by analyze-pr."
        elif severity == "medium" and floor < 55:
            floor, reason = 55, "Medium vulnerability reported by analyze-pr."
        elif severity == "low" and floor < 32:
            floor, reason = 32, "Low vulnerability reported by analyze-pr."
    for risk in ci_cd_risks:
        severity = str(risk.get("severity", "low")).lower()
        trigger = str(risk.get("trigger", "")).lower()
        if trigger in {"pull_request_target", "workflow_run"} and risk.get("secrets_exposed"):
            if floor < 86:
                floor, reason = 86, "CI/CD risk exposes secrets across a trust boundary."
        elif severity == "high" and floor < 70:
            floor, reason = 70, "High CI/CD risk reported by analyze-pr."
        elif severity == "medium" and floor < 52:
            floor, reason = 52, "Medium CI/CD risk reported by analyze-pr."
    if summary.get("merge_blocker") and floor < 80:
        floor, reason = 80, str(summary.get("merge_block_reason") or "Legacy merge blocker is active.")
    return floor, reason


def unified_action(*, calibrated_score: int, legacy_merge_blocker: bool, severity_floor: int, severity_reason: str, safety_decision: str, selected: dict[str, Any], has_findings: bool, attack_chain_score: int, attack_chain_reason: str) -> tuple[str, str]:
    if attack_chain_score >= 70:
        return "BLOCK", attack_chain_reason or "Exploit chain reaches a dangerous sink."
    if selected.get("critical_violations"):
        return "BLOCK", "Safety-flow found critical verification violations."
    if safety_decision == "reject":
        return "BLOCK", "Safety-flow rejected the best candidate."
    if legacy_merge_blocker or severity_floor >= 80 or calibrated_score >= 85:
        return "BLOCK", severity_reason or "Risk floor exceeded."
    if safety_decision in {"revise", "needs_verification"}:
        return "REVIEW", "Safety-flow requires verification before this change can be trusted."
    if selected.get("violations"):
        return "REVIEW", "Safety-flow found unresolved verification violations."
    if has_findings or calibrated_score >= 40:
        return "REVIEW", "Security findings or calibrated risk require review."
    return "ALLOW", "No blocking findings and the selected candidate passed verification."


def triage_for_unified_decision(action: str, score: int, severity_floor: int) -> str:
    if action == "BLOCK":
        return "P0" if score >= 85 or severity_floor >= 86 else "P1"
    if action == "REVIEW":
        if score >= 70:
            return "P1"
        if score >= 40:
            return "P2"
        return "P3"
    return "P3"


def unified_confidence(response: dict[str, Any], safety_flow: dict[str, Any] | None, calibrated_score: int) -> float:
    evaluation = response.get("evaluation", {})
    selected = (safety_flow or {}).get("selected") or {}
    operational = (safety_flow or {}).get("operational_metrics") or {}
    base = 0.50
    base += 0.20 * as_float(evaluation.get("confidence_score"), 0.0)
    base += 0.15 * as_float(selected.get("verification_score"), 0.0)
    base += 0.10 * as_float(operational.get("verification_pass_rate"), 0.0)
    base += 0.10 * abs((calibrated_score / 100.0) - 0.5) * 2
    base -= 0.12 * as_float(selected.get("uncertainty"), 0.0)
    return round(max(0.0, min(0.99, base)), 4)


def calibrated_exploit_probability(*, legacy_probability: float, calibrated_score: int, selected: dict[str, Any], vulns: list[dict[str, Any]], ci_cd_risks: list[dict[str, Any]], safety_flow_risk: dict[str, Any] | None = None, attack_chain_score: int = 0) -> float:
    finding_prior = 0.0
    if vulns:
        severities = {str(v.get("severity", "low")).lower() for v in vulns}
        if "critical" in severities:
            finding_prior = 0.88
        elif "high" in severities:
            finding_prior = 0.72
        elif "medium" in severities:
            finding_prior = 0.50
        else:
            finding_prior = 0.30
    if ci_cd_risks:
        finding_prior = max(finding_prior, 0.45)

    model_prior = 1.0 - as_float(selected.get("security"), 0.5)
    score_prior = calibrated_score / 100.0
    safety_prior = as_float((safety_flow_risk or {}).get("p_exploit"), 0.0)
    chain_prior = attack_chain_score / 100.0
    p = max(legacy_probability, finding_prior, model_prior, score_prior * 0.85, safety_prior, chain_prior)
    return round(max(0.0, min(0.99, p)), 4)


def extract_fix_candidates(safety_flow: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not safety_flow:
        return []
    candidates = {str(c.get("id")): c for c in safety_flow.get("candidates", [])}
    out = []
    for item in safety_flow.get("ranking", [])[:5]:
        cid = str(item.get("candidate"))
        candidate = candidates.get(cid, {})
        out.append({"id": cid, "strategy": item.get("strategy") or candidate.get("strategy"), "verified": bool(item.get("verified", False)), "risk_adjusted_utility": item.get("risk_adjusted_utility"), "expected_loss": item.get("expected_loss"), "security": item.get("security"), "uncertainty": item.get("uncertainty"), "violations": item.get("violations", []), "critical_violations": item.get("critical_violations", []), "explanation": candidate.get("explanation", ""), "diff": candidate.get("diff", "")})
    return out


def compact_safety_flow(safety_flow: dict[str, Any] | None) -> dict[str, Any]:
    if not safety_flow:
        return {"available": False, "decision": {"action": "unavailable"}, "selected": None, "ranking": []}
    return {"available": True, "flow": safety_flow.get("flow", []), "decision": safety_flow.get("decision", {}), "deployment_policy": safety_flow.get("deployment_policy", {}), "selected": safety_flow.get("selected"), "ranking": safety_flow.get("ranking", [])[:5], "risk": safety_flow.get("risk", {}), "properties": safety_flow.get("properties", []), "representation": safety_flow.get("representation", {}), "runtime_evidence": safety_flow.get("runtime_evidence", {}), "operational_metrics": safety_flow.get("operational_metrics", {}), "prior": safety_flow.get("prior", {})}


def band_for_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "minimal"


def as_float(value: Any, default: float | None = 0.0) -> float | None:
    try:
        if value is None:
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def as_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(round(float(value)))
    except (TypeError, ValueError):
        return default


def build_attack_path_hint(summary: dict[str, Any], safety_flow: dict[str, Any] | None) -> list[str]:
    hint: list[str] = []
    attack = summary.get("attack_path") or {}
    if attack:
        if attack.get("entry_point"):
            hint.append(f"entry:{attack.get('entry_point')}")
        if attack.get("sink"):
            hint.append(f"sink:{attack.get('sink')}")
        if attack.get("blast_radius"):
            hint.append(f"blast:{attack.get('blast_radius')}")
    if safety_flow and safety_flow.get("selected"):
        sel = safety_flow["selected"]
        if sel.get("critical_violations"):
            hint.append("selected_has_critical_violations")
        elif sel.get("violations"):
            hint.append("selected_has_violations")
    return hint

# =============================================================================
# 15. BACKGROUND JOBS
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


async def job_worker() -> None:
    assert job_queue is not None
    while True:
        job = await job_queue.get()
        try:
            token = get_installation_token(job.installation_id)
            result = await run_pipeline(job.repo, job.pr_number, trace_id=job.trace_id)
            sf_result = result.get("safety_flow")
            if sf_result and sf_result.get("selected"):
                try:
                    sel = sf_result["selected"]
                    record_strategy_result(
                        job.repo,
                        pr_number=job.pr_number,
                        strategy=str(sel.get("candidate", "unknown")),
                        intent=sf_result.get("prior", {}).get("intent", "general_fix"),
                        utility=float(sel.get("utility", 0)),
                        security=float(sel.get("security", 0)),
                        verified=bool(sel.get("verified", False)),
                        decision=str(sf_result.get("decision", {}).get("action", "unknown")),
                    )
                except Exception as mem_exc:
                    log.warning("memory_record_failed", extra={"exc": str(mem_exc)})
            comment = _build_pr_comment(result, sf_result=sf_result)
            post_pr_comment(job.repo, job.pr_number, comment, token)
            risk_obj = result.get("risk", result.get("risk_engine", {}))
            level = str(risk_obj.get("band", "low"))
            score = risk_obj.get("score", 0)
            action = str(result.get("decision", {}).get("action", "")).upper()
            state = "failure" if action == "BLOCK" else score_to_merge_state(level)
            post_commit_status(job.repo, job.commit_sha, token, state, f"{action or 'RISK'} {score}/100 - {level.upper()}")
            metric("job_success")
        except Exception as exc:
            metric("job_failure")
            log.error("job_failed", extra={"repo": job.repo, "pr": job.pr_number, "exc": str(exc), "trace_id": job.trace_id}, exc_info=True)
        finally:
            job_queue.task_done()

# =============================================================================
# 16. APP LIFECYCLE
# =============================================================================


@asynccontextmanager
async def lifespan(application: FastAPI):
    global job_queue
    job_queue = asyncio.Queue(maxsize=JOB_QUEUE_MAXSIZE)
    worker = asyncio.create_task(job_worker())
    log.info("startup", extra={"env": CFG.environment, "version": application.version})
    try:
        yield
    finally:
        worker.cancel()
        _supabase.close()
        log.info("shutdown")


app = FastAPI(title="DevMind API", version="1.5.1", docs_url="/docs" if CFG.is_dev else None, redoc_url=None, lifespan=lifespan)

allowed_origins = [CFG.frontend_origin]
if CFG.is_dev:
    allowed_origins.extend(["http://localhost:5173", "http://127.0.0.1:5173"])

app.add_middleware(CORSMiddleware, allow_origins=allowed_origins, allow_methods=["GET", "POST"], allow_headers=["*"])

# =============================================================================
# 17. MIDDLEWARE / ERRORS
# =============================================================================


@app.middleware("http")
async def observability(request: Request, call_next):
    trace_id = request.headers.get("x-trace-id") or str(uuid.uuid4())[:12]
    _ctx.trace_id = trace_id
    t0 = time.monotonic()
    response = await call_next(request)
    elapsed = round((time.monotonic() - t0) * 1000)
    log.info("http_request", extra={"method": request.method, "path": request.url.path, "status": response.status_code, "elapsed_ms": elapsed, "trace_id": trace_id})
    response.headers["X-Trace-Id"] = trace_id
    return response


@app.exception_handler(Exception)
async def unhandled_exception(request: Request, exc: Exception):
    tid = get_trace_id()
    log.error("unhandled_exception", extra={"path": request.url.path, "exc": str(exc), "trace_id": tid}, exc_info=True)
    return JSONResponse(status_code=500, content={"error": ErrorCode.INTERNAL_ERROR.value, "message": str(exc), "trace_id": tid})

# =============================================================================
# 18. ENDPOINTS
# =============================================================================


@app.api_route("/health", methods=["GET", "HEAD"])
async def healthcheck():
    return {"status": "ok", "version": app.version, "env": CFG.environment, "queue_size": 0 if job_queue is None else job_queue.qsize(), "metrics": METRICS}


@app.get("/")
async def root():
    return {"service": "DevMind", "status": "ok", "version": app.version}


@app.get("/metrics")
async def metrics():
    return {"metrics": METRICS}


@app.post("/analyze-pr", dependencies=[Depends(require_api_key)])
async def analyze_pr(req: AnalysePRRequest, request: Request):
    trace_id = request.headers.get("x-trace-id") or get_trace_id()
    log.info("analyze_pr_request", extra={"repo": req.repo, "pr": req.pr_number, "trace_id": trace_id})
    return await run_pipeline(req.repo, req.pr_number, trace_id=trace_id)


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
# 19. GITHUB WEBHOOK
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
        raise err(413, ErrorCode.INVALID_PAYLOAD, "Webhook payload too large.")
    if not verify_webhook_signature(body, x_hub_signature_256 or ""):
        raise err(401, ErrorCode.INVALID_WEBHOOK_SIG, "Signature mismatch.")
    if x_github_event != "pull_request":
        return {"accepted": False, "reason": f"event '{x_github_event}' not handled"}

    try:
        payload: dict[str, Any] = json.loads(body)
    except json.JSONDecodeError:
        raise err(400, ErrorCode.INVALID_PAYLOAD, "Body is not valid JSON.")

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
        raise err(400, ErrorCode.INVALID_PAYLOAD, "Missing repo, pr number, or installation_id.")

    if processed_deliveries.contains(delivery_id):
        metric("webhook_deduped")
        return {"accepted": True, "deduped": True, "trace_id": trace_id}

    processed_deliveries.add(delivery_id)
    log.info("webhook_received", extra={"action": action, "repo": repo, "pr": pr_number, "trace_id": trace_id})

    if job_queue is None:
        raise err(503, ErrorCode.UPSTREAM_ERROR, "Job queue not ready.", trace_id=trace_id)

    job = AnalysisJob(repo=repo, pr_number=pr_number, trace_id=trace_id, installation_id=installation_id, commit_sha=commit_sha, delivery_id=delivery_id)

    try:
        token_pending = get_installation_token(installation_id)
        post_commit_status(repo, commit_sha, token_pending, "pending", "DevMind is analyzing this PR...")
    except Exception as exc:
        log.warning("pending_status_failed", extra={"exc": str(exc), "trace_id": trace_id})

    try:
        job_queue.put_nowait(job)
    except asyncio.QueueFull:
        raise err(429, ErrorCode.RATE_LIMITED, "Analysis queue is full.", trace_id=trace_id)

    return {"accepted": True, "repo": repo, "pr": pr_number, "action": action, "trace_id": trace_id}


@app.post("/evaluate")
async def evaluate_endpoint(req: EvaluateRequest):
    return evaluate_payload(req.model_dump())


@app.post("/safety-flow", dependencies=[Depends(require_api_key)])
async def safety_flow_endpoint(req: SafetyFlowRequest):
    return run_safety_flow(req)


@app.get("/memory", dependencies=[Depends(require_api_key)])
async def memory_endpoint(repo: str, recent: int = 10):
    summary = summarize_repo_memory(repo)
    limit = max(0, recent)
    summary["recent_events"] = summary.get("recent_events", [])[-limit:] if limit else []
    return summary


@app.get("/memory/prior", dependencies=[Depends(require_api_key)])
async def memory_prior_endpoint(repo: str, prompt: str):
    return get_prior_for_prompt(repo, prompt)


@app.get("/calibration/ece", dependencies=[Depends(require_api_key)])
async def calibration_ece_endpoint(repo: str, bins: int = 10):
    return expected_calibration_error(repo, bins=bins)


@app.post("/outcome", dependencies=[Depends(require_api_key)])
async def outcome_endpoint(req: OutcomeRequest):
    return record_outcome(req.repo, pr_number=req.pr_number, outcome=req.outcome, text=req.text, metadata=req.metadata)


@app.post("/generate")
async def generate_endpoint(req: GenerateRequest):
    return generate_request(req)


@app.post("/repair")
async def repair_endpoint(req: RepairRequest):
    return repair_request(req)


@app.post("/verify")
async def verify_endpoint(req: VerifyRequest):
    return verify_candidate(req)


@app.post("/sandbox")
async def sandbox_endpoint(req: SandboxRequest):
    return run_sandbox(req.candidate, req.context)
