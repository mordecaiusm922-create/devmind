"""
main.py -- DevMind SaaS API

FastAPI application focused on:
- clean orchestration over the agentic summarizer
- strict typing
- structured JSON logging
- idempotent GitHub webhook handling
- queue-based background processing
- rate limiting
- timeout isolation
- payload limits
- explicit merge-blocker decisions
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
from typing import Annotated, Any, Dict, List, Optional

import httpx
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from agent import AgentConfig, DevMindAgent
from evaluator import enforce_risk_floor, compute_risk_score
from feature_extractor import extract_features
from github import get_pr_data
from github_app import (
    get_installation_token,
    post_commit_status,
    post_pr_comment,
    verify_webhook_signature,
)
from logger import read_recent_logs
from prob_engine import (
    generate_request, repair_request, verify_candidate,
    GenerateRequest, RepairRequest, VerifyRequest,
)
from evaluate import evaluate_payload
from safety_flow import SafetyFlowRequest, run_safety_flow
from sandbox import run_sandbox
from infra_analyzer import analyze_infra, InfraAnalysisResult
from cve_checker import check_cves
from parser import parse_pr_file

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
# 3. CONFIG
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
# 5. TTL STORAGE
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
# 6. SUPABASE KEY LOOKUP
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
        raise _err(
            status.HTTP_401_UNAUTHORIZED,
            ErrorCode.MISSING_API_KEY,
            "Pass X-Api-Key header.",
        )

    valid = x_api_key in CFG.static_api_keys or _supabase.key_exists(x_api_key)
    if not valid:
        raise _err(
            status.HTTP_401_UNAUTHORIZED,
            ErrorCode.INVALID_API_KEY,
            "API key not recognized.",
        )

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
    model_config = ConfigDict(extra="ignore")
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
# 11. AGENT
# =============================================================================

analysis_agent = DevMindAgent(
    config=AgentConfig(
        retry_on_failure=True,
        max_retries=1,
        verbose=False,
    )
)

# =============================================================================
# 12. METRICS
# =============================================================================

METRICS: dict[str, int] = defaultdict(int)


def _metric(name: str, delta: int = 1) -> None:
    METRICS[name] += delta

# =============================================================================
# 13. HELPERS
# =============================================================================


def _build_cache_key(repo: str, pr_number: int) -> str:
    return f"{repo}#{pr_number}"


def _build_job_key(repo: str, pr_number: int, delivery_id: str) -> str:
    return f"{repo}#{pr_number}:{delivery_id}"


def _check_payload_limits(pr_data: dict[str, Any]) -> None:
    files = pr_data.get("files", [])
    diff_chars = sum(len(f.get("diff") or "") for f in files)
    if len(files) > MAX_FILES_PER_PR:
        raise _err(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            ErrorCode.INVALID_PAYLOAD,
            "PR has too many files.",
        )
    if diff_chars > MAX_DIFF_CHARS_PER_PR:
        raise _err(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            ErrorCode.INVALID_PAYLOAD,
            "PR diff is too large.",
        )


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


def _build_pr_comment(result: dict, sf_result: dict | None = None) -> str:
    from policy_engine import policy_decision, detect_surface
    unified_risk = result.get("risk", {})
    unified_decision = result.get("decision", {})
    s = result.get("summary", {})
    score = unified_risk.get("score", 0)
    policy_score = unified_risk.get("policy_score", score)
    level = unified_risk.get("band", "low").upper()
    # Usar policy_decision si existe, sino fallback al pipeline
    policy_action = result.get("policy_decision", "")
    ast_taint = result.get("_ast_taint_detected", False)
    if ast_taint or result.get("infrastructure_security", {}).get("block_merge"):
        action = "BLOCK"
    elif policy_action:
        action = policy_action.upper()
    else:
        action = str(unified_decision.get("action", "REVIEW")).upper()
    infra_block = bool((result.get("infrastructure_security") or {}).get("block_merge", False))
    merge_block = action == "BLOCK" or (bool(s.get("merge_blocker", False)) and action != "APPROVE") or infra_block
    infra = result.get("infrastructure_security", {})
    infra_score = infra.get("score", 0)
    infra_findings = infra.get("findings", [])
    
    # Decision icon
    icons = {"BLOCK": "BLOCK", "REVISE": "REVISE", "APPROVE": "APPROVE", "REVIEW": "REVIEW"}
    icon = icons.get(action, "INFO")
    
    display_score = policy_score if action == "BLOCK" and policy_score > score else score
    if action == "BLOCK" and display_score > score:
        level = _band_for_score(display_score).upper()

    # Merge blocker line
    blocker_line = ""
    if merge_block:
        reason = unified_decision.get("reason", s.get("merge_block_reason", "Risk threshold exceeded"))
        blocker_line = f"\n> **Merge blocked:** {reason}\n"
    
    # Why chain
    why_chain = result.get("why_chain", [])
    why_md = " -> ".join(why_chain) if why_chain else "_not available_"
    
    # Surface
    surface = result.get("surface", "runtime")
    
    # Infra findings
    infra_md = ""
    if infra_findings:
        infra_md = "\n### Infrastructure Findings\n"
        for f in infra_findings[:5]:
            sev = str(f.get("severity","")).upper()
            infra_md += f"- **[{sev}]** `{f.get('rule_id','')}` {f.get('title','')}\n"
            if f.get("fix_hint"):
                infra_md += f"  - Fix: {f.get('fix_hint')}\n"
    
    # Vulnerabilities
    vulns = s.get("vulnerabilities") or []
    vulns_md = "_No vulnerabilities detected_"
    if vulns:
        lines_v = []
        for v in vulns[:3]:
            sev = str(v.get("severity","")).upper()
            loc = v.get("location","-")
            desc = v.get("description","")
            fix = v.get("fix","")
            lines_v.append(f"**[{sev}]** `{loc}`\n{desc}\n**Fix:** {fix}")
        vulns_md = "\n\n".join(lines_v)
    
    # Safety flow section
    sf_md = ""
    if sf_result and sf_result.get("selected"):
        sel = sf_result["selected"]
        dec = sf_result.get("decision", {})
        sf_action = dec.get("action","N/A") if isinstance(dec, dict) else "N/A"
        # Ajustar security score basado en findings criticos (multiplicative risk)
        raw_security = float(sel.get("security", 0) or 0)
        ast_f = result.get("ast_findings", [])
        has_taint = any(f.get("rule_id","").startswith("TAINT") for f in ast_f)
        has_cmd = any(f.get("rule_id") == "TAINT002" for f in ast_f)
        critical_count = sum(1 for f in ast_f if f.get("severity") == "critical")
        calibrated_security = raw_security
        if has_taint: calibrated_security *= 0.15
        if has_cmd: calibrated_security *= 0.2
        if critical_count >= 2: calibrated_security = min(calibrated_security, 0.1)
        calibrated_security = round(calibrated_security, 3)
        sf_md = f"""\n### Repair Candidates\n**Best candidate:** `{sel.get("candidate","N/A")}` | Action: `{sf_action}`\n**Risk-adjusted utility:** `{sel.get("risk_adjusted_utility",0)}` | Security: `{calibrated_security}` *(calibrated)* | Verified: `{sel.get("verified",False)}`\n"""
    
    # CVE findings
    cve_findings = result.get("infrastructure_security", {}).get("cve_findings", [])
    cve_md = ""
    if cve_findings:
        cve_md = "\n### Dependency Vulnerabilities (CVE)\n"
        for c in cve_findings[:5]:
            sev = str(c.get("severity","")).upper()
            pkg = c.get("package","")
            ver = c.get("version","")
            cve_id = c.get("cve_id","")
            desc = c.get("description","")[:80]
            fix = c.get("fix_version","")
            cve_md += f"- **[{sev}]** `{pkg}=={ver}` {cve_id}\n"
            cve_md += f"  {desc}\n"
            if fix:
                cve_md += f"  **Fix:** upgrade to `{fix}`\n"

    # AST findings
    ast_findings = result.get("ast_findings", [])
    ast_md = ""
    if ast_findings:
        ast_md = "\n### Code Analysis (AST)\n"
        for a in ast_findings[:5]:
            sev = str(a.get("severity","")).upper()
            rule = a.get("rule_id","")
            title = a.get("title","")
            evidence = a.get("evidence","")[:60]
            fix = a.get("fix_hint","")[:80]
            ast_md += "- **[" + sev + "]** `" + rule + "` " + title + "\n"
            if evidence:
                ast_md += "  `" + evidence + "`\n"
            if fix:
                ast_md += "  Fix: " + fix + "\n"

    triage = result.get("triage", s.get("triage", "P3"))
    trace = result.get("trace_id", "")[:12]
    
    comment = f"""## {icon} DevMind Analysis

**{triage}** | Risk Score `{display_score}/100` | **{level}** | Surface: `{surface}`
{blocker_line}
### Decision Chain
`{why_md}`

### Risk Breakdown
| Metric | Score |
|--------|-------|
| Risk Score | `{display_score}/100` |
| Decision | `{action}` |
| Infra Score | `{infra_score}/100` |
{infra_md}
### Vulnerabilities
{vulns_md}
{cve_md}
{ast_md}
{sf_md}
---
_Analyzed by DevMind v1.5.0_ | trace `{trace}`
"""
    return comment

def decide_merge_blocker(
    *,
    risk_band: str,
    risk_floor: str,
    vulnerabilities: list,
    permissions: dict | None,
    ci_cd_risks: list,
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

    dangerous_triggers = {"pull_request_target", "workflow_run"}
    for risk in ci_cd_risks:
        trigger = str(risk.get("trigger", "")).lower()
        secrets_exposed = risk.get("secrets_exposed", False)
        severity = str(risk.get("severity", "")).lower()
        if trigger in dangerous_triggers and (secrets_exposed or severity == "high"):
            return True, f"Dangerous CI/CD trigger ({trigger}) with secrets or high severity"

    return False, "No blocking conditions met"


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

    diff_stats = {
        "additions": pr_data.get("additions", 0),
        "deletions": pr_data.get("deletions", 0),
        "changed_files": pr_data.get("changed_files", 0),
    }
    features = extract_features(combined, diff_stats)
    return features, combined["functions_changed"]


# =============================================================================
# 14. PIPELINE
# =============================================================================


infra_score = 0
infra_block_merge = False
infra_results = None

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
        raise _err(
            504,
            ErrorCode.ANALYSIS_TIMEOUT,
            f"Analysis timed out after {CFG.analysis_timeout_s}s.",
            trace_id=trace_id,
        )
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

    infra_score = 0
    infra_block_merge = False
    infra_findings = []

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

    # =============================================================================
    # Infrastructure Security Analysis
    # =============================================================================

    try:
        infra_results = analyze_infra(pr_data.get("files", []))

        infra_findings = [
            {
                "rule_id": f.rule_id,
                "severity": f.severity,
                "surface": f.surface,
                "title": f.title,
                "description": f.description,
                "file": f.file,
                "line": f.line,
                "evidence": f.evidence,
                "cwe": f.cwe,
                "fix_hint": f.fix_hint,
            }
            for f in infra_results.findings
        ]

        infra_score = int(getattr(infra_results, 'risk_score', 0))
        infra_block_merge = bool(getattr(infra_results, 'block_merge', False))

    except Exception as exc:
        log.warning(
            "infra_analysis_failed",
            extra={
                "exc": str(exc),
                "trace_id": trace_id,
            }
        )

        infra_findings = []
        infra_score = 0
        infra_block_merge = False

    # CVE Analysis
    cve_result = None
    cve_findings = []
    try:
        cve_result = check_cves(pr_data.get('files', []))
        cve_findings = [{
            'package': f.package,
            'version': f.version,
            'cve_id': f.cve_id,
            'severity': f.severity,
            'description': f.description,
            'fix_version': f.fix_version,
        } for f in cve_result.findings]
        if cve_result.block_merge:
            infra_block_merge = True
    except Exception as exc:
        log.warning('cve_check_failed', extra={'exc': str(exc)})


    # Surface classification - previene alucinaciones en docs/tests
    try:
        from surface_classifier import classify_change_surface
        _files = pr_data.get("files", []) or []
        _diff_text = " ".join(f.get("patch", "") or "" for f in _files)[:3000]
        _surface_ctx = classify_change_surface(_files, _diff_text)
        pr_data["_surface_ctx"] = {
            "surface": _surface_ctx.surface,
            "risk_multiplier": _surface_ctx.risk_multiplier,
            "disable_fix_generation": _surface_ctx.disable_fix_generation,
            "disable_runtime_security": _surface_ctx.disable_runtime_security,
            "use_lightweight_pipeline": _surface_ctx.use_lightweight_pipeline,
            "negative_signals": _surface_ctx.negative_signals,
        }
    except Exception:
        _surface_ctx = None

    agent_result = _timed("agent_run", analysis_agent.run, pr_data)
    summary = _normalize_summary(agent_result.summary)
    pre = agent_result.pre_analysis
    ev = agent_result.evaluation

    validated_summary = _validate_summary(summary).model_dump()
    if pre is not None:
        validated_summary = enforce_risk_floor(validated_summary, pre)

    permissions = validated_summary.get("permissions_analysis", {}) or {}
    vulns = validated_summary.get("vulnerabilities", []) or []
    ci_cd_risks = validated_summary.get("ci_cd_risks", []) or []
    risk_band = str(validated_summary.get("risk_note", {}).get("level", "low")).lower()
    risk_floor = pre.risk_floor if pre else "medium"

    merge_blocker, reason = decide_merge_blocker(
        risk_band=risk_band,
        risk_floor=risk_floor,
        vulnerabilities=vulns,
        permissions=permissions,
        ci_cd_risks=ci_cd_risks,
    )

    validated_summary["merge_blocker"] = merge_blocker
    validated_summary["merge_block_reason"] = reason

    features, parsed_functions = _build_code_features(pr_data)
    _ev_obj = ev
    if isinstance(ev, dict):
        from evaluator import Evaluation
        _ev_inner = ev.get("evaluation", ev)
        _ev_obj = Evaluation(
            confidence=_ev_inner.get("confidence", "low"),
            confidence_score=_ev_inner.get("confidence_score", 0.0),
            specificity_score=_ev_inner.get("specificity_score", 0.0),
            generic_phrases_found=tuple(_ev_inner.get("generic_phrases_found", [])),
            generic_penalty=_ev_inner.get("generic_penalty", 0),
            is_flagged=_ev_inner.get("is_flagged", False),
            flag_reason=_ev_inner.get("flag_reason", None),
        )
    risk_signals = compute_risk_score(pre, summary, _ev_obj, pr_data) if pre and _ev_obj else None

    # Aplica risk_multiplier del surface classifier
    if risk_signals and _surface_ctx is not None:
        _multiplier = _surface_ctx.risk_multiplier
        if _multiplier < 1.0:
            # risk_signals puede ser objeto - no modificar, solo pasar a _build_response via pr_data
            pr_data["_risk_multiplier"] = _multiplier
            pr_data["_surface"] = _surface_ctx.surface
            pr_data["_negative_signals"] = _surface_ctx.negative_signals

    pr_data["_cve_findings"] = cve_findings
    response = _build_response(
        repo=repo,
        risk_signals=risk_signals,
        pr_number=pr_number,
        pr_data=pr_data,
        summary=validated_summary,
        pre=pre,
        ev=ev,
        trace_id=trace_id,
        features=features,
        parsed_fns=parsed_functions,
    )
    # Aplica surface multiplier al risk final en response
    if _surface_ctx is not None and _surface_ctx.risk_multiplier < 1.0:
        _m = _surface_ctx.risk_multiplier
        if "risk" in response and isinstance(response["risk"], dict):
            _orig = response["risk"].get("score", 0)
            _new_score = _orig if (response.get('_ast_taint_detected') or infra_block_merge or _orig >= 80) else max(0, round(_orig * _m))
            _risk_obj["score"] = _new_score
            _risk_obj["surface"] = _surface_ctx.surface
            _risk_obj["surface_multiplier"] = _m
            _risk_obj["negative_signals"] = _surface_ctx.negative_signals
            if _new_score >= 80: _risk_obj["band"] = "critical"
            elif _new_score >= 60: _risk_obj["band"] = "high"
            elif _new_score >= 40: _risk_obj["band"] = "medium"
            elif _new_score >= 20: _risk_obj["band"] = "low"
            else: _risk_obj["band"] = "minimal"
    safety_flow = _run_pr_safety_flow(repo, pr_number, pr_data, response, trace_id)
    # Inyectar cve_findings en response antes de attach
    if isinstance(response.get("infrastructure_security"), dict):
        response["infrastructure_security"]["cve_findings"] = cve_findings
    # FUERZA infra_score si AST detecto taint - debe ir antes de attach
    if response.get('_ast_taint_detected'):
        infra_score = max(infra_score, 90)
        infra_block_merge = True
        response['_policy_risk_override'] = {'score': 90, 'band': 'critical'}
    _attach_unified_decision_v2(response, safety_flow)
    # Policy engine override - si auto_approve y no hay findings criticos
    try:
        _why = response.get("why_chain", [])
        _pol_dec = response.get("policy_decision", "")
        _pol_risk = response.get("_policy_risk_override", {})
        _ast_taint = response.get("_ast_taint_detected", False)
        _infra_block = any("critical_infra" in w or "infra_score" in w for w in _why)
        _has_critical = bool(response.get("risk", {}).get("score", 0) >= 80 and _infra_block)
        if (
            "auto_approve" in _why
            and _pol_dec == "APPROVE"
            and not _ast_taint
            and not _has_critical
        ):
            response["decision"] = {
                "action": "APPROVE",
                "reason": "Policy engine auto-approved: trivial surface with no security signals.",
                "confidence": 0.9,
                "merge_blocker": False,
                "blocking_findings": [],
            }
            if "risk" in response and isinstance(response["risk"], dict):
                response["risk"]["score"] = _pol_risk.get("score", 5)
                response["risk"]["band"] = _pol_risk.get("band", "minimal")
    except Exception as _oe:
        log.warning("policy_override_failed", extra={"exc": str(_oe)})
    # Aplica surface multiplier DESPUES de attach (evita sobreescritura)
    if _surface_ctx is not None and _surface_ctx.risk_multiplier < 1.0:
        _m = _surface_ctx.risk_multiplier
        _risk_obj = response.get("risk") if isinstance(response, dict) else None
        if _risk_obj is not None and not isinstance(_risk_obj, dict):
            try:
                from dataclasses import asdict
                _risk_obj = asdict(_risk_obj)
                response["risk"] = _risk_obj
            except Exception:
                try:
                    _risk_obj = dict(_risk_obj)
                    response["risk"] = _risk_obj
                except Exception:
                    _risk_obj = None
        if isinstance(_risk_obj, dict):
            _orig = _risk_obj.get("score", 0)
            _new_score = _orig if _orig >= 80 else max(0, round(_orig * _m))
            _risk_obj["score"] = _new_score
            _risk_obj["surface"] = _surface_ctx.surface
            _risk_obj["surface_multiplier"] = _m
            _risk_obj["negative_signals"] = _surface_ctx.negative_signals
            if _new_score >= 80: _risk_obj["band"] = "critical"
            elif _new_score >= 60: _risk_obj["band"] = "high"
            elif _new_score >= 40: _risk_obj["band"] = "medium"
            elif _new_score >= 20: _risk_obj["band"] = "low"
            else: _risk_obj["band"] = "minimal"
    _metric("analysis_done")
    # AST Analysis en pipeline
    try:
        from ast_analyzer import analyze_ast
        _ast_result = analyze_ast(pr_data.get("files", []))
        if _ast_result and _ast_result.block_merge:
            infra_block_merge = True
            infra_score = max(infra_score, _ast_result.risk_score)
        response["ast_findings"] = [{"rule_id": f.rule_id, "severity": f.severity, "title": f.title, "description": f.description, "file": f.file, "line": f.line, "evidence": f.evidence, "fix_hint": f.fix_hint} for f in _ast_result.findings] if _ast_result else []
        if _ast_result and _ast_result.has_taint_flow:
            response["_ast_taint_detected"] = True
    except Exception as _ae:
        log.warning("ast_analysis_failed", extra={"exc": str(_ae)})
        response["ast_findings"] = []
    # Pre-compute policy override ANTES del unified decision
    try:
        from policy_engine import policy_decision as _pd_early
        _files_early = pr_data.get('files', []) or []
        _prompt_early = pr_data.get('title', '') + ' ' + pr_data.get('body', '')
        _intent_early = response.get('intent', {}).get('label', 'general_fix') if isinstance(response.get('intent'), dict) else 'general_fix'
        _ast_taint_early = response.get('_ast_taint_detected', False)
        _pe = _pd_early(prompt=_prompt_early, files=_files_early, mode='secure',
            intent_label=_intent_early, infra_block=infra_block_merge or _ast_taint_early,
            infra_score=max(infra_score, 90) if _ast_taint_early else infra_score, safety_action='')
        response['_policy_risk_override'] = {'score': int(_pe.get('risk_score', 0) or 0), 'band': _pe.get('band', '')}
    except Exception as _pe_early_err:
        import logging as _lg; _lg.getLogger('devmind').warning(f'POLICY_PRECOMPUTE_FAILED: {_pe_early_err}')

    # Policy engine - agrega why_chain y surface al response
    try:
        from policy_engine import policy_decision, detect_surface
        _files = pr_data.get('files', []) or []
        _prompt = pr_data.get('title', '') + ' ' + pr_data.get('body', '')
        _mode = 'secure'
        _intent = response.get('intent', {}).get('label', 'general_fix') if isinstance(response.get('intent'), dict) else 'general_fix'
        _safety_action = ''
        _sf = response.get('safety_flow', {})
        if isinstance(_sf, dict):
            _sd = _sf.get('decision', {})
            _safety_action = _sd.get('action', '').upper() if isinstance(_sd, dict) else ''
        _ast_taint = response.get("_ast_taint_detected", False)
        _policy = policy_decision(
            prompt=_prompt, files=_files, mode=_mode,
            intent_label=_intent, infra_block=infra_block_merge or _ast_taint,
            infra_score=max(infra_score, 90) if _ast_taint else infra_score, safety_action=_safety_action
        )
        response['why_chain'] = _policy.get('why_chain', [])
        response['surface'] = _policy.get('surface', 'runtime')
        response['policy_decision'] = _policy.get('decision', '')
        response['policy_reason'] = _policy.get('reason', '')
        # Guarda policy override para usar en calibrated_score
        _policy_band = _policy.get('band', '')
        _policy_risk = int(_policy.get('risk_score', 0) or 0)
        response['_policy_risk_override'] = {'score': _policy_risk, 'band': _policy_band}
    except Exception as _pe:
        log.warning('policy_engine_failed', extra={'exc': str(_pe)})

    # Guardar decision en Supabase para metricas
    try:
        from metrics import record_decision
        _dec = response.get("decision", {})
        _risk = response.get("risk", {})
        record_decision(
            repo=repo,
            pr_number=pr_number,
            trace_id=trace_id,
            action=str(_dec.get("action", "UNKNOWN")),
            reason=str(_dec.get("reason", "")),
            risk_score=int(_risk.get("score", 0)),
            policy_score=int(_risk.get("policy_score", 0)),
            surface=str(response.get("surface", "runtime")),
            intent=str(response.get("intent", {}).get("label", "")) if isinstance(response.get("intent"), dict) else "",
            blocking_findings=list(_dec.get("blocking_findings", [])),
            ast_findings_count=len(response.get("ast_findings", [])),
            cve_findings_count=len(response.get("infrastructure_security", {}).get("cve_findings", [])),
            infra_findings_count=len(response.get("infrastructure_security", {}).get("findings", [])),
            why_chain=list(_dec.get("why_chain", [])),
        )
    except Exception as _me:
        log.warning("metrics_record_failed", extra={"exc": str(_me)})
    try:
        from metrics import record_decision
        _dec = response.get("decision", {})
        _risk = response.get("risk", {})
        record_decision(
            repo=repo, pr_number=pr_number, trace_id=trace_id,
            action=str(_dec.get("action", "UNKNOWN")),
            reason=str(_dec.get("reason", "")),
            risk_score=int(_risk.get("score", 0)),
            policy_score=int(_risk.get("policy_score", 0)),
            surface=str(response.get("surface", "runtime")),
            intent=str(response.get("intent", {}).get("label", "")) if isinstance(response.get("intent"), dict) else "",
            blocking_findings=list(_dec.get("blocking_findings", [])),
            ast_findings_count=len(response.get("ast_findings", [])),
            cve_findings_count=len(response.get("infrastructure_security", {}).get("cve_findings", [])),
            infra_findings_count=len(response.get("infrastructure_security", {}).get("findings", [])),
            why_chain=list(_dec.get("why_chain", [])),
        )
    except Exception as _me:
        log.warning("metrics_record_failed", extra={"exc": str(_me)})
    try:
        from metrics import record_decision
        _dec = response.get("decision", {})
        _risk = response.get("risk", {})
        record_decision(
            repo=repo, pr_number=pr_number, trace_id=trace_id,
            action=str(_dec.get("action", "UNKNOWN")),
            reason=str(_dec.get("reason", "")),
            risk_score=int(_risk.get("score", 0)),
            policy_score=int(_risk.get("policy_score", 0)),
            surface=str(response.get("surface", "runtime")),
            intent=str(response.get("intent", {}).get("label", "")) if isinstance(response.get("intent"), dict) else "",
            blocking_findings=list(_dec.get("blocking_findings", [])),
            ast_findings_count=len(response.get("ast_findings", [])),
            cve_findings_count=len(response.get("infrastructure_security", {}).get("cve_findings", [])),
            infra_findings_count=len(response.get("infrastructure_security", {}).get("findings", [])),
            why_chain=list(_dec.get("why_chain", [])),
        )
    except Exception as _me:
        log.warning("metrics_record_failed", extra={"exc": str(_me)})
    return response


def _build_response(
    *,
    repo: str,
    risk_signals: Any = None,
    pr_number: int,
    pr_data: dict[str, Any],
    summary: dict[str, Any],
    pre: Any,
    ev: Any,
    trace_id: str,
    features: dict[str, Any],
    parsed_fns: list[Any],
) -> dict[str, Any]:
    evaluation = ev.get("evaluation", {}) if isinstance(ev, dict) else {}

    response: dict[str, Any] = {
        "schema_version": "1.4.0",
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
            "risk_floor": pre.risk_floor if pre else "medium",
            "risk_tags": list(pre.risk_tags) if pre is not None else [],
            "flagged_files": (list(pre.flagged_files) if pre is not None else []),
            "trivially_touched": (list(pre.trivially_touched) if pre is not None else []),
            "files_with_diff": (pre.files_with_diff if pre is not None else 0),
            "files_skipped_budget": (pre.files_skipped_budget if pre is not None else 0),
            "files_skipped_noise": (pre.files_skipped_noise if pre is not None else 0),
            "total_diff_chars": (pre.total_diff_chars if pre is not None else 0),
        },
        "code_features": features,
        "parsed_functions": parsed_fns[:10],
    }

    return response


def _run_pr_safety_flow(
    repo: str,
    pr_number: int,
    pr_data: dict[str, Any],
    response: dict[str, Any],
    trace_id: str,
) -> dict[str, Any] | None:
    req = SafetyFlowRequest(
        prompt=_build_pr_safety_prompt(repo, pr_number, pr_data, response),
        mode="secure",
        repo=repo,
        context={
            "repo": repo,
            "pr_number": pr_number,
            "title": pr_data.get("title", ""),
            "filename": _first_relevant_filename(response, pr_data),
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
        files=_normalize_pr_files_for_safety(pr_data),
        n_candidates=3,
        max_repair_attempts=1,
    )
    try:
        return run_safety_flow(req)
    except Exception as exc:
        log.warning("safety_flow_failed", extra={"exc": str(exc), "trace_id": trace_id})
        return None


def _build_pr_safety_prompt(
    repo: str,
    pr_number: int,
    pr_data: dict[str, Any],
    response: dict[str, Any],
) -> str:
    summary = response.get("summary", {})
    vulns = summary.get("vulnerabilities") or []
    ci_cd = summary.get("ci_cd_risks") or []

    vuln_lines = [
        (
            f"- {v.get('severity', 'unknown')} {v.get('type', 'vulnerability')} "
            f"at {v.get('location', '-')}: {v.get('description', '')}. "
            f"Fix: {v.get('fix', '')}"
        )
        for v in vulns
    ]
    ci_lines = [
        (
            f"- trigger={r.get('trigger', '-')}; severity={r.get('severity', '-')}; "
            f"risk={r.get('risk', '')}; line={r.get('line', '-')}"
        )
        for r in ci_cd
    ]

    return "\n".join(
        [
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
        ]
    )


def _normalize_pr_files_for_safety(pr_data: dict[str, Any]) -> list[dict[str, Any]]:
    files = []
    for f in pr_data.get("files", []) or []:
        filename = str(f.get("filename") or "")
        if not filename:
            continue
        files.append(
            {
                "filename": filename,
                "diff": str(f.get("diff") or f.get("patch") or f.get("raw_patch") or ""),
                "raw_patch": str(f.get("raw_patch") or f.get("diff") or ""),
                "status": str(f.get("status") or "modified"),
                "additions": int(f.get("additions") or 0),
                "deletions": int(f.get("deletions") or 0),
            }
        )
    return files


def _first_relevant_filename(response: dict[str, Any], pr_data: dict[str, Any]) -> str:
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


def _attach_unified_decision_v2(response: dict[str, Any], safety_flow: dict[str, Any] | None) -> None:
    unified = _build_unified_decision_v2(response, safety_flow)
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


def _build_unified_decision_v2(
    response: dict[str, Any],
    safety_flow: dict[str, Any] | None,
) -> dict[str, Any]:
    summary = response.get("summary", {})
    risk_engine = response.get("risk_engine", {})
    vulns = summary.get("vulnerabilities") or []
    ci_cd_risks = summary.get("ci_cd_risks") or []
    legacy_score = _as_int(risk_engine.get("score"), 0)
    legacy_probability = _as_float((risk_engine.get("breakdown") or {}).get("probability"), 0.0)

    selected = (safety_flow or {}).get("selected") or {}
    sf_decision = (safety_flow or {}).get("decision") or {}
    sf_risk = (safety_flow or {}).get("risk") or {}
    sf_score = max(_safety_flow_risk_score(selected, sf_decision), _as_int(sf_risk.get("score"), 0))
    severity_floor, severity_reason = _finding_severity_floor(vulns, ci_cd_risks, summary)
    _policy_risk_override = int((response.get('_policy_risk_override') or {}).get('score', 0) or 0)
    infra_security = response.get("infrastructure_security", {}) or {}
    cve_findings = infra_security.get("cve_findings", []) or []
    ast_taint_detected = bool(response.get("_ast_taint_detected", False))
    cve_block_merge = any(
        str(f.get("severity", "")).lower() == "critical"
        for f in cve_findings
        if isinstance(f, dict)
    )
    calibrated_score = max(
        legacy_score,
        sf_score,
        severity_floor,
        infra_score,
        _policy_risk_override,
    )

    verified = bool(selected.get("verified", False))
    has_findings = bool(vulns or ci_cd_risks)
    if verified and not has_findings and sf_decision.get("action") == "approve":
        calibrated_score = max(0, calibrated_score - 8)

    # Policy engine override - prioridad sobre calibrated_score
    _pr_override = int((response.get('_policy_risk_override') or {}).get('score', 0) or 0)
    if _pr_override > calibrated_score:
        calibrated_score = _pr_override
    # Surface classifier - reduce false positives para docs/changelog
    try:
        from surface_classifier import classify_change_surface
        _raw_files = response.get("files", []) or (response.get("pre_analysis") or {}).get("trivially_touched", []) or []
        _files = [
            f if isinstance(f, dict) else {"filename": str(f)}
            for f in _raw_files
        ]
        _surf = classify_change_surface(files=_files, diff="") if _files else None
        if (
            _surf is not None
            and _surf.risk_multiplier <= 0.30
            and not ast_taint_detected
            and not cve_block_merge
            and not infra_block_merge
            and _policy_risk_override < 80
        ):
            calibrated_score = int(calibrated_score * _surf.risk_multiplier)
    except Exception:
        pass

    risk_note = summary.get("risk_note") or {}
    risk_note_level = str(
        risk_note.get("level", "") if isinstance(risk_note, dict) else risk_note
    ).lower()
    pre_analysis = response.get("pre_analysis") or {}
    risk_floor = str(
        pre_analysis.get("risk_floor", "") if isinstance(pre_analysis, dict) else ""
    ).lower()
    policy_decision = str(response.get("policy_decision") or "").upper()
    if (
        risk_note_level == "low"
        and risk_floor == "low"
        and not vulns
        and not ci_cd_risks
        and not ast_taint_detected
        and not cve_block_merge
        and not infra_block_merge
        and policy_decision not in {"BLOCK", "REVISE"}
        and _policy_risk_override < 55
    ):
        calibrated_score = min(calibrated_score, 40)

    calibrated_score = max(0, min(100, calibrated_score))
    from decision_resolver import resolve_decision
    _resolved = resolve_decision(
        calibrated_score=calibrated_score,
        legacy_merge_blocker=bool(summary.get("merge_blocker", False)) or infra_block_merge,
        severity_floor=severity_floor,
        severity_reason=severity_reason,
        safety_decision=str(sf_decision.get("action") or ""),
        selected=selected,
        has_findings=has_findings,
        ast_taint_detected=ast_taint_detected,
        ast_findings=response.get("ast_findings", []),
        cve_block_merge=cve_block_merge,
        cve_findings=cve_findings,
        infra_block_merge=infra_block_merge,
        infra_score=infra_score,
        infra_findings=infra_security.get("findings", []),
        policy_decision=response.get("policy_decision", ""),
        policy_reason=response.get("policy_reason", ""),
        policy_why_chain=response.get("why_chain", []),
        pr_files=list((response.get("pre_analysis") or {}).get("flagged_files", [])) or [],
    )
    action = _resolved.action
    reason = _resolved.reason
    triage = _triage_for_unified_decision(action, calibrated_score, severity_floor)
    confidence = _unified_confidence(response, safety_flow, calibrated_score)
    p_exploit = _calibrated_exploit_probability(
        legacy_probability=legacy_probability,
        calibrated_score=calibrated_score,
        selected=selected,
        vulns=vulns,
        ci_cd_risks=ci_cd_risks,
        safety_flow_risk=sf_risk,
    )

    return {
        "decision": {
            "action": action,
            "confidence": confidence,
            "reason": reason,
            "merge_blocker": action == "BLOCK" or bool(summary.get("merge_blocker", False)),
            "blocking_findings": _resolved.blocking_findings,
            "why_chain": _resolved.why_chain,
        },
        "risk": {
            "score": calibrated_score,
            "policy_score": _resolved.policy_score,
            "band": _band_for_score(calibrated_score),
            "p_exploit": p_exploit,
            "source_scores": {
                "analyze_pr": legacy_score,
                "safety_flow": sf_score,
                "finding_floor": severity_floor,
            },
            "calibration": "max(analyze_pr, safety_flow_expected_loss, severity_floor)",
            "safety_flow_calibration": sf_risk.get("calibration", {}),
        },
        "infrastructure_security": {
            "score": infra_score,
            "block_merge": infra_block_merge,
            "findings": response.get("infrastructure_security", {}).get("findings", []),
            "cve_findings": response.get("infrastructure_security", {}).get("cve_findings", []),
        },
        "fix_candidates": _extract_fix_candidates(safety_flow),
        "triage": triage,
        "safety_flow": _compact_safety_flow(safety_flow),
    }


def _safety_flow_risk_score(selected: dict[str, Any], decision: dict[str, Any]) -> int:
    if not selected:
        return 0

    expected_loss = _as_float(selected.get("expected_loss"), None)
    if expected_loss is None:
        expected_loss = 1.0 - _as_float(selected.get("risk_adjusted_utility"), 0.0)

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


def _finding_severity_floor(
    vulns: list[dict[str, Any]],
    ci_cd_risks: list[dict[str, Any]],
    summary: dict[str, Any],
) -> tuple[int, str]:
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


def _unified_action(
    *,
    calibrated_score: int,
    legacy_merge_blocker: bool,
    severity_floor: int,
    severity_reason: str,
    safety_decision: str,
    selected: dict[str, Any],
    has_findings: bool,
) -> tuple[str, str]:
    if selected.get("critical_violations"):
        return "BLOCK", "Safety-flow found critical verification violations."

    if safety_decision == "reject":
        return "BLOCK", "Safety-flow rejected the best candidate."

    if legacy_merge_blocker or severity_floor >= 80 or calibrated_score >= 85:
        return "BLOCK", severity_reason

    if safety_decision in {"revise", "needs_verification"}:
        return "REVIEW", "Safety-flow requires verification before this change can be trusted."

    if selected.get("violations"):
        return "REVIEW", "Safety-flow found unresolved verification violations."

    if has_findings or calibrated_score >= 40:
        return "REVIEW", "Security findings or calibrated risk require review."

    return "ALLOW", "No blocking findings and the selected candidate passed verification."


def _triage_for_unified_decision(action: str, score: int, severity_floor: int) -> str:
    if action == "BLOCK":
        return "P0" if score >= 85 or severity_floor >= 86 else "P1"
    if action == "REVIEW":
        if score >= 70:
            return "P1"
        if score >= 40:
            return "P2"
        return "P3"
    return "P3"


def _unified_confidence(
    response: dict[str, Any],
    safety_flow: dict[str, Any] | None,
    calibrated_score: int,
) -> float:
    evaluation = response.get("evaluation", {})
    selected = (safety_flow or {}).get("selected") or {}
    operational = (safety_flow or {}).get("operational_metrics") or {}
    base = 0.50
    base += 0.20 * _as_float(evaluation.get("confidence_score"), 0.0)
    base += 0.15 * _as_float(selected.get("verification_score"), 0.0)
    base += 0.10 * _as_float(operational.get("verification_pass_rate"), 0.0)
    base += 0.10 * abs((calibrated_score / 100.0) - 0.5) * 2
    base -= 0.12 * _as_float(selected.get("uncertainty"), 0.0)
    return round(max(0.0, min(0.99, base)), 4)


def _calibrated_exploit_probability(
    *,
    legacy_probability: float,
    calibrated_score: int,
    selected: dict[str, Any],
    vulns: list[dict[str, Any]],
    ci_cd_risks: list[dict[str, Any]],
    safety_flow_risk: dict[str, Any] | None = None,
) -> float:
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

    model_prior = 1.0 - _as_float(selected.get("security"), 0.5)
    score_prior = calibrated_score / 100.0
    safety_prior = _as_float((safety_flow_risk or {}).get("p_exploit"), 0.0)
    p = max(legacy_probability, finding_prior, model_prior, score_prior * 0.85, safety_prior)
    return round(max(0.0, min(0.99, p)), 4)


def _extract_fix_candidates(safety_flow: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not safety_flow:
        return []

    candidates = {str(c.get("id")): c for c in safety_flow.get("candidates", [])}
    out = []
    for item in safety_flow.get("ranking", [])[:5]:
        cid = str(item.get("candidate"))
        candidate = candidates.get(cid, {})
        out.append(
            {
                "id": cid,
                "strategy": item.get("strategy") or candidate.get("strategy"),
                "verified": bool(item.get("verified", False)),
                "risk_adjusted_utility": item.get("risk_adjusted_utility"),
                "expected_loss": item.get("expected_loss"),
                "security": item.get("security"),
                "uncertainty": item.get("uncertainty"),
                "violations": item.get("violations", []),
                "critical_violations": item.get("critical_violations", []),
                "explanation": candidate.get("explanation", ""),
                "diff": candidate.get("diff", ""),
            }
        )
    return out


def _compact_safety_flow(safety_flow: dict[str, Any] | None) -> dict[str, Any]:
    if not safety_flow:
        return {
            "available": False,
            "decision": {"action": "unavailable"},
            "selected": None,
            "ranking": [],
        }

    return {
        "available": True,
        "flow": safety_flow.get("flow", []),
        "decision": safety_flow.get("decision", {}),
        "deployment_policy": safety_flow.get("deployment_policy", {}),
        "selected": safety_flow.get("selected"),
        "ranking": safety_flow.get("ranking", [])[:5],
        "risk": safety_flow.get("risk", {}),
        "properties": safety_flow.get("properties", []),
        "representation": safety_flow.get("representation", {}),
        "runtime_evidence": safety_flow.get("runtime_evidence", {}),
        "operational_metrics": safety_flow.get("operational_metrics", {}),
        "prior": safety_flow.get("prior", {}),
    }


def _band_for_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "minimal"


def _as_float(value: Any, default: float | None = 0.0) -> float | None:
    try:
        if value is None:
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(round(float(value)))
    except (TypeError, ValueError):
        return default


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

async def _job_worker() -> None:
    assert job_queue is not None
    while True:
        job = await job_queue.get()
        try:
            token = get_installation_token(job.installation_id)
            result = await _run_pipeline(job.repo, job.pr_number, trace_id=job.trace_id)
            sf_result = result.get("safety_flow")
            if sf_result and sf_result.get("selected"):
                try:
                    from memory import record_strategy_result
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
            state = "failure" if action == "BLOCK" else _score_to_merge_state(level)
            post_commit_status(
                job.repo,
                job.commit_sha,
                token,
                state,
                f"{action or 'RISK'} {score}/100 - {level.upper()}",
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
# 16. APP LIFECYCLE
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
    version="1.4.0",
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
# 17. MIDDLEWARE / ERROR HANDLERS


@app.post("/review", dependencies=[Depends(_require_api_key)])
async def review_endpoint(payload: dict):
    from infra_analyzer import analyze_infra
    from policy_engine import policy_decision
    files = list(payload.get("files", []) or [])
    prompt = str(payload.get("prompt", ""))
    mode = str(payload.get("mode", "secure"))
    infra = analyze_infra(files) if files else None
    infra_score = infra.risk_score if infra else 0
    infra_block = infra.block_merge if infra else False
    infra_findings = [{"rule_id": f.rule_id, "severity": f.severity, "title": f.title, "surface": f.surface, "fix_hint": f.fix_hint} for f in infra.findings] if infra else []
    from cve_checker import check_cves
    cve_result = check_cves(files) if files else None
    cve_findings = [{"package": f.package, "version": f.version, "cve_id": f.cve_id, "severity": f.severity, "description": f.description, "fix_version": f.fix_version} for f in cve_result.findings] if cve_result else []
    if cve_result and cve_result.block_merge:
        infra_block = True
        infra_score = max(infra_score, 70)
    from ast_analyzer import analyze_ast
    ast_result = analyze_ast(files) if files else None
    ast_findings = [{"rule_id": f.rule_id, "severity": f.severity, "title": f.title, "description": f.description, "file": f.file, "line": f.line, "evidence": f.evidence, "fix_hint": f.fix_hint} for f in ast_result.findings] if ast_result else []
    if ast_result and ast_result.block_merge:
        infra_block = True
        infra_score = max(infra_score, ast_result.risk_score)
    intent_label = "general_fix"
    intent_confidence = 0.0
    safety_action = ""
    try:
        import httpx
        async with httpx.AsyncClient(timeout=30) as client:
            sf = await client.post("https://devmind-2cej.onrender.com/safety-flow",
                json={"prompt": prompt, "mode": mode, "files": files},
                headers={"Content-Type": "application/json", "X-Api-Key": payload.get("_api_key", "")})
            if sf.status_code == 200:
                sd = sf.json()
                intent_label = sd.get("representation", {}).get("intent", {}).get("label", "general_fix")
                intent_confidence = sd.get("representation", {}).get("intent", {}).get("confidence", 0.0)
                dec = sd.get("decision", {})
                safety_action = dec.get("action", "").upper() if isinstance(dec, dict) else ""
    except Exception:
        pass
    policy = policy_decision(prompt=prompt, files=files, mode=mode,
        intent_label=intent_label, infra_block=infra_block,
        infra_score=infra_score, safety_action=safety_action)
    return {
        "decision": policy["decision"],
        "reason": policy["reason"],
        "surface": policy["surface"],
        "intent": {"label": intent_label, "confidence": intent_confidence},
        "infrastructure_security": {"score": infra_score, "block_merge": infra_block, "findings": infra_findings},
        "merge_blocker": policy["decision"] == "BLOCK",
        "why_chain": policy.get("why_chain", []),
        "cve_findings": cve_findings,
        "ast_findings": ast_findings,
    }

@app.post("/sandbox", dependencies=[Depends(_require_api_key)])
async def sandbox_endpoint(payload: dict):
    from sandbox import sandbox_candidate
    code = (
        payload.get("code")
        or payload.get("candidate")
        or payload.get("diff")
        or ""
    )
    repo = payload.get("repo_path") or payload.get("repo")
    return sandbox_candidate(code=code, repo_path=repo)

@app.post("/run", dependencies=[Depends(_require_api_key)])
async def run_pipeline_endpoint(payload: dict):
    from pipeline import run_pipeline_from_json
    return await run_pipeline_from_json(payload)
# =============================================================================


@app.middleware("http")
async def _observability(request: Request, call_next):
    trace_id = request.headers.get("x-trace-id") or str(uuid.uuid4())[:12]
    _ctx.trace_id = trace_id

    infra_score = 0
    infra_block_merge = False
    infra_findings = []
    t0 = time.monotonic()

    response = await call_next(request)
    if not hasattr(response, "get"):
        return response

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
    # Guardar decision en Supabase para metricas
    try:
        from metrics import record_decision
        _dec = response.get("decision", {})
        _risk = response.get("risk", {})
        record_decision(
            repo=repo,
            pr_number=pr_number,
            trace_id=trace_id,
            action=str(_dec.get("action", "UNKNOWN")),
            reason=str(_dec.get("reason", "")),
            risk_score=int(_risk.get("score", 0)),
            policy_score=int(_risk.get("policy_score", 0)),
            surface=str(response.get("surface", "runtime")),
            intent=str(response.get("intent", {}).get("label", "")) if isinstance(response.get("intent"), dict) else "",
            blocking_findings=list(_dec.get("blocking_findings", [])),
            ast_findings_count=len(response.get("ast_findings", [])),
            cve_findings_count=len(response.get("infrastructure_security", {}).get("cve_findings", [])),
            infra_findings_count=len(response.get("infrastructure_security", {}).get("findings", [])),
            why_chain=list(_dec.get("why_chain", [])),
        )
    except Exception as _me:
        log.warning("metrics_record_failed", extra={"exc": str(_me)})

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
# 18. ENDPOINTS
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
# 19. GITHUB WEBHOOK
# =============================================================================

_HANDLED_ACTIONS = frozenset({"opened", "synchronize", "reopened"})


def _handle_push_event(push_data: dict, installation_id: int, trace_id: str) -> None:
    repo = push_data.get('repo', '')
    commit_sha = push_data.get('commit_sha', '')
    files = push_data.get('files', [])
    pusher = push_data.get('pusher', 'unknown')
    messages = push_data.get('commit_messages', [])
    prompt = f'Direct push to main by {pusher}: {chr(44).join(messages[:3])}'
    log.info('push_analysis_start', extra={'repo': repo, 'sha': commit_sha, 'trace_id': trace_id})
    try:
        token = get_installation_token(installation_id)
        enriched_files = []
        for f in files[:10]:
            fname = f.get("filename", "")
            try:
                file_resp = httpx.get(
                    f"https://api.github.com/repos/{repo}/contents/{fname}",
                    headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3+json"},
                    params={"ref": commit_sha}, timeout=5,
                )
                if file_resp.status_code == 200:
                    import base64
                    fc = base64.b64decode(file_resp.json().get("content", "")).decode("utf-8", errors="ignore")
                    enriched_files.append({**f, "content": fc[:3000]})
                else:
                    enriched_files.append(f)
            except Exception:
                enriched_files.append(f)
        infra_block = False
        infra_score = 0
        ast_findings = []
        try:
            from ast_analyzer import analyze_ast
            _ast = analyze_ast(enriched_files)
            if _ast and _ast.block_merge:
                infra_block = True
                infra_score = max(infra_score, _ast.risk_score)
            ast_findings = [{"rule_id": f.rule_id, "severity": f.severity} for f in _ast.findings] if _ast else []
        except Exception as _ae:
            log.warning("push_ast_failed", extra={"exc": str(_ae), "trace_id": trace_id})
        try:
            from cve_checker import check_cves
            _cve = check_cves(enriched_files)
            if _cve and (getattr(_cve, "block_merge", False) or (isinstance(_cve, dict) and _cve.get("block_merge"))):
                infra_block = True
                infra_score = max(infra_score, 90)
        except Exception as _ce:
            log.warning("push_cve_failed", extra={"exc": str(_ce), "trace_id": trace_id})
        from policy_engine import policy_decision
        _policy = policy_decision(prompt=prompt, files=enriched_files, mode="secure",
            intent_label="general_fix", infra_block=infra_block, infra_score=infra_score, safety_action="")
        action = _policy.get("decision", "REVIEW")
        risk_score = int(_policy.get("risk_score", 50) or 50)
        if infra_block:
            action = "BLOCK"
            risk_score = max(risk_score, 90)
        status = "success" if action == "APPROVE" else "failure"
        description = f"DevMind: {action} | Risk {risk_score}/100"
        post_commit_status(repo, commit_sha, token, status, description)
        log.info("push_analysis_done", extra={"repo": repo, "action": action, "risk": risk_score, "ast": len(ast_findings), "trace_id": trace_id})
    except Exception as exc:
        log.warning("push_analysis_failed", extra={"exc": str(exc), "trace_id": trace_id})

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

    if x_github_event == 'push':
        try:
            payload: dict[str, Any] = json.loads(body)
        except json.JSONDecodeError:
            raise _err(400, ErrorCode.INVALID_PAYLOAD, 'Body is not valid JSON.')
        ref = payload.get('ref', '')
        if ref not in ('refs/heads/main', 'refs/heads/master'):
            return {'accepted': False, 'reason': f'push to {ref} ignored'}
        repo = payload.get('repository', {}).get('full_name', '')
        commits = payload.get('commits', [])
        pusher = payload.get('pusher', {}).get('name', 'unknown')
        installation_id = payload.get('installation', {}).get('id')
        if not repo or not commits or not installation_id:
            return {'accepted': False, 'reason': 'missing repo, commits or installation_id'}
        delivery_id = x_github_delivery or str(uuid.uuid4())
        trace_id = delivery_id[:12]
        if processed_deliveries.contains(delivery_id):
            return {'accepted': True, 'deduped': True, 'trace_id': trace_id}
        processed_deliveries.add(delivery_id)
        log.info('push_webhook_received', extra={'repo': repo, 'ref': ref, 'commits': len(commits), 'pusher': pusher, 'trace_id': trace_id})
        commit_sha = commits[-1].get('id', '') if commits else ''
        added_files = [f for c in commits for f in c.get('added', [])]
        modified_files = [f for c in commits for f in c.get('modified', [])]
        removed_files = [f for c in commits for f in c.get('removed', [])]
        all_files = list(set(added_files + modified_files))
        push_data = {
            'repo': repo,
            'ref': ref,
            'commit_sha': commit_sha,
            'pusher': pusher,
            'files': [{'filename': f} for f in all_files],
            'added': added_files,
            'modified': modified_files,
            'removed': removed_files,
            'commit_messages': [c.get('message', '') for c in commits],
        }
        if job_queue is None:
            return {'accepted': False, 'reason': 'queue_not_initialized'}
        import threading; threading.Thread(target=_handle_push_event, args=(push_data, installation_id, trace_id), daemon=True).start()
        return {'accepted': True, 'trace_id': trace_id, 'event': 'push', 'files': len(all_files)}
    if x_github_event != 'pull_request':
        return {'accepted': False, 'reason': f'event {x_github_event!r} not handled'}
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


class EvaluateRequest(BaseModel):
    prompt: str
    candidates: List[Dict[str, Any]] = []
    context: Dict[str, Any] = {}
    mode: str = "balanced"
    intent: Dict[str, Any] = {}
    evidence: Dict[str, Any] = {}
    history: List[Dict[str, Any]] = []
    files: List[Dict[str, Any]] = []
    repo: Optional[str] = None


class SandboxRequest(BaseModel):
    candidate: Dict[str, Any]
    context: Dict[str, Any] = Field(default_factory=dict)


class OutcomeRequest(BaseModel):
    repo: str
    pr_number: int = 0
    outcome: str
    text: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)


@app.post("/evaluate")
async def evaluate_endpoint(req: EvaluateRequest):
    return evaluate_payload(req.model_dump())

@app.post("/safety-flow", dependencies=[Depends(_require_api_key)])
async def safety_flow_endpoint(req: SafetyFlowRequest):
    return run_safety_flow(req)

@app.get("/memory", dependencies=[Depends(_require_api_key)])
async def memory_endpoint(repo: str, recent: int = 10):
    from memory import summarize_repo_memory

    summary = summarize_repo_memory(repo)
    limit = max(0, recent)
    summary["recent_events"] = summary.get("recent_events", [])[-limit:] if limit else []
    return summary

@app.get("/memory/prior", dependencies=[Depends(_require_api_key)])
async def memory_prior_endpoint(repo: str, prompt: str):
    from memory import get_prior_for_prompt

    return get_prior_for_prompt(repo, prompt)

@app.get("/calibration/ece", dependencies=[Depends(_require_api_key)])
async def calibration_ece_endpoint(repo: str, bins: int = 10):
    from calibration import expected_calibration_error

    return expected_calibration_error(repo, bins=bins)

@app.post("/outcome", dependencies=[Depends(_require_api_key)])
async def outcome_endpoint(req: OutcomeRequest):
    from memory import record_outcome

    return record_outcome(
        req.repo,
        pr_number=req.pr_number,
        outcome=req.outcome,
        text=req.text,
        metadata=req.metadata,
    )

@app.post("/generate")
async def generate_endpoint(req: GenerateRequest):
    return generate_request(req)

@app.post("/repair")
async def repair_endpoint(req: RepairRequest):
    return repair_request(req)

@app.post("/verify")
async def verify_endpoint(req: VerifyRequest):
    return verify_candidate(req)


from infra_analyzer import analyze_infra













