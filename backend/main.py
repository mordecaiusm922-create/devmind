"""
main.py -- DevMind SaaS API

Production-grade FastAPI application with:
  - Strict typing
  - Structured JSON logging with trace IDs
  - Layered error taxonomy
  - Timeout isolation around analysis
  - Dependency injection for cross-cutting concerns
  - Clean transport / application / domain separation
  - No unnecessary global mutable state
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
import time
import uuid
from collections import defaultdict
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any

import httpx
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator

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
# 1. STRUCTURED LOGGING
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
# 2. CONFIGURATION
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
# 3. ERROR TAXONOMY
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
# 4. SUPABASE CLIENT
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
# 5. RATE LIMITER
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
# 6. AUTH DEPENDENCY
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
# 7. REQUEST CONTEXT
# =============================================================================

_ctx = threading.local()


def _get_trace_id() -> str:
    return getattr(_ctx, "trace_id", "unknown")

# =============================================================================
# 8. DOMAIN MODELS
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

# =============================================================================
# 9. RESPONSE BUILDER
# =============================================================================


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
            "risk_note": summary.get("risk"),
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
# 10. CORE PIPELINE
# =============================================================================


def _pipeline_sync(repo: str, pr_number: int, trace_id: str) -> dict[str, Any]:
    _ctx.trace_id = trace_id

    def _timed(label: str, fn, *args, **kwargs):
        t0 = time.monotonic()
        result = fn(*args, **kwargs)
        log.info(
            f"pipeline_step step={label} duration_ms={round((time.monotonic()-t0)*1000)}",
            extra={"trace_id": trace_id},
        )
        return result

    pr_data = _timed("fetch_pr", get_pr_data, repo, pr_number)

    summary, pre, ev = _timed("summarize", summarize_pr, pr_data)

    risk = None

    _timed("log_analysis", log_analysis, repo, pr_number, pr_data, summary, pre, ev)

    all_parsed = []
    for f in pr_data.get("files", []):
        fname = f.get("filename", "")
        patch = f.get("raw_patch", "") or f.get("diff", "")
        if not patch or f.get("is_noise"):
            continue
        try:
            parsed = parse_pr_file(fname, patch, None)
            all_parsed.append(parsed)
        except Exception as exc:
            log.warning(
                "parse_file_failed",
                extra={"file": fname, "exc": str(exc), "trace_id": trace_id},
            )

    combined = {"functions_changed": [], "calls": []}
    for p in all_parsed:
        combined["functions_changed"].extend(p.get("functions_changed", []))
        combined["calls"].extend(p.get("calls", []))

    diff_stats = {
        "additions": pr_data.get("additions", 0),
        "deletions": pr_data.get("deletions", 0),
        "changed_files": pr_data.get("changed_files", 0),
    }

    features = _timed("extract_features", extract_features, combined, diff_stats)
    permissions = summary.get("permissions_analysis", {})
vulns = summary.get("vulnerabilities", [])

risk_band = summary.get("risk_note", {}).get("level", "low")
risk_floor = pre.risk_floor

merge_blocker, reason = decide_merge_blocker(
    risk_band=risk_band,
    risk_floor=risk_floor,
    vulnerabilities=vulns,
    permissions=permissions,
)

summary["merge_blocker"] = merge_blocker
summary["merge_block_reason"] = reason

    return _build_response(
        repo=repo,
        pr_number=pr_number,
        pr_data=pr_data,
        summary=summary,
        pre=pre,
        ev=ev,
        risk=risk,
        features=features,
        parsed_fns=combined["functions_changed"],
        trace_id=trace_id,
      
    )

def decide_merge_blocker(
    *,
    risk_band: str,
    risk_floor: str,
    vulnerabilities: list,
    permissions: dict | None,
) -> tuple[bool, str]:
    """
    Returns:
        (merge_blocker, reason)
    """

    # 🔴 HARD BLOCK
    if risk_band in ("critical", "high"):
        return True, "High or critical risk detected"

    # 🔴 Vulnerabilities explícitas
    if vulnerabilities:
        severe = [v for v in vulnerabilities if v.get("severity") in ("high", "critical")]
        if severe:
            return True, "High severity vulnerabilities detected"

    # 🟠 Security-sensitive PR
    if risk_floor == "medium":
        if permissions and not permissions.get("trust_boundary_respected", True):
            return True, "Permissions cross trust boundary"

        if permissions and permissions.get("secrets_accessed_before_validation"):
            return True, "Secrets used before validation"

    # 🟡 Soft signals (NO bloquea, pero importante)
    return False, "No blocking conditions met"

async def _run_analysis(repo: str, pr_number: int, trace_id: str | None = None) -> dict[str, Any]:
    tid = trace_id or str(uuid.uuid4())
    log.info("analysis_start", extra={"repo": repo, "pr": pr_number, "trace_id": tid})

    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(_pipeline_sync, repo, pr_number, tid),
            timeout=CFG.analysis_timeout_s,
        )
    except asyncio.TimeoutError:
        log.error("analysis_timeout", extra={"repo": repo, "pr": pr_number, "trace_id": tid})
        raise _err(
            504,
            ErrorCode.ANALYSIS_TIMEOUT,
            f"Analysis timed out after {CFG.analysis_timeout_s}s.",
            trace_id=tid,
        )
    except HTTPException:
        raise
    except ValueError as exc:
        raise _err(422, ErrorCode.VALIDATION_ERROR, str(exc), trace_id=tid)
    except Exception as exc:
        msg = str(exc)
        if "404" in msg or "Not Found" in msg:
            raise _err(
                404,
                ErrorCode.PR_NOT_FOUND,
                f"PR not found: {repo}#{pr_number}",
                trace_id=tid,
            )
        if any(code in msg for code in ("401", "403")):
            raise _err(
                401,
                ErrorCode.GITHUB_AUTH_FAILURE,
                "GitHub API auth failed. Check GITHUB_TOKEN.",
                trace_id=tid,
            )
        log.error("analysis_error", extra={"exc": msg, "trace_id": tid}, exc_info=True)
        raise _err(400, ErrorCode.UPSTREAM_ERROR, msg, trace_id=tid)

    log.info("analysis_complete", extra={"repo": repo, "pr": pr_number, "trace_id": tid})
    return result

# =============================================================================
# 11. WEBHOOK COMMENT BUILDER
# =============================================================================

_RISK_EMOJI: dict[str, str] = {
    "critical": "RED",
    "high": "ORANGE",
    "medium": "YELLOW",
    "low": "GREEN",
    "minimal": "WHITE",
}

_TRIAGE_LABEL: dict[str, str] = {
    "P0": "P0 - Stop everything",
    "P1": "P1 - Block merge",
    "P2": "P2 - Review carefully",
    "P3": "P3 - Nice to fix",
}


def _build_pr_comment(result: dict[str, Any]) -> str:
    s = result.get("summary", {})
    re_obj = result.get("risk_engine", {})
    level = re_obj.get("band", "low")
    score = re_obj.get("score", 0)
    top_factors = re_obj.get("top_factors", [])
    vulns = s.get("vulnerabilities") or []
    triage = s.get("triage", "P3")
    merge_block = s.get("merge_blocker", False)
    emoji = _RISK_EMOJI.get(level, "WHITE")

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
    triage_md = _TRIAGE_LABEL.get(triage, f"**{triage}**")
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

{triage_md} - Risk Score `{score}/100` - **{level.upper()}**
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
_Analyzed by DevMind trace `{result.get("trace_id", "")}`_"""

# =============================================================================
# 12. APP LIFECYCLE
# =============================================================================


@asynccontextmanager
async def _lifespan(application: FastAPI):
    log.info("startup", extra={"env": CFG.environment, "version": application.version})
    yield
    _supabase.close()
    log.info("shutdown")


app = FastAPI(
    title="DevMind API",
    version="1.2.0",
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
# 13. MIDDLEWARE
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
# 14. ENDPOINTS
# =============================================================================


@app.api_route("/health", methods=["GET", "HEAD"])
async def healthcheck():
    return {"status": "ok", "version": app.version, "env": CFG.environment}


@app.get("/")
async def root():
    return {"service": "DevMind", "status": "ok", "version": app.version}


@app.post("/analyze-pr", dependencies=[Depends(_require_api_key)])
async def analyze_pr(req: AnalysePRRequest, request: Request):
    trace_id = request.headers.get("x-trace-id") or _get_trace_id()
    log.info(
        "analyze_pr_request",
        extra={"repo": req.repo, "pr": req.pr_number, "trace_id": trace_id},
    )
    return await _run_analysis(req.repo, req.pr_number, trace_id=trace_id)


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
# 15. GITHUB WEBHOOK
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
    trace_id = x_github_delivery or str(uuid.uuid4())[:12]

    if not repo or not pr_number or not installation_id:
        raise _err(
            400,
            ErrorCode.INVALID_PAYLOAD,
            "Missing repo, pr number, or installation_id.",
        )

    log.info(
        "webhook_received",
        extra={"action": action, "repo": repo, "pr": pr_number, "trace_id": trace_id},
    )

    async def _analyze_and_comment() -> None:
        try:
            token = get_installation_token(installation_id)
            result = await _run_analysis(repo, pr_number, trace_id=trace_id)
            comment = _build_pr_comment(result)
            post_pr_comment(repo, pr_number, comment, token)

            re_obj = result.get("risk_engine", {})
            level = re_obj.get("band", "low")
            score = re_obj.get("score", 0)
            state = "failure" if level in ("critical", "high") else "success"
            post_commit_status(
                repo,
                commit_sha,
                token,
                state,
                f"Risk {score}/100 - {level.upper()}",
            )
            log.info(
                "webhook_comment_posted",
                extra={"repo": repo, "pr": pr_number, "trace_id": trace_id},
            )
        except Exception as exc:
            log.error(
                "webhook_analysis_failed",
                extra={
                    "repo": repo,
                    "pr": pr_number,
                    "exc": str(exc),
                    "trace_id": trace_id,
                },
                exc_info=True,
            )

    try:
        token_pending = get_installation_token(installation_id)
        post_commit_status(
            repo,
            commit_sha,
            token_pending,
            "pending",
            "DevMind is analyzing this PR...",
        )
    except Exception as exc:
        log.warning("pending_status_failed", extra={"exc": str(exc), "trace_id": trace_id})

    threading.Thread(
        target=lambda: asyncio.run(_analyze_and_comment()),
        daemon=False,
        name=f"devmind-webhook-{trace_id}",
    ).start()

    return {"accepted": True, "repo": repo, "pr": pr_number, "action": action, "trace_id": trace_id}