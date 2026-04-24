"""
main.py — DevMind SaaS API
FastAPI application. Wraps the core pipeline (github.py, summarizer.py,
evaluator.py) with auth, rate limiting, structured logging, and a GitHub
webhook handler.
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Annotated

from dotenv import load_dotenv
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator

from github import get_pr_data
from parser import parse_pr_file
from feature_extractor import extract_features
from logger import log_analysis, read_recent_logs
from summarizer import summarize_pr
from evaluator import compute_risk_score

load_dotenv()

# ── Structured logger ──────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}',
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("devmind")

# ── Config ────────────────────────────────────────────────────────────────────
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "http://localhost:5173")
WEBHOOK_SECRET  = os.getenv("GITHUB_WEBHOOK_SECRET", "")
# API keys: static fallback + Supabase lookup
_RAW_KEYS       = os.getenv("API_KEYS", "dev-key-insecure")
VALID_API_KEYS  = set(k.strip() for k in _RAW_KEYS.split(",") if k.strip())
SUPABASE_URL    = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY    = os.getenv("SUPABASE_SERVICE_KEY", "")

def _lookup_api_key_in_supabase(api_key: str) -> bool:
    if not SUPABASE_URL or not SUPABASE_KEY:
        return False
    try:
        import httpx
        resp = httpx.get(
            f"{SUPABASE_URL}/rest/v1/users",
            params={"api_key": f"eq.{api_key}", "select": "api_key", "limit": "1"},
            headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}"},
            timeout=3.0,
        )
        return resp.status_code == 200 and len(resp.json()) > 0
    except Exception:
        return False

# Rate limit: requests per window per API key
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "20"))
RATE_LIMIT_WINDOW_S = int(os.getenv("RATE_LIMIT_WINDOW_S", "60"))

ANALYSIS_TIMEOUT_S  = int(os.getenv("ANALYSIS_TIMEOUT_S", "120"))

# ── In-memory sliding-window rate limiter ─────────────────────────────────────
# Good enough for MVP; swap for Redis when you have multiple workers.
_rate_store: dict[str, list[float]] = defaultdict(list)


def _check_rate_limit(api_key: str) -> None:
    now    = time.time()
    window = _rate_store[api_key]
    # Drop timestamps outside the window
    _rate_store[api_key] = [t for t in window if now - t < RATE_LIMIT_WINDOW_S]
    if len(_rate_store[api_key]) >= RATE_LIMIT_REQUESTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded: {RATE_LIMIT_REQUESTS} requests / {RATE_LIMIT_WINDOW_S}s",
        )
    _rate_store[api_key].append(now)


# ── API key dependency ─────────────────────────────────────────────────────────
def _require_api_key(x_api_key: Annotated[str | None, Header()] = None) -> str:
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid API key. Pass X-Api-Key header.",
        )
    # Accept static keys OR keys registered in Supabase
    if x_api_key not in VALID_API_KEYS and not _lookup_api_key_in_supabase(x_api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid API key. Pass X-Api-Key header.",
        )
    _check_rate_limit(x_api_key)
    return x_api_key


# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="DevMind API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN, "http://localhost:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# ── Request logging middleware ─────────────────────────────────────────────────
@app.middleware("http")
async def _log_requests(request: Request, call_next):
    req_id = str(uuid.uuid4())[:8]
    t0     = time.time()
    response = await call_next(request)
    elapsed  = round((time.time() - t0) * 1000)
    log.info(
        f"req_id={req_id} method={request.method} path={request.url.path} "
        f"status={response.status_code} elapsed_ms={elapsed}"
    )
    response.headers["X-Request-Id"] = req_id
    return response


# ── Global exception handler ───────────────────────────────────────────────────
@app.exception_handler(Exception)
async def _unhandled(request: Request, exc: Exception):
    log.error(f"Unhandled exception on {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": str(exc)},
    )


# ── Models ────────────────────────────────────────────────────────────────────
class AnalysePRRequest(BaseModel):
    repo:      str
    pr_number: int

    @field_validator("repo")
    @classmethod
    def _validate_repo(cls, v: str) -> str:
        if "/" not in v or len(v.split("/")) != 2:
            raise ValueError("repo must be 'owner/repo'")
        return v.strip()

    @field_validator("pr_number")
    @classmethod
    def _validate_pr(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("pr_number must be positive")
        return v


# ── Core pipeline runner ───────────────────────────────────────────────────────
async def _run_analysis(repo: str, pr_number: int) -> dict:
    """
    Runs the full pipeline in a thread (summarize_pr is synchronous/blocking).
    Enforces a hard timeout so a stalled Anthropic call never hangs the server.
    """
    def _pipeline():
        pr_data              = get_pr_data(repo, pr_number)
        summary, pre, ev     = summarize_pr(pr_data)
        risk                 = compute_risk_score(pre, summary, ev, pr_data)
        log_analysis(repo, pr_number, pr_data, summary, pre, ev)
        # Tree-sitter
        all_parsed = []
        import logging
        logging.warning(f"PIPELINE: total_files={len(pr_data.get(chr(39)files chr(39), []))}")
        for f in pr_data.get("files", []):
            fname = f.get("filename", "")
            patch = f.get("raw_patch", "")
            logging.warning(f"FILE: {fname} patch_len={len(patch)} is_noise={f.get(chr(39)is_noise chr(39))}")
            if not patch or f.get("is_noise"):
                continue
            parsed = parse_pr_file(fname, patch, None)
            all_parsed.append(parsed)
        combined = {"functions_changed": [], "calls": []}
        for p in all_parsed:
            combined["functions_changed"].extend(p.get("functions_changed", []))
            combined["calls"].extend(p.get("calls", []))
        diff_stats = {"additions": pr_data.get("additions", 0), "deletions": pr_data.get("deletions", 0), "changed_files": pr_data.get("changed_files", 0)}
        features = extract_features(combined, diff_stats)
        response = _build_response(repo, pr_number, pr_data, summary, pre, ev, risk)
        response['code_features'] = features
        response['parsed_functions'] = combined['functions_changed'][:10]
        return response

    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_pipeline),
            timeout=ANALYSIS_TIMEOUT_S,
        )
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=504,
            detail=f"Analysis timed out after {ANALYSIS_TIMEOUT_S}s. "
                   "The PR may be too large or the AI service is slow.",
        )
    except ValueError as e:
        # Raised by _call_claude when response is truncated
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        msg = str(e)
        if "404" in msg or "Not Found" in msg:
            raise HTTPException(status_code=404, detail=f"PR not found: {repo}#{pr_number}")
        if "401" in msg or "403" in msg:
            raise HTTPException(status_code=401, detail="GitHub API auth failed. Check GITHUB_TOKEN.")
        raise HTTPException(status_code=400, detail=msg)


def _build_response(repo, pr_number, pr_data, summary, pre, ev, risk=None) -> dict:
    response = {
        "pr_number":     pr_number,
        "repo":          repo,
        "title":         pr_data["title"],
        "author":        pr_data["author"],
        "changed_files": pr_data["changed_files"],
        "additions":     pr_data["additions"],
        "deletions":     pr_data["deletions"],
        "is_large_pr":   pr_data.get("is_large_pr", False),
        "summary": {
            "what":                  summary.get("what"),
            "why":                   summary.get("why"),
            "impact":                summary.get("impact"),
            "risk":                  summary.get("risk"),
            "key_changes":           summary.get("key_changes", []),
            "review_focus":          summary.get("review_focus"),
            "analysed_in_chunks":    summary.get("analysed_in_chunks"),
            "hallucination_warning": summary.get("hallucination_warning"),
            "vulnerabilities":       summary.get("vulnerabilities", []),
        },
        "evaluation": {
            "confidence":            ev.confidence,
            "confidence_score":      round(ev.confidence_score, 3),
            "specificity_score":     round(ev.specificity_score, 3),
            "is_flagged":            ev.is_flagged,
            "flag_reason":           ev.flag_reason,
            "generic_phrases_found": ev.generic_phrases_found,
        },
        "pre_analysis": {
            "risk_floor":           pre.risk_floor,
            "risk_tags":            pre.risk_tags,
            "flagged_files":        pre.flagged_files,
            "trivially_touched":    pre.trivially_touched,
            "files_with_diff":      pre.files_with_diff,
            "files_skipped_budget": pre.files_skipped_budget,
            "files_skipped_noise":  pre.files_skipped_noise,
            "total_diff_chars":     pre.total_diff_chars,
        },
        "analysed_at": datetime.now(timezone.utc).isoformat(),
    }
    if risk is not None:
        response["risk_engine"] = {
            "score":       risk.risk_score,
            "band":        risk.risk_band,
            "label":       risk.risk_label,
            "top_factors": risk.top_factors,
            "breakdown": {
                "probability": round(risk.p_score, 3),
                "impact":      round(risk.i_score, 3),
                "confidence":  round(risk.c_score, 3),
            },
        }
    return response


# ══════════════════════════════════════════════════════════════════════════════
# Endpoints
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/")
async def health():
    return {"status": "ok", "version": "1.0.0"}


@app.get("/health")
async def healthcheck():
    return {"status": "ok"}


@app.post("/analyze-pr", dependencies=[Depends(_require_api_key)])
async def analyze_pr(req: AnalysePRRequest):
    """
    Analyse a GitHub pull request.
    Returns structured summary, risk assessment, and quality evaluation.
    Requires X-Api-Key header.
    """
    log.info(f"analyze-pr repo={req.repo} pr={req.pr_number}")
    return await _run_analysis(req.repo, req.pr_number)


# ── GitHub Webhook ─────────────────────────────────────────────────────────────

def _verify_github_signature(body: bytes, sig_header: str | None) -> None:
    """
    Validates the X-Hub-Signature-256 header using HMAC-SHA256.
    Skips validation if GITHUB_WEBHOOK_SECRET is not configured (dev mode).
    """
    if not WEBHOOK_SECRET:
        return  # dev mode — no secret configured
    if not sig_header or not sig_header.startswith("sha256="):
        raise HTTPException(status_code=401, detail="Missing webhook signature")
    expected = "sha256=" + hmac.new(
        WEBHOOK_SECRET.encode(), body, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, sig_header):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")


async def _process_webhook_pr(repo: str, pr_number: int) -> None:
    """Background task: run analysis and log. Errors are logged, never re-raised."""
    try:
        log.info(f"webhook analysis start repo={repo} pr={pr_number}")
        await _run_analysis(repo, pr_number)
        log.info(f"webhook analysis done repo={repo} pr={pr_number}")
    except Exception as e:
        log.error(f"webhook analysis failed repo={repo} pr={pr_number} error={e}")


@app.post("/webhook/github", status_code=202)
async def github_webhook(
    request:         Request,
    background_tasks: BackgroundTasks,
    x_github_event:  Annotated[str | None, Header()] = None,
    x_hub_signature_256: Annotated[str | None, Header()] = None,
):
    """
    GitHub webhook endpoint.
    Listens for pull_request events and triggers analysis in the background.
    Returns 202 immediately — GitHub expects a fast response.

    Setup:
      1. GitHub repo → Settings → Webhooks → Add webhook
      2. Payload URL: https://your-domain.com/webhook/github
      3. Content type: application/json
      4. Secret: your GITHUB_WEBHOOK_SECRET value
      5. Events: Pull requests
    """
    body = await request.body()
    _verify_github_signature(body, x_hub_signature_256)

    if x_github_event != "pull_request":
        # Acknowledge non-PR events without processing
        return {"accepted": False, "reason": f"event '{x_github_event}' not handled"}

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    action = payload.get("action", "")
    # Only trigger on open or sync (new commits pushed)
    if action not in ("opened", "synchronize", "reopened"):
        return {"accepted": False, "reason": f"action '{action}' not handled"}

    pr    = payload.get("pull_request", {})
    repo  = payload.get("repository", {}).get("full_name", "")
    pr_number = pr.get("number")

    if not repo or not pr_number:
        raise HTTPException(status_code=400, detail="Missing repository or PR number in payload")

    log.info(f"webhook received action={action} repo={repo} pr={pr_number}")
    background_tasks.add_task(_process_webhook_pr, repo, pr_number)

    return {
        "accepted": True,
        "repo":     repo,
        "pr":       pr_number,
        "action":   action,
        "message":  "Analysis queued",
    }


# ── Internal endpoints (no auth for simplicity — add auth before going public) ─

@app.get("/logs")
async def get_logs(n: int = 50):
    """Last n analysis log entries."""
    return {"logs": read_recent_logs(n)}
