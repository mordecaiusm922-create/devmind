"""
main.py â€” DevMind SaaS API
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

# â”€â”€ Structured logger â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}',
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("devmind")

# â”€â”€ Config â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

# â”€â”€ In-memory sliding-window rate limiter â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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


# â”€â”€ API key dependency â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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


# â”€â”€ App â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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


# â”€â”€ Request logging middleware â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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


# â”€â”€ Global exception handler â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.exception_handler(Exception)
async def _unhandled(request: Request, exc: Exception):
    log.error(f"Unhandled exception on {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": str(exc)},
    )


# â”€â”€ Models â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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


# â”€â”€ Core pipeline runner â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
        for f in pr_data.get("files", []):
            fname = f.get("filename", "")
            patch = f.get("raw_patch", "") or f.get("diff", "")
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


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Endpoints
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

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


# â”€â”€ GitHub Webhook â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _verify_github_signature(body: bytes, sig_header: str | None) -> None:
    """
    Validates the X-Hub-Signature-256 header using HMAC-SHA256.
    Skips validation if GITHUB_WEBHOOK_SECRET is not configured (dev mode).
    """
    if not WEBHOOK_SECRET:
        return  # dev mode â€” no secret configured
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
    request: Request,
    background_tasks: BackgroundTasks,
    x_github_event: Annotated[str | None, Header()] = None,
    x_hub_signature_256: Annotated[str | None, Header()] = None,
):
    from github_app import verify_webhook_signature, get_installation_token, post_pr_comment
    body = await request.body()
    if not verify_webhook_signature(body, x_hub_signature_256 or ""):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    if x_github_event != "pull_request":
        return {"accepted": False, "reason": f"event '{x_github_event}' not handled"}

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    action = payload.get("action", "")
    if action not in ("opened", "synchronize", "reopened"):
        return {"accepted": False, "reason": f"action '{action}' not handled"}

    pr            = payload.get("pull_request", {})
    repo          = payload.get("repository", {}).get("full_name", "")
    pr_number     = pr.get("number")
    commit_sha    = pr.get("head", {}).get("sha", "")
    installation_id = payload.get("installation", {}).get("id")

    if not repo or not pr_number or not installation_id:
        raise HTTPException(status_code=400, detail="Missing repo, PR number, or installation_id")

    log.info(f"webhook received action={action} repo={repo} pr={pr_number}")

    async def analyze_and_comment():
        print("[TASK] started")
        try:
            token  = get_installation_token(installation_id)
            result = await _run_analysis(repo, pr_number)
            s      = result.get("summary", {})
            re_obj = result.get("risk_engine", {})
            level  = re_obj.get("band", "low")
            score  = re_obj.get("score", 0)
            top_factors = re_obj.get("top_factors", [])
            vulns  = s.get("vulnerabilities") or []

            EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "minimal": "⚪"}
            emoji = EMOJI.get(level, "⚪")

            vuln_lines = []
            for v in vulns:
                sev  = v.get("severity", "").upper()
                loc  = v.get("location", "")
                desc = v.get("description", "")
                fix  = v.get("fix", "")
                vuln_lines.append(f"> **{sev}** `{loc}`\n> {desc}\n> **Fix:** {fix}")

            factors_md = "\n".join(f"- {f}" for f in top_factors) if top_factors else "- None detected"
            vulns_md   = "\n\n".join(vuln_lines) if vuln_lines else "_No vulnerabilities detected_"

            comment = f"""## {emoji} DevMind Risk Analysis

**Risk score:** `{score}/100` — **{level.upper()}**

### Top risk factors
{factors_md}

### Vulnerabilities
{vulns_md}

### Summary
**What:** {s.get("what", "N/A")}
**Impact:** {s.get("impact", "N/A")}

---
_Analyzed by [DevMind](https://devmind-gamma.vercel.app)_"""

            post_pr_comment(repo, pr_number, comment, token)
            create_check_run(repo, commit_sha, token, score, level, top_factors, s)
            log.info(f"webhook comment posted repo={repo} pr={pr_number}")
        except Exception as e:
            import traceback
            print(f"[TASK ERROR] {traceback.format_exc()}")
            log.error(f"webhook analysis failed repo={repo} pr={pr_number} error={e}")

    import threading
    threading.Thread(target=lambda: asyncio.run(analyze_and_comment()), daemon=False).start()
    return {"accepted": True, "repo": repo, "pr": pr_number, "action": action}
# â”€â”€ Internal endpoints (no auth for simplicity â€” add auth before going public) â”€

@app.get("/logs")
async def get_logs(n: int = 50):
    """Last n analysis log entries."""
    return {"logs": read_recent_logs(n)}



