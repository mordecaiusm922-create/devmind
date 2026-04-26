import hashlib
import hmac
import httpx
import jwt
import os
import time
from fastapi import Request, HTTPException

GITHUB_APP_ID = os.getenv("GITHUB_APP_ID", "")
GITHUB_APP_PRIVATE_KEY = os.getenv("GITHUB_APP_PRIVATE_KEY", "")
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "")


def verify_webhook_signature(payload: bytes, signature: str) -> bool:
    if not signature or not signature.startswith("sha256="):
        return False
    expected = hmac.new(
        GITHUB_WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)


def generate_jwt() -> str:
    now = int(time.time())
    payload = {
        "iat": now - 60,
        "exp": now + 600,
        "iss": GITHUB_APP_ID,
    }
    return jwt.encode(payload, GITHUB_APP_PRIVATE_KEY, algorithm="RS256")


def get_installation_token(installation_id: int) -> str:
    token = generate_jwt()
    print(f"[CHECK RUN] repo={repo} sha={commit_sha[:7]} band={risk_band}")
    response = httpx.post(
        f"https://api.github.com/app/installations/{installation_id}/access_tokens",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        },
        timeout=10,
    )
    print(f"[CHECK RUN] status={response.status_code} body={response.text[:200]}")
    return response.json()["token"]


def post_pr_comment(repo: str, pr_number: int, body: str, token: str) -> None:
    httpx.post(
        f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        },
        json={"body": body},
        timeout=10,
    )

def create_check_run(repo: str, commit_sha: str, token: str, risk_score: int, risk_band: str, top_factors: list, summary: dict) -> dict:
    if risk_band == "critical":
        conclusion = "failure"
        title = f"🔴 Critical risk — {risk_score}/100"
    elif risk_band == "high":
        conclusion = "failure"
        title = f"🟠 High risk — {risk_score}/100"
    elif risk_band == "medium":
        conclusion = "neutral"
        title = f"🟡 Medium risk — {risk_score}/100"
    else:
        conclusion = "success"
        title = f"🟢 Low risk — {risk_score}/100"

    factors_md = "\n".join(f"- {f}" for f in top_factors) if top_factors else "- None detected"
    summary_md = f"""**What:** {summary.get("what", "N/A")}
**Impact:** {summary.get("impact", "N/A")}

### Top risk factors
{factors_md}
"""

    print(f"[CHECK RUN] repo={repo} sha={commit_sha[:7]} band={risk_band}")
    response = httpx.post(
        f"https://api.github.com/repos/{repo}/check-runs",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        },
        json={
            "name": "DevMind Risk Engine",
            "head_sha": commit_sha,
            "status": "completed",
            "conclusion": conclusion,
            "output": {
                "title": title,
                "summary": summary_md,
            },
        },
        timeout=10,
    )
    print(f"[CHECK RUN] status={response.status_code} body={response.text[:200]}")
    return response.json()
