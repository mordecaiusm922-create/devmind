"""
devmind_server.py — DevMind Agent Governance
MCP Server: the runtime enforcement point for AI agents.

Every tool call an agent makes passes through DevMindSandbox.intercept()
before execution. DevMind decides: ALLOW / REVIEW / BLOCK / REWRITE / ESCALATE.

Tools exposed to agents:
    execute_command     — run a shell command (terminal surface)
    read_file           — read a file (filesystem surface)
    write_file          — write a file (filesystem surface)
    delete_file         — delete a file (filesystem surface)
    git_operation       — git commands (git surface)
    http_request        — outbound HTTP (network surface)
    db_query            — database query (database surface)
    deploy              — deployment action (deployment surface)
    session_status      — inspect current session state

Usage (Claude Desktop / claude.ai):
    Add to claude_desktop_config.json:
    {
      "mcpServers": {
        "devmind": {
          "command": "python",
          "args": ["/path/to/devmind_server.py"],
          "env": {
            "DEVMIND_ORG_ID": "your-org",
            "DEVMIND_AUDIT_LOG": "data/audit/devmind_audit.jsonl",
            "DEVMIND_ENV": "production"
          }
        }
      }
    }
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Ensure local packages are importable
sys.path.insert(0, str(Path(__file__).resolve().parent))

from mcp.server.fastmcp import FastMCP
from runtime.backend_connector import GovernedSandbox
from core.types import ActionSurface, ChangeImpact, ChangeType, Decision

# =============================================================================
# Init
# =============================================================================

print("[DEVMIND] Governance MCP Server starting...", flush=True)

from mcp.server.transport_security import TransportSecuritySettings

mcp = FastMCP(
    "DevMind Governance",
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=["devmind-mcp.onrender.com", "localhost", "127.0.0.1"],
        allowed_origins=["https://devmind-mcp.onrender.com", "http://localhost", "http://127.0.0.1"],
    ),
)

ORG_ID      = os.getenv("DEVMIND_ORG_ID", "devmind-default")
AUDIT_LOG   = os.getenv("DEVMIND_AUDIT_LOG", "data/audit/devmind_audit.jsonl")
ENVIRONMENT = os.getenv("DEVMIND_ENV", "local")
AGENT_NAME  = os.getenv("DEVMIND_AGENT", "claude-code")
TIMEOUT     = int(os.getenv("DEVMIND_TIMEOUT", "15"))
OUTPUT_LIMIT = int(os.getenv("DEVMIND_OUTPUT_LIMIT", "12000"))

sandbox = GovernedSandbox(
    org_id=ORG_ID,
    audit_path=AUDIT_LOG,
)

# Active session — one per server process (one agent conversation)
_SESSION_ID = str(uuid.uuid4())

print(f"[DEVMIND] org={ORG_ID} env={ENVIRONMENT} session={_SESSION_ID}", flush=True)

# =============================================================================
# Secret redaction — applied to all output returned to the agent
# =============================================================================

_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),        "AWS_KEY_REDACTED"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),      "GITHUB_TOKEN_REDACTED"),
    (re.compile(r"\bdm-[A-Za-z0-9_-]{16,}\b"),            "DEVMIND_KEY_REDACTED"),
    (re.compile(
        r"(?i)(api[_-]?key|secret|token|password|private[_-]?key)"
        r"(\s*[:=]\s*['\"])[^'\"]+(['\"])"
    ), r"\1\2SECRET_REDACTED\3"),
)

def _redact(text: str) -> str:
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    return text

def _trim(text: str, limit: int = OUTPUT_LIMIT) -> str:
    text = _redact(text or "")
    if len(text) <= limit:
        return text
    return text[:limit] + "\n[DevMind] output truncated"

# =============================================================================
# Enforcement helper
# =============================================================================

def _enforce(decision_obj: Any, payload: str) -> tuple[bool, str]:
    """
    Returns (proceed: bool, message: str).
    Callers check proceed before executing anything.
    """
    d = decision_obj.decision

    if d == Decision.BLOCK:
        return False, (
            f"[DEVMIND BLOCK]\n"
            f"Reason: {decision_obj.reason}\n"
            f"Risk score: {decision_obj.risk_score}/100\n"
            f"Why: {' → '.join(decision_obj.why_chain[-3:])}\n"
            f"Instruction: solve the task without crossing this security boundary."
        )

    if d == Decision.ESCALATE:
        return False, (
            f"[DEVMIND ESCALATE]\n"
            f"Session risk is critical. Action suspended pending human review.\n"
            f"Violations in this session: {decision_obj.why_chain[-1]}\n"
            f"Contact your security team to resume."
        )

    if d == Decision.REVIEW:
        return False, (
            f"[DEVMIND REVIEW REQUIRED]\n"
            f"This action requires human approval before execution.\n"
            f"Reason: {decision_obj.reason} (score: {decision_obj.risk_score}/100)\n"
            f"Request approval via your team's security workflow."
        )

    if d == Decision.REWRITE and decision_obj.rewrite:
        return True, decision_obj.rewrite   # caller uses this as the safe payload

    return True, payload  # ALLOW


# =============================================================================
# Tools
# =============================================================================

@mcp.tool()
def execute_command(command: str, rationale: str) -> str:
    """
    Execute a shell command through DevMind governance.

    DevMind evaluates the command before execution and may:
    - ALLOW: execute and return output
    - BLOCK: refuse with explanation
    - REVIEW: pause for human approval
    - ESCALATE: suspend session (repeated violations)

    Args:
        command:   The exact shell command to run.
        rationale: Why the agent needs to run this command.
    """
    decision = sandbox.intercept(
        agent=AGENT_NAME,
        tool="terminal",
        operation="execute",
        payload=command,
        session_id=_SESSION_ID,
        environment=ENVIRONMENT,
        extra_context={"rationale": _redact(rationale)},
    )

    proceed, message = _enforce(decision, command)
    if not proceed:
        return message

    try:
        result = subprocess.run(
            command, shell=True, capture_output=True,
            text=True, timeout=TIMEOUT,
            encoding="utf-8", errors="replace",
        )
        return (
            f"[DEVMIND ALLOW] Exit code: {result.returncode}\n"
            f"STDOUT:\n{_trim(result.stdout)}\n"
            f"STDERR:\n{_trim(result.stderr)}"
        )
    except subprocess.TimeoutExpired:
        return f"[DEVMIND ERROR] Timeout: command exceeded {TIMEOUT}s."
    except Exception as exc:
        return f"[DEVMIND ERROR] {_redact(str(exc))}"


@mcp.tool()
def read_file(path: str) -> str:
    """
    Read a file through DevMind governance.

    Args:
        path: Absolute or relative path to the file.
    """
    decision = sandbox.intercept(
        agent=AGENT_NAME,
        tool="filesystem",
        operation="read",
        payload=path,
        session_id=_SESSION_ID,
        environment=ENVIRONMENT,
    )

    proceed, message = _enforce(decision, path)
    if not proceed:
        return message

    try:
        content = Path(path).read_text(encoding="utf-8", errors="replace")
        return _trim(content)
    except FileNotFoundError:
        return f"[DEVMIND ERROR] File not found: {path}"
    except Exception as exc:
        return f"[DEVMIND ERROR] {_redact(str(exc))}"


@mcp.tool()
def write_file(path: str, content: str, rationale: str) -> str:
    """
    Write content to a file through DevMind governance.

    Args:
        path:      Absolute or relative path.
        content:   Content to write.
        rationale: Why this file needs to be written.
    """
    payload = f"write:{path}\n{content[:500]}"   # path + preview for evaluation

    decision = sandbox.intercept(
        agent=AGENT_NAME,
        tool="filesystem",
        operation="write",
        payload=payload,
        session_id=_SESSION_ID,
        environment=ENVIRONMENT,
        extra_context={"rationale": _redact(rationale)},
    )

    proceed, message = _enforce(decision, payload)
    if not proceed:
        return message

    try:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return f"[DEVMIND ALLOW] Written: {path} ({len(content)} bytes)"
    except Exception as exc:
        return f"[DEVMIND ERROR] {_redact(str(exc))}"


@mcp.tool()
def delete_file(path: str, rationale: str) -> str:
    """
    Delete a file through DevMind governance.
    High-risk operation — always requires justification.

    Args:
        path:      File to delete.
        rationale: Why this file must be deleted.
    """
    decision = sandbox.intercept(
        agent=AGENT_NAME,
        tool="filesystem",
        operation="delete",
        payload=path,
        session_id=_SESSION_ID,
        environment=ENVIRONMENT,
        extra_context={"rationale": _redact(rationale)},
    )

    proceed, message = _enforce(decision, path)
    if not proceed:
        return message

    try:
        Path(path).unlink()
        return f"[DEVMIND ALLOW] Deleted: {path}"
    except FileNotFoundError:
        return f"[DEVMIND ERROR] File not found: {path}"
    except Exception as exc:
        return f"[DEVMIND ERROR] {_redact(str(exc))}"


@mcp.tool()
def git_operation(git_command: str, rationale: str) -> str:
    """
    Run a git command through DevMind governance.

    Args:
        git_command: The git command (e.g. 'git push origin main').
        rationale:   Why this git operation is needed.
    """
    decision = sandbox.intercept(
        agent=AGENT_NAME,
        tool="git",
        operation=git_command.split()[1] if len(git_command.split()) > 1 else "execute",
        payload=git_command,
        session_id=_SESSION_ID,
        environment=ENVIRONMENT,
        extra_context={"rationale": _redact(rationale)},
    )

    proceed, message = _enforce(decision, git_command)
    if not proceed:
        return message

    try:
        result = subprocess.run(
            git_command, shell=True, capture_output=True,
            text=True, timeout=30,
            encoding="utf-8", errors="replace",
        )
        return (
            f"[DEVMIND ALLOW] Exit code: {result.returncode}\n"
            f"{_trim(result.stdout)}\n{_trim(result.stderr)}"
        )
    except Exception as exc:
        return f"[DEVMIND ERROR] {_redact(str(exc))}"


@mcp.tool()
def db_query(query: str, rationale: str) -> str:
    """
    Submit a database query through DevMind governance.
    DevMind evaluates the query for destructive or injection patterns.

    NOTE: This tool evaluates and audits the query.
    Execution happens through your own DB connection — implement _execute_query().

    Args:
        query:     The SQL or query string.
        rationale: Why this query is needed.
    """
    decision = sandbox.intercept(
        agent=AGENT_NAME,
        tool="database",
        operation="execute",
        payload=query,
        session_id=_SESSION_ID,
        environment=ENVIRONMENT,
        extra_context={"rationale": _redact(rationale)},
    )

    proceed, message = _enforce(decision, query)
    if not proceed:
        return message

    # Plug in your DB connection here:
    # result = _execute_query(query)
    return (
        f"[DEVMIND ALLOW] Query approved (score={decision.risk_score}/100).\n"
        f"Execute via your application DB connection.\n"
        f"Query: {_redact(query[:200])}"
    )


@mcp.tool()
def http_request(url: str, method: str, rationale: str) -> str:
    """
    Make an outbound HTTP request through DevMind governance.

    Args:
        url:       Target URL.
        method:    HTTP method (GET, POST, etc.).
        rationale: Why this request is needed.
    """
    payload = f"{method.upper()} {url}"

    decision = sandbox.intercept(
        agent=AGENT_NAME,
        tool="http",
        operation="request",
        payload=payload,
        session_id=_SESSION_ID,
        environment=ENVIRONMENT,
        extra_context={"rationale": _redact(rationale)},
    )

    proceed, message = _enforce(decision, payload)
    if not proceed:
        return message

    return (
        f"[DEVMIND ALLOW] Request approved (score={decision.risk_score}/100).\n"
        f"Execute via your application HTTP client.\n"
        f"Request: {method.upper()} {url}"
    )


@mcp.tool()
def deploy(target: str, artifact: str, rationale: str) -> str:
    """
    Trigger a deployment through DevMind governance.
    Always high-risk — evaluated against environment and target.

    Args:
        target:    Deploy target (e.g. 'production', 'staging', 'k8s/prod').
        artifact:  What is being deployed (image, branch, version).
        rationale: Why this deployment is happening now.
    """
    payload = f"deploy target={target} artifact={artifact}"

    decision = sandbox.intercept(
        agent=AGENT_NAME,
        tool="deploy",
        operation="execute",
        payload=payload,
        session_id=_SESSION_ID,
        environment=target,   # the deploy target IS the environment
        extra_context={"rationale": _redact(rationale)},
    )

    proceed, message = _enforce(decision, payload)
    if not proceed:
        return message

    return (
        f"[DEVMIND ALLOW] Deployment approved (score={decision.risk_score}/100).\n"
        f"Target: {target} | Artifact: {artifact}\n"
        f"Trigger via your deployment pipeline."
    )


@mcp.tool()
def evaluate_terraform_plan(plan: str, environment: str, rationale: str) -> str:
    """
    Evaluate a Terraform plan/apply through DevMind infrastructure governance.

    DevMind scans the plan for IAM wildcards, public S3 buckets, open
    security groups, hardcoded secrets, force_destroy, and other
    infrastructure-level risk signals, then returns
    ALLOW / REVIEW / BLOCK / ESCALATE.

    This tool does NOT run terraform. Run `terraform apply` yourself only
    after receiving ALLOW.

    Args:
        plan:        The terraform plan output or .tf file content.
        environment: Target environment (e.g. 'production', 'staging', 'local').
        rationale:   Why this infrastructure change is needed.
    """
    affects_prod = environment.strip().lower() in ("production", "prod")

    decision = sandbox.intercept_change(
        agent=AGENT_NAME,
        change_type=ChangeType.TERRAFORM_APPLY,
        surface=ActionSurface.INFRASTRUCTURE,
        payload=plan,
        session_id=_SESSION_ID,
        environment=environment,
        impact=ChangeImpact(affects_production=affects_prod),
        extra_context={"rationale": _redact(rationale)},
    )

    proceed, message = _enforce(decision, plan)
    if not proceed:
        return message

    return (
        f"[DEVMIND ALLOW] Terraform plan approved (score={decision.risk_score}/100).\n"
        f"Environment: {environment}\n"
        f"Run `terraform apply` via your own shell/pipeline."
    )


@mcp.tool()
def evaluate_k8s_manifest(manifest: str, environment: str, rationale: str) -> str:
    """
    Evaluate a Kubernetes manifest or Helm chart through DevMind governance.

    DevMind scans for privileged containers, host network/PID access,
    cluster-admin bindings, wildcard RBAC, latest image tags, and other
    cluster-level risk signals, then returns ALLOW / REVIEW / BLOCK / ESCALATE.

    This tool does NOT run kubectl/helm. Apply the manifest yourself only
    after receiving ALLOW.

    Args:
        manifest:    The Kubernetes manifest (YAML) or Helm values/template content.
        environment: Target environment (e.g. 'production', 'staging', 'local').
        rationale:   Why this change is needed.
    """
    affects_prod = environment.strip().lower() in ("production", "prod")

    is_helm = bool(re.search(r"(?i)\{\{.*\}\}|rbac\.create|helm\.sh", manifest))
    change_type = ChangeType.HELM_RELEASE if is_helm else ChangeType.K8S_MANIFEST

    decision = sandbox.intercept_change(
        agent=AGENT_NAME,
        change_type=change_type,
        surface=ActionSurface.KUBERNETES,
        payload=manifest,
        session_id=_SESSION_ID,
        environment=environment,
        impact=ChangeImpact(affects_production=affects_prod),
        extra_context={"rationale": _redact(rationale)},
    )

    proceed, message = _enforce(decision, manifest)
    if not proceed:
        return message

    return (
        f"[DEVMIND ALLOW] {change_type.value} approved (score={decision.risk_score}/100).\n"
        f"Environment: {environment}\n"
        f"Apply via your own kubectl/helm command."
    )


@mcp.tool()
def release_gate(version: str, artifact: str, environment: str, rationale: str) -> str:
    """
    Evaluate a release publish/promote through DevMind's release gate.

    DevMind combines this session's accumulated risk profile (70% weight)
    with a scan of the release artifact for secrets and risk markers
    (30% weight). 3+ policy violations in this session, or secrets found
    in the artifact, BLOCK the release unconditionally. A production
    target requires at least REVIEW.

    This tool does NOT publish the release. Trigger your release pipeline
    yourself only after receiving ALLOW.

    Args:
        version:     Release version/tag (e.g. 'v3.1.0').
        artifact:    Release notes, changelog, or artifact content to scan.
        environment: Target environment (e.g. 'production', 'staging').
        rationale:   Why this release is happening now.
    """
    affects_prod = environment.strip().lower() in ("production", "prod")

    decision = sandbox.intercept_release(
        agent=AGENT_NAME,
        version=version,
        artifact=artifact,
        session_id=_SESSION_ID,
        environment=environment,
        impact=ChangeImpact(affects_production=affects_prod),
        extra_context={"rationale": _redact(rationale)},
    )

    proceed, message = _enforce(decision, artifact)
    if not proceed:
        return message

    return (
        f"[DEVMIND ALLOW] Release {version} approved (score={decision.risk_score}/100).\n"
        f"Environment: {environment}\n"
        f"Trigger your release pipeline."
    )


@mcp.tool()
def session_status() -> str:
    """
    Return the current session's governance state.
    Use this to understand how DevMind sees the current agent session.
    """
    stats = sandbox.session_stats(_SESSION_ID)
    if not stats:
        return json.dumps({"session_id": _SESSION_ID, "state": "new", "total_actions": 0})
    return json.dumps(stats, indent=2)


# =============================================================================
# Entry point
# =============================================================================

if __name__ == "__main__":
    transport = os.getenv("DEVMIND_MCP_TRANSPORT", "stdio")
    if transport == "streamable-http":
        import uvicorn
        from starlette.middleware.base import BaseHTTPMiddleware
        from starlette.responses import JSONResponse

        DEVMIND_MCP_TOKEN = os.getenv("DEVMIND_MCP_TOKEN")

        class TokenAuthMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request, call_next):
                if DEVMIND_MCP_TOKEN:
                    auth_header = request.headers.get("authorization", "")
                    expected = f"Bearer {DEVMIND_MCP_TOKEN}"
                    if auth_header != expected:
                        return JSONResponse({"error": "Unauthorized"}, status_code=401)
                return await call_next(request)

        port = int(os.getenv("PORT", "8000"))
        mcp.settings.host = "0.0.0.0"
        mcp.settings.port = port

        app = mcp.streamable_http_app()
        if DEVMIND_MCP_TOKEN:
            app.add_middleware(TokenAuthMiddleware)
            print(f"[DEVMIND] Running on streamable-http (AUTHENTICATED) | org={ORG_ID} | env={ENVIRONMENT} | port={port}", flush=True)
        else:
            print(f"[DEVMIND] WARNING: Running on streamable-http WITHOUT AUTH | org={ORG_ID} | env={ENVIRONMENT} | port={port}", flush=True)

        uvicorn.run(app, host="0.0.0.0", port=port)
    else:
        print(f"[DEVMIND] Running on stdio | org={ORG_ID} | env={ENVIRONMENT}", flush=True)
        mcp.run(transport="stdio")