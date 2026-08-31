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
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from pydantic import AnyHttpUrl
import hashlib as _hashlib
from datetime import datetime as _datetime, timezone as _timezone
from engines.audit_engine import SupabaseAuditEngine

MCP_RESOURCE_URL = os.getenv("DEVMIND_MCP_RESOURCE_URL", "https://devmind-mcp.onrender.com")


class SupabaseTokenVerifier(TokenVerifier):
    """Resource Server token validation for the MCP transport.

    Reuses the same api_credentials table (and hashing scheme) that
    api.py already validates REST tokens against -- one source of
    truth for credentials across both DevMind backends. Enforces
    Resource Indicators (RFC 8707): a token bound to a different
    resource (or issued for the REST API specifically) is rejected
    here, not silently accepted.
    """

    def __init__(self) -> None:
        self._audit = SupabaseAuditEngine()

    async def verify_token(self, token: str) -> AccessToken | None:
        client = self._audit._client
        if client is None:
            print("[DEVMIND] AUTH: no Supabase client configured -- rejecting all MCP tokens", flush=True)
            return None
        token_hash = _hashlib.sha256(token.encode()).hexdigest()
        try:
            result = (
                client.table("api_credentials")
                .select("org_id, agent_id, resource, revoked_at")
                .eq("token_hash", token_hash)
                .single()
                .execute()
            )
        except Exception as e:
            print(f"[DEVMIND] AUTH: token lookup failed: {e}", flush=True)
            return None
        if not result.data or result.data.get("revoked_at") is not None:
            return None
        bound_resource = result.data.get("resource")
        if bound_resource is not None and bound_resource != MCP_RESOURCE_URL:
            print(f"[DEVMIND] AUTH: token bound to {bound_resource!r}, not this resource -- rejected", flush=True)
            return None
        try:
            client.table("api_credentials").update(
                {"last_used_at": _datetime.now(_timezone.utc).isoformat()}
            ).eq("token_hash", token_hash).execute()
        except Exception:
            pass
        return AccessToken(
            token=token,
            client_id=result.data.get("agent_id") or result.data["org_id"],
            scopes=[],
        )


mcp = FastMCP(
    "DevMind Governance",
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[
            "devmind-mcp.onrender.com",
            "localhost", "127.0.0.1",
            f"localhost:{os.getenv('PORT', '8000')}",
            f"127.0.0.1:{os.getenv('PORT', '8000')}",
        ],
        allowed_origins=["https://devmind-mcp.onrender.com", "http://localhost", "http://127.0.0.1"],
    ),
    token_verifier=SupabaseTokenVerifier(),
    auth=AuthSettings(
        issuer_url=AnyHttpUrl(MCP_RESOURCE_URL),
        resource_server_url=AnyHttpUrl(MCP_RESOURCE_URL),
        required_scopes=[],
    ),
)

ORG_ID      = os.getenv("DEVMIND_ORG_ID", "devmind-default")
AUDIT_LOG   = os.getenv("DEVMIND_AUDIT_LOG", "data/audit/devmind_audit.jsonl")
ENVIRONMENT = os.getenv("DEVMIND_ENV", "local")
AGENT_NAME  = os.getenv("DEVMIND_AGENT", "claude-code")
TIMEOUT     = int(os.getenv("DEVMIND_TIMEOUT", "15"))
OUTPUT_LIMIT = int(os.getenv("DEVMIND_OUTPUT_LIMIT", "12000"))

def _select_audit_engine(candidate: Any) -> Any | None:
    """Use `candidate` (a Supabase-backed audit engine) only when it
    actually has a live Supabase client configured -- otherwise
    return None so GovernedSandbox falls through to its own default
    (local JSONL) instead of silently logging nothing. Extracted as
    a standalone function so this decision is unit-testable without
    reloading the whole module under different env vars."""
    return candidate if getattr(candidate, "_client", None) is not None else None


_supabase_audit = SupabaseAuditEngine()
_selected_audit_engine = _select_audit_engine(_supabase_audit)
sandbox = GovernedSandbox(
    org_id=ORG_ID,
    audit_path=AUDIT_LOG,
    audit_engine=_selected_audit_engine,
)
if _selected_audit_engine is None:
    print("[DEVMIND] WARNING: no Supabase credentials -- audit trail falling back to local JSONL (not durable across redeploys)", flush=True)

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
def _is_break_glass_prohibited_for_org(org_id: str) -> bool:
    """Org-level kill switch for break-glass overrides (point 5,
    2026-08-23 snapshot). Looks up organizations.break_glass_prohibited
    in Supabase by org_id.

    Fails CLOSED: if org_id isn't a valid UUID, if there's no Supabase
    client, if the org has no matching row, or if the query raises for
    any reason -- treat break-glass as prohibited. This is an
    access-control decision (not an audit-log write), so it follows
    the same fail-closed precedent as SupabaseTokenVerifier rather
    than the fail-open precedent used by the audit trail helpers in
    this file. A Supabase outage means break-glass is unavailable
    until it's back, by design -- see the point-5 design discussion
    in the project history for the explicit trade-off this makes
    against emergency availability.
    """
    if not GovernedSandbox._is_org_id_a_valid_uuid(org_id):
        print(
            f"[BREAK-GLASS] org_id={org_id!r} is not a valid UUID -- "
            f"failing closed, treating break-glass as prohibited.",
            flush=True,
        )
        return True

    client = _supabase_audit._client
    if client is None:
        print(
            "[BREAK-GLASS] no Supabase client available -- failing closed, "
            "treating break-glass as prohibited.",
            flush=True,
        )
        return True

    try:
        result = (
            client.table("organizations")
            .select("break_glass_prohibited")
            .eq("id", org_id)
            .limit(1)
            .execute()
        )
        rows = result.data or []
        if not rows:
            print(
                f"[BREAK-GLASS] org_id={org_id!r} has no matching row in "
                f"organizations -- failing closed, treating break-glass as "
                f"prohibited.",
                flush=True,
            )
            return True
        return bool(rows[0].get("break_glass_prohibited", True))
    except Exception as exc:
        print(
            f"[BREAK-GLASS] organizations lookup failed (failing closed): {exc!r}",
            flush=True,
        )
        return True

def _log_break_glass_override(command: str, decision: Any, justification: str) -> None:
    """Dedicated, maximum-severity audit record for a break-glass
    override -- separate from the normal decision audit trail so it
    can never be missed or confused with a routine ALLOW. Stopgap:
    non-fatal on write failure (print() always fires so this is
    visible in Render logs even if the Supabase write fails)."""
    decision_name = getattr(getattr(decision, "decision", None), "name", "UNKNOWN")
    reason = getattr(decision, "reason", None)
    risk_score = getattr(decision, "risk_score", None)
    print(
        f"[BREAK-GLASS OVERRIDE] session={_SESSION_ID} agent={AGENT_NAME} "
        f"original_decision={decision_name} risk_score={risk_score} "
        f"command={_redact(command)[:300]!r} "
        f"justification={_redact(justification)[:300]!r}",
        flush=True,
    )
    try:
        client = _supabase_audit._client
        if client is not None:
            client.table("break_glass_log").insert({
                "session_id": _SESSION_ID,
                "agent": AGENT_NAME,
                "command": _redact(command)[:2000],
                "original_decision": decision_name,
                "original_reason": reason,
                "risk_score": risk_score,
                "justification": _redact(justification)[:2000],
            }).execute()
    except Exception as db_exc:
        print(f"[BREAK-GLASS OVERRIDE] Supabase write failed (non-fatal): {db_exc!r}", flush=True)


@mcp.tool()
def execute_command(
    command: str,
    rationale: str,
    break_glass: bool = False,
    break_glass_justification: str = "",
) -> str:
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
        break_glass: Set True only during a genuine emergency to
            override a BLOCK or REVIEW verdict. Requires
            break_glass_justification. Logged with maximum audit
            severity and flagged for mandatory post-incident review --
            this is not a quiet bypass. Does NOT override ESCALATE
            (irrecoverable, org/account-wide blast radius) under any
            circumstances.
        break_glass_justification: Required, non-empty, when
            break_glass=True. Explain the specific emergency.
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

    # --- Phase 2 shadow mode: log what the allowlist WOULD have
    # decided, without changing real enforcement yet. Stopgap
    # print()-based logging -- not durable, replace with a Supabase
    # table before relying on this for real rollout decisions.
    # Also feeds the REVIEW message below (allowlist_context) so the
    # classification isn't computed twice.
    allowlist_context: tuple[bool, str] | None = None
    try:
        from engines.allowlist import is_allowlisted
        allowlist_allowed, allowlist_reason = is_allowlisted(command)
        allowlist_context = (allowlist_allowed, allowlist_reason)
        blocklist_decision = getattr(decision, "decision", None)
        blocklist_decision_name = getattr(blocklist_decision, "name", str(blocklist_decision))
        agreement = "AGREE" if (allowlist_allowed == (blocklist_decision_name == "ALLOW")) else "DISAGREE"
        print(
            f"[SHADOW:allowlist] {agreement} | "
            f"blocklist={blocklist_decision_name} | "
            f"allowlist={'ALLOW' if allowlist_allowed else 'REVIEW'} ({allowlist_reason}) | "
            f"command={_redact(command)[:200]!r}",
            flush=True,
        )
        try:
            _shadow_client = SupabaseAuditEngine()._client
            if _shadow_client is not None:
                _shadow_client.table("allowlist_shadow_log").insert({
                    "session_id": _SESSION_ID,
                    "command": _redact(command)[:2000],
                    "blocklist_decision": blocklist_decision_name,
                    "allowlist_allowed": allowlist_allowed,
                    "allowlist_reason": allowlist_reason,
                    "agreement": agreement,
                }).execute()
        except Exception as db_exc:
            print(f"[SHADOW:allowlist] Supabase write failed (non-fatal): {db_exc!r}", flush=True)
    except Exception as shadow_exc:
        print(f"[SHADOW:allowlist] ERROR computing shadow decision: {shadow_exc!r}", flush=True)

    proceed, message = _enforce(decision, command)
    if not proceed:
        decision_name = getattr(getattr(decision, "decision", None), "name", None)
        if allowlist_context is not None and decision_name == "REVIEW":
            ctx_allowed, ctx_reason = allowlist_context
            if ctx_allowed:
                message += (
                    f"\n\nAllowlist context: this command matches the known-safe "
                    f"'{ctx_reason}' category. The review is coming from a different "
                    f"policy signal, not from unrecognized command syntax -- see Reason above."
                )
            else:
                message += (
                    f"\n\nAllowlist context: this command isn't recognized as belonging to "
                    f"any known-safe SRE category (diagnostic investigation, approved "
                    f"remediation, or capacity/SLO checks). If it should be, that's useful "
                    f"signal for expanding DevMind's allowlist."
                )

        if decision_name == "ESCALATE":
            return message + (
                "\n\nbreak_glass cannot override ESCALATE -- irrecoverable, "
                "org/account-wide blast radius requires a real human security "
                "checkpoint under all circumstances, no exceptions."
            )

        if break_glass and _is_break_glass_prohibited_for_org(ORG_ID):
            return message + (
                "\n\nbreak_glass is disabled for this organization. Contact "
                "your DevMind administrator if this is a genuine emergency."
            )

        if break_glass:
            if not break_glass_justification.strip():
                return message + (
                    "\n\n[DEVMIND] break_glass=True requires a non-empty "
                    "break_glass_justification explaining the emergency. Refusing "
                    "to override without one."
                )
            _log_break_glass_override(command, decision, break_glass_justification)
        else:
            return message

    try:
        from e2b_code_interpreter import Sandbox
        from e2b.sandbox.commands.command_handle import CommandExitException

        with Sandbox.create(allow_internet_access=False, timeout=TIMEOUT) as sbx:
            try:
                result = sbx.commands.run(command, timeout=TIMEOUT)
                return (
                    f"[DEVMIND ALLOW] Exit code: {result.exit_code}\n"
                    f"STDOUT:\n{_trim(result.stdout)}\n"
                    f"STDERR:\n{_trim(result.stderr)}"
                )
            except CommandExitException as e:
                return (
                    f"[DEVMIND ALLOW] Exit code: {e.exit_code}\n"
                    f"STDOUT:\n{_trim(e.stdout)}\n"
                    f"STDERR:\n{_trim(e.stderr)}"
                )
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


@mcp.tool()
def _debug_check_bwrap_capability() -> str:
    """TEMPORARY diagnostic tool -- remove after use. Checks whether
    this Render instance permits unprivileged user namespaces for
    bubblewrap sandboxing. Read-only, harmless, no destructive action."""
    import shutil as _shutil
    if not _shutil.which("bwrap"):
        return "[DIAG] bwrap binary not found on this instance -- would need to be installed via Dockerfile/build step."
    try:
        result = subprocess.run(
            ["bwrap", "--unshare-all", "--ro-bind", "/usr", "/usr",
             "--ro-bind", "/bin", "/bin", "--ro-bind", "/lib", "/lib",
             "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
             "--", "/bin/echo", "sandbox_ok"],
            capture_output=True, text=True, timeout=10,
        )
        return (
            f"[DIAG] exit_code={result.returncode}\n"
            f"stdout={result.stdout!r}\n"
            f"stderr={result.stderr!r}"
        )
    except Exception as exc:
        return f"[DIAG] exception: {exc!r}"


# =============================================================================
# Entry point
# =============================================================================

if __name__ == "__main__":
    transport = os.getenv("DEVMIND_MCP_TRANSPORT", "stdio")
    if transport == "streamable-http":
        import uvicorn
        from starlette.middleware.base import BaseHTTPMiddleware
        from starlette.responses import JSONResponse

        import time as _time
        from collections import defaultdict as _defaultdict

        # Defense in depth: even with a valid token, cap request volume per
        # client IP. Same in-memory, per-process pattern as api.py's rate
        # limiter -- resets on restart, does not share state across multiple
        # instances. Sufficient for a single free-tier instance.
        _rate_buckets: dict[str, list[float]] = _defaultdict(list)
        _RATE_MAX = 30
        _RATE_WINDOW = 60

        class RateLimitMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request, call_next):
                if request.url.path == "/health":
                    return await call_next(request)
                client_ip = request.client.host if request.client else "unknown"
                now = _time.time()
                bucket = _rate_buckets[client_ip]
                while bucket and now - bucket[0] > _RATE_WINDOW:
                    bucket.pop(0)
                if len(bucket) >= _RATE_MAX:
                    return JSONResponse(
                        {"error": f"Rate limit exceeded: max {_RATE_MAX} requests per {_RATE_WINDOW}s."},
                        status_code=429,
                    )
                bucket.append(now)
                return await call_next(request)

        port = int(os.getenv("PORT", "8000"))
        mcp.settings.host = "0.0.0.0"
        mcp.settings.port = port

        app = mcp.streamable_http_app()

        from starlette.routing import Route
        from starlette.responses import JSONResponse as _JSONResponse
        async def _health(request):
            return _JSONResponse({"status": "ok", "service": "devmind-mcp"})
        app.router.routes.insert(0, Route("/health", _health, methods=["GET"]))

        app.add_middleware(RateLimitMiddleware)
        print(f"[DEVMIND] Running on streamable-http (OAuth Resource Server, RATE-LIMITED) | org={ORG_ID} | env={ENVIRONMENT} | port={port} | resource={MCP_RESOURCE_URL}", flush=True)

        uvicorn.run(app, host="0.0.0.0", port=port)
    else:
        print(f"[DEVMIND] Running on stdio | org={ORG_ID} | env={ENVIRONMENT}", flush=True)
        mcp.run(transport="stdio")
