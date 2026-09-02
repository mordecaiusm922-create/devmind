# DevMind — Runtime Governance for Autonomous AI Agents

> **The control plane that sits between an agent's decision and your production systems.**

DevMind intercepts, evaluates, and audits every action an AI agent attempts to take — before it executes. Deterministic policy engine. No LLM in the decision path. Sub-50ms response time.

**Live MCP server:** [devmind-mcp.onrender.com/mcp](https://devmind-mcp.onrender.com/mcp) -- connect Claude Desktop, Claude Code, Cursor, Codex, or any MCP client directly to your agent's runtime.
**Live REST API:** [devmind-2cej.onrender.com/health](https://devmind-2cej.onrender.com/health) -- for CI/CD pipelines and scripts that aren't MCP clients.
**334 invariant tests passing · CI green on every push**

---

## Why this exists

On April 25, 2026, a Cursor AI agent deleted PocketOS's entire production database — including every backup — in nine seconds. A single API call. No confirmation prompt. No governance layer. Just an agent with a token that had far more permissions than the task required.

Agents are becoming capable enough to take consequential, irreversible actions autonomously: deploying to production, executing database migrations, modifying infrastructure, rotating secrets. Most organizations have no layer that evaluates those actions before they execute.

DevMind is that layer.

Try the exact scenario against the live API:

```bash
curl -X POST https://devmind-2cej.onrender.com/evaluate-change \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $DEVMIND_TOKEN" \
  -d '{
    "agent_id": "cursor-agent",
    "change_type": "terraform_apply",
    "surface": "infrastructure",
    "payload": "production volume destroy",
    "affects_production": true,
    "blast_radius": "org"
  }'
```

```json
{
  "decision": "ESCALATE",
  "risk_score": 15.0,
  "why": [
    "Signal matched: prod_resource_name (+15)",
    "Blast radius is ORG -> ESCALATE (irrecoverable scope, no override)"
  ],
  "escalation_required": true
}
```

No agent touched Railway. The decision returned before the call was ever made.

---

## Connect via remote MCP (no local install required)

DevMind runs as a remote MCP server. Any MCP-compatible agent — Claude Desktop, Cursor, Codex, OpenCode, or any client supporting the Model Context Protocol — can connect directly over HTTP, with no local Python setup.

**Live MCP endpoint:** `https://devmind-mcp.onrender.com/mcp`
**Health check (no auth required):** `https://devmind-mcp.onrender.com/health`
**Protected Resource Metadata (RFC 9728):** `https://devmind-mcp.onrender.com/.well-known/oauth-protected-resource`

devmind-mcp is a spec-compliant **OAuth 2.1 Resource Server**. Every credential is scoped to a single agent/org **and** bound to a specific resource server (Resource Indicators, RFC 8707) — a token minted for `devmind-mcp` is rejected by the REST API and vice versa, and a token bound to one agent is rejected if used as another. Requests without a valid, correctly-scoped token receive a spec-correct `401` with a `WWW-Authenticate` header pointing back at the Protected Resource Metadata endpoint above, before reaching the governance engine. `/health` is exempt, so external monitoring (uptime checks, load balancer probes) can verify liveness without credentials.

**Getting a token today:** there is no self-service interactive login yet (no Authorization Code + PKCE flow) — with a small number of known agent clients, credentials are issued directly via `scripts/issue_token.py`, backed by Supabase. [Request one by opening an issue](https://github.com/mordecaiusm922-create/devmind/issues/new?template=request_token.yml) and you'll get back a token scoped to your agent and to the MCP resource specifically. A full interactive OAuth flow is planned once third-party self-service distribution opens (see Roadmap).

### Real containment, not just classification

`execute_command` does not run shell commands against the host process. Every allowed command executes inside a disposable **E2B Firecracker microVM** — no internet access by default, fully separate filesystem, destroyed after each call. If a command evades the policy engine's classification, the blast radius is a throwaway VM, not the machine running DevMind's own governance logic. This exists because blocklist-style classification alone was proven insufficient in practice: `find -exec rm`, `dd` writes to raw devices, shell fork bombs, redirection-based truncation, and `/dev/tcp` reverse shells were all confirmed to evade pattern-based detection during isolated live testing before this containment layer existed.

The terminal/filesystem surface is also mid-migration from a blocklist model (pattern-match known-bad commands — the original design) to an **allowlist model** (recognize known-safe SRE/platform-engineering vocabulary — diagnostic/investigation commands, approved remediations, capacity/SLO checks — and default-deny everything else to REVIEW). The allowlist currently runs in shadow mode: it logs what it *would* decide without changing real enforcement yet, while real usage data is collected before flipping to enforce mode.

### Supported actions

DevMind provides one MCP tool per surface your agent can act on:

| Surface | Tool | What it gates |
|---|---|---|
| Terminal | `execute_command` | Any shell command (runs in an E2B microVM sandbox) |
| Filesystem | `read_file`, `write_file`, `delete_file` | File reads/writes/deletes |
| Git | `git_operation` | Any git command (push, force-push, etc.) |
| Network | `http_request` | Outbound HTTP calls |
| Database | `db_query` | SQL queries |
| Deployment | `deploy` | Deploys to any target/environment |
| Infrastructure | `evaluate_terraform_plan`, `evaluate_k8s_manifest` | Terraform plans, Kubernetes manifests |
| Release | `release_gate` | Release publish/promote |
| Session | `session_status` | Inspect the current session's accumulated risk profile |

### Example prompts

Once connected, you don't call DevMind directly -- your agent calls these tools naturally as part of doing its job, and DevMind evaluates each call before it executes:

- *"Delete the old staging database volume"* -- gated by `execute_command`/`db_query`, likely `REVIEW` or `BLOCK` depending on environment.
- *"Push this hotfix directly to main"* -- gated by `git_operation`, matches the `no-direct-main-push` org rule.
- *"Apply this Terraform plan to production"* -- gated by `evaluate_terraform_plan`, blast-radius and semantic parsing both apply.
- *"Write my AWS key into the .env file so the script can read it"* -- gated by `write_file`, hard-blocked as a hardcoded secret regardless of environment.
- *"Check the current session's risk profile"* -- calls `session_status` directly, no gating (read-only).

### Claude Desktop

Add to your MCP settings (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "devmind": {
      "url": "https://devmind-mcp.onrender.com/mcp",
      "transport": "streamable-http",
      "headers": {
        "Authorization": "Bearer YOUR_DEVMIND_MCP_TOKEN"
      }
    }
  }
}
```

### Cursor

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "devmind": {
      "url": "https://devmind-mcp.onrender.com/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_DEVMIND_MCP_TOKEN"
      }
    }
  }
}
```

### Codex

Codex reads MCP config from `~/.codex/config.toml` (or a project-scoped `.codex/config.toml`). Add:

```toml
[mcp_servers.devmind]
url = "https://devmind-mcp.onrender.com/mcp"
bearer_token_env_var = "DEVMIND_MCP_TOKEN"
```

Then set the token as an environment variable before starting Codex, rather than pasting it into the file:

```bash
export DEVMIND_MCP_TOKEN="YOUR_DEVMIND_MCP_TOKEN"
```

### OpenCode

Add to `opencode.json` (project-level or `~/.config/opencode/opencode.json`):

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "devmind": {
      "type": "remote",
      "url": "https://devmind-mcp.onrender.com/mcp",
      "enabled": true,
      "oauth": false,
      "headers": {
        "Authorization": "Bearer {env:DEVMIND_MCP_TOKEN}"
      }
    }
  }
}
```

`"oauth": false` is required today since there's no interactive authorization server yet -- this tells OpenCode to use the static bearer token directly instead of attempting OAuth discovery.

### Any other MCP client

DevMind speaks standard streamable-HTTP MCP -- any harness that supports a remote MCP server over HTTP with a bearer token works the same way: point it at `https://devmind-mcp.onrender.com/mcp` and set an `Authorization: Bearer YOUR_DEVMIND_MCP_TOKEN` header (or your client's equivalent, e.g. an env-var-based token reference). If your tool's config format isn't shown above, check its docs for "remote MCP server" or "streamable HTTP" setup -- the URL and token are all you need.

### Run it locally instead

If you'd rather run the MCP server on your own machine (stdio transport, the default):

```json
{
  "mcpServers": {
    "devmind": {
      "command": "python",
      "args": ["/path/to/devmind_server.py"],
      "env": {
        "DEVMIND_ORG_ID": "your-org",
        "DEVMIND_AUDIT_LOG": "data/audit/devmind_audit.jsonl",
        "DEVMIND_ENV": "production",
        "SUPABASE_URL": "your-supabase-url",
        "SUPABASE_KEY": "your-supabase-service-key",
        "E2B_API_KEY": "your-e2b-api-key",
        "SLACK_BOT_TOKEN": "your-slack-bot-token",
        "SLACK_SIGNING_SECRET": "your-slack-signing-secret",
        "SLACK_REVIEW_CHANNEL": "your-slack-channel-id"
      }
    }
  }
}
```

`SUPABASE_URL`/`SUPABASE_KEY` are required for token validation (the OAuth Resource Server checks credentials against Supabase, not a static shared secret). `E2B_API_KEY` is required for `execute_command` to run -- without it, that specific tool returns an error while every other tool still works. `SLACK_BOT_TOKEN`/`SLACK_SIGNING_SECRET`/`SLACK_REVIEW_CHANNEL` are required for the human-review-via-Slack channel -- without them, a REVIEW verdict still returns cleanly (nothing crashes) but there's no way to actually approve it, since no notification goes anywhere.

For the HTTP transport instead of stdio, set `DEVMIND_MCP_TRANSPORT=streamable-http` and issue yourself a token via `python scripts/issue_token.py <org_id> <label> --resource https://devmind-mcp.onrender.com` (or your local resource URL) before running.

---

## Architecture

```
                    ┌─────────────────────┐
  AgentAction   ──▶ │   Policy Engine      │ ──▶ GovernanceDecision
  (tool calls)      │   policy_engine.py   │
                    └─────────────────────┘

                    ┌─────────────────────┐
  AgentChange   ──▶ │   Infra Engine       │ ──▶ GovernanceDecision
  (Terraform/K8s)   │   infra_engine.py    │
                    └─────────────────────┘

                    ┌─────────────────────┐
  AgentChange   ──▶ │   Release Gate       │ ──▶ GovernanceDecision
  (release_publish/ │   release_gate.py    │
   release_promote) │  70% session + 30%   │
                    │  artifact scan        │
                    └─────────────────────┘

  AgentSession  →  unit of memory       (pattern across actions in a session)
  Organization  →  unit of persistence  (policy, incident history, reputation)
```

Three engines, one decision contract. `AgentAction` (tool calls — terminal, filesystem, database, cloud) routes through the **policy engine**. `AgentChange` (Terraform applies, K8s manifests, Helm releases) routes through the **infra engine**, which evaluates blast radius before anything else. `AgentChange` with a release change type (`release_publish`/`release_promote`) routes through the **release gate**, which derives a session-risk score from the caller's `AgentSession` and an artifact-risk score from the payload, weighting them 70/30.

### Decision hierarchy

Every evaluation produces exactly one `GovernanceDecision`:

| Decision   | Meaning                                               |
|------------|--------------------------------------------------------|
| `ALLOW`    | Execute normally                                       |
| `REVIEW`   | Pause — notify human, await approval                   |
| `BLOCK`    | Deny outright — hard signal matched, no override        |
| `ESCALATE` | Irrecoverable blast radius — mandatory human checkpoint |
| `REWRITE`  | Execute a safe alternative payload instead              |

`BLOCK` and `ESCALATE` are not the same decision. `BLOCK` fires on hard signals the engine can resolve with certainty — a hardcoded secret, an IAM wildcard, a privileged container manifest. `ESCALATE` fires when the blast radius itself makes full automation unsafe — `ORG` or `ACCOUNT`-level changes always escalate, unconditionally, regardless of any org policy.

---

## Audit trail

Every decision made by `/evaluate`, `/evaluate-change`, and `/release-gate` (REST) or `execute_command` and the other MCP tools (MCP server) is persisted to a Supabase-backed audit log (`audit_records` table) — not just returned in the response. The MCP server falls back to a local JSONL file only if `SUPABASE_URL`/`SUPABASE_KEY` aren't configured (a warning is printed at startup when this happens), so a local dev instance without Supabase still gets *some* audit trail instead of silently logging nothing. Each record stores the agent, tool, operation, a SHA-256 hash of the payload (never the raw payload itself), the full decision, risk score, and why-chain, timestamped and queryable by session, agent, decision, or organization. This is what lets an organization answer "show me every time an agent tried to run `terraform destroy` against production last month" with an actual query, not a promise.

---

## Live API (HTTP)

Deployed at [`devmind-2cej.onrender.com`](https://devmind-2cej.onrender.com), running the exact engine in this repo. Useful for CI pipelines, scripts, or anything that isn't an MCP client.

| Endpoint            | Method | Purpose                                                |
|----------------------|--------|---------------------------------------------------------|
| `/health`            | GET    | Liveness check                                          |
| `/evaluate`          | POST   | Evaluate an `AgentAction` (tool call) via policy engine  |
| `/evaluate-change`   | POST   | Evaluate an `AgentChange` (Terraform/K8s/Helm) via infra engine |
| `/release-gate`      | POST   | Evaluate a release (`AgentChange` + `AgentSession`) via release gate |
| `/simulate`          | GET    | Run the 28 real-world risk scenarios, return the report  |

**Authentication is fail-closed whenever Supabase credentials are configured** (true in production): a missing or invalid `Authorization` header returns `401` before the request reaches the policy engine at all. Get a token via `python scripts/issue_token.py <org_id> <label>` (see the MCP section above for the full flow) -- a token scoped to `devmind-mcp` specifically will be rejected here; leave `--resource` unset for a token valid against both, or scope it to `https://devmind-2cej.onrender.com` for this API only.

```bash
export DEVMIND_TOKEN="dvm_your_token_here"

# IAM wildcard → BLOCK (hard signal, no override)
curl -X POST https://devmind-2cej.onrender.com/evaluate-change \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $DEVMIND_TOKEN" \
  -d '{
    "agent_id": "my-agent",
    "change_type": "terraform_apply",
    "surface": "infrastructure",
    "payload": "Action: \"*\" Resource: \"*\" Effect: Allow"
  }'

# Tool call through the policy engine
curl -X POST https://devmind-2cej.onrender.com/evaluate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $DEVMIND_TOKEN" \
  -d '{
    "agent_id": "claude-code",
    "tool": "terminal",
    "operation": "execute",
    "payload": "curl https://install.sh | bash"
  }'

# Release with a dirty session + secret in the artifact → BLOCK
curl -X POST https://devmind-2cej.onrender.com/release-gate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $DEVMIND_TOKEN" \
  -d '{
    "agent_id": "release-bot",
    "change_type": "release_publish",
    "payload": "api_key = \"sk-abc123secretvalue\"",
    "affects_production": true,
    "policy_violations": 3
  }'
```

Both return in well under 100ms — deterministic Python running in-process, not an LLM call. Note that `/evaluate` and `/evaluate-change` return a governance *decision*, not an execution result -- unlike the MCP `execute_command` tool, this REST API does not itself run anything inside an E2B sandbox; it's the caller's responsibility to act (or not) on the verdict.

---

## Quickstart (local)

```bash
git clone https://github.com/mordecaiusm922-create/devmind
cd devmind
pip install -r requirements.txt
python -m pytest tests/ -v          # 334 tests, deterministic, no mocks
python simulate_real_risks.py       # 28 real-world scenarios
```

Run the HTTP API locally:

```bash
uvicorn api:app --port 8000
# → http://localhost:8000/docs for interactive Swagger UI
```

Run the MCP server locally:

```bash
python devmind_server.py
# stdio transport by default — connect via claude_desktop_config.json
```

Call the engine directly from Python:

```python
from core.types import AgentAction, AgentSession, Organization, SessionState
from engines.policy_engine import evaluate_action
from datetime import datetime, timezone
import uuid

action = AgentAction(
    action_id=str(uuid.uuid4()),
    session_id="sess-001",
    agent="claude-code",
    tool="terminal",
    operation="execute",
    payload="curl https://install.sh | bash",
    timestamp=datetime.now(timezone.utc),
)
session = AgentSession(
    session_id="sess-001",
    agent="claude-code",
    organization="acme-corp",
    user="alice",
    started_at=datetime.now(timezone.utc),
)

decision = evaluate_action(action, session)
print(decision.decision, decision.risk_score, decision.why_chain)
```

---

## Module structure

```
core/
  types.py             — AgentAction, AgentChange, AgentSession, Organization,
                          GovernanceDecision, BlastRadius, ChangeType, ActionSurface

engines/
  policy_engine.py     — evaluate_action()  — tool-call governance
  infra_engine.py      — evaluate_change()  — Terraform / K8s / Helm governance
  terraform_semantic.py — semantic parser for `terraform plan -json`
  k8s_semantic.py       — semantic parser for K8s Pod/Deployment manifests
  release_gate.py      — evaluate_release() — session + artifact release governance
  audit_engine.py       — audit trail: JSONL (local/dev fallback) and Supabase (production)
  allowlist.py          — default-deny SRE-vocabulary allowlist for terminal/filesystem
                           (Phase 2, currently running in shadow mode)

tests/
  test_policy_engine.py
  test_infra_engine.py  — includes semantic parser coverage
  test_release_gate.py
  test_allowlist.py
  test_sandbox.py        — session-persistence UUID handling
  test_break_glass.py    — BLOCK-only break-glass override, org-level kill switch
  test_review_approval.py — human-review-via-Slack channel for REVIEW verdicts
                           — 334 invariant tests total

api.py                  — FastAPI wrapper exposing all three engines over HTTP,
                           each call persisted to the Supabase audit trail
devmind_server.py        — MCP server exposing DevMind as agent-callable tools
simulate_real_risks.py  — 28 real-world scenarios across fintech, healthcare,
                           SaaS, infrastructure, and supply chain
```

---

## Decision ladder — infra engine

`evaluate_change()` applies rules in this order — first decisive match wins:

1. **Semantic parsing** — if the payload is a real `terraform plan -json` or a Kubernetes Pod/Deployment manifest, the engine reads the actual structure (resource types, planned actions, security context) instead of relying only on pattern matching. Falls through silently to the steps below if the payload isn't parseable as either.
2. **Hard blocks** — deterministic, no override. IAM wildcards, hardcoded secrets, public S3 buckets, open security groups, privileged containers, `hostNetwork`/`hostPID`, cluster-admin bindings.
3. **Blast radius gate** — `ORG` or `ACCOUNT` scope → `ESCALATE`, unconditionally. This is the invariant that would have caught PocketOS. If the caller didn't declare a blast radius and the payload was a parseable Terraform plan, it can be inferred here from the plan's own structure.
4. **Production escalation** — a critical signal plus `affects_production=True` → `BLOCK`.
5. **Signal-based risk scoring** — weighted regex signals across Terraform, Kubernetes, and generic surfaces (exact patterns and weights live in source, not reproduced here).
6. **Risk threshold decision** — probabilistic fallback when no hard rule fires. Exact thresholds are intentionally not published here (they're visible in the source if you want to audit them) -- publishing the cutoff invites payloads tuned to land just under it.

The policy engine (`policy_engine.py`) mirrors this ordering for tool-call actions, with its own signal library for terminal, filesystem, database, and cloud surfaces.

### Semantic parsing (Terraform & Kubernetes)

Beyond regex-based signal matching, the infra engine parses structured infrastructure changes directly:

- **Terraform**: accepts real `terraform plan -json` output. Reads `resource_changes[].type` and `.change.actions` to classify destructive operations against a resource taxonomy (data persistence, IAM scope, network scope, cluster scope) — and infers blast radius from the plan's actual structure when the caller doesn't declare one explicitly.
- **Kubernetes**: accepts real Pod/Deployment YAML manifests. Parses `securityContext`, `hostNetwork`/`hostPID`/`hostIPC`, and capability lists against the official [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) (Baseline and Restricted profiles).

Both parsers are additive: if the payload isn't valid structured input, the engine falls back to the existing regex-based signal matching — nothing about existing behavior changes for callers who pass plain strings.

```python
# Real terraform plan -json, not a string someone typed
plan = subprocess.run(["terraform", "plan", "-out=tfplan"], capture_output=True)
plan_json = subprocess.run(["terraform", "show", "-json", "tfplan"], capture_output=True)

response = requests.post(
    "https://devmind-2cej.onrender.com/evaluate-change",
    json={
        "agent_id": "cursor-agent",
        "change_type": "terraform_apply",
        "surface": "infrastructure",
        "payload": plan_json.stdout,
        "affects_production": True,
    }
)
# blast_radius is inferred from the plan itself if not declared --
# no need to manually classify "this deletes an EBS volume" as ORG-scoped.
```

---

## Testing philosophy

Every governance invariant that matters has a test that runs on every push:

```python
def test_org_blast_radius_always_escalates():
    change = AgentChange(
        change_type=ChangeType.TERRAFORM_APPLY,
        surface=ActionSurface.INFRASTRUCTURE,
        payload="production volume destroy",
        impact=ChangeImpact(blast_radius=BlastRadius.ORG, affects_production=True),
        ...
    )
    decision = evaluate_change(change)
    assert decision.decision == Decision.ESCALATE
    assert decision.escalation_required == True
```

334 tests, zero mocks on the decision logic itself. If someone weakens an invariant, CI fails before it reaches main.

---

## Known limitations

Stated plainly, because a governance tool that hides its own gaps isn't trustworthy:

- **Pattern-based detection can still be evaded by novel syntax for a known-bad effect.** Outside of Terraform plan JSON and Kubernetes manifests (parsed structurally), most signal matching is regex over the payload string -- and during isolated live testing, `find -exec rm`, `dd` writes to raw devices, shell fork bombs, redirection-based truncation, and `/dev/tcp` reverse shells all evaded detection this way. Two things now limit the real-world impact of that gap: (1) `execute_command` runs inside a disposable E2B Firecracker microVM, not the host process, so an evaded command's blast radius is contained rather than executing against real infrastructure; (2) the terminal/filesystem surface is migrating from blocklist to an allowlist model (default-deny, only known-safe SRE/platform-engineering commands pass automatically), currently running in shadow mode alongside the existing signals while real usage data is collected before enforcement. Commands fragmented across multiple actions in the same session are caught via session-level payload correlation (the last 5 payloads are checked jointly against hard-block patterns) in both the MCP server and REST API -- this closes the most common fragmentation pattern but isn't exhaustive.
- **Semantic parsing covers Terraform and Kubernetes only.** Helm values, Pulumi, CloudFormation, and other IaC formats are still evaluated via regex signals, not structural parsing.
- **No self-service interactive OAuth flow yet.** devmind-mcp is a spec-compliant OAuth 2.1 Resource Server (RFC 9728 Protected Resource Metadata, RFC 8707 Resource Indicators) -- credentials are scoped per-agent and bound to a specific resource server (a token minted for the MCP server is rejected by the REST API and vice versa), backed by Supabase, not a shared secret. What's missing is an Authorization Code + PKCE flow for a human to click through a browser login -- with a small number of known agent clients today, tokens are issued directly via `scripts/issue_token.py`. This is the right tradeoff for the current stage, not the end state.
- **The MCP server's audit trail is durable when Supabase credentials are configured** (true in production), using the same `SupabaseAuditEngine` the REST API uses. It falls back to a local JSONL file (not durable across a Render redeploy) only when `SUPABASE_URL`/`SUPABASE_KEY` aren't set -- a startup warning makes this visible rather than silent.
- **The `/evaluate` endpoint's `context.environment` field must be explicitly set on the request** for production-aware policy signals to apply — it is not inferred from other fields. If your integration omits it, actions won't be evaluated as production traffic even if they target production infrastructure.

---

## What DevMind is not

- Not an LLM wrapper — the decision engine is deterministic Python, not a model call.
- Not a static scanner — it evaluates actions at the moment of intent, before execution.
- Not a generic firewall — it understands agent-specific surfaces: terminal, filesystem, database, cloud, Terraform, Kubernetes, Helm, releases.

---

## Roadmap

- [x] Remote MCP server (`devmind-mcp.onrender.com`)
- [x] Semantic parsing for Terraform plans and Kubernetes manifests
- [x] Persistent audit trail for the REST API (Supabase-backed, survives redeploys)
- [x] Session-level payload correlation (fragmented hard-block detection, both MCP and REST)
- [x] OAuth 2.1 Resource Server for MCP (RFC 9728 Protected Resource Metadata + RFC 8707 Resource Indicators) — per-agent, per-resource scoped credentials, Supabase-backed
- [x] Real containment for `execute_command` — E2B Firecracker microVMs, no host execution, no internet access by default
- [ ] Terminal/filesystem allowlist enforcement — default-deny model built and tested, currently running in shadow mode alongside the existing blocklist signals while real usage data is collected
- [x] Evasion audit of SQL, Terraform, IAM, and git signals (same methodology as the terminal allowlist work) -- 6 confirmed gaps closed, including an undocumented duplication found between policy_engine.py and infra_engine.py's independent signal lists (tracked as tech debt)
- [x] Session-composition context in LLM escalation -- REVIEW verdicts are now judged against recent session history (last 5 payloads), not just the isolated action, closing a gap where individually-permitted actions could combine into an unrecognized attack pattern
- [x] Break-glass override for BLOCK verdicts -- requires explicit justification, logged to a dedicated Supabase table with maximum audit severity. Does not override ESCALATE (irrecoverable, org/account-wide blast radius) under any circumstances. As of the human-review-via-Slack channel below, break_glass no longer applies to REVIEW at all (only BLOCK) -- if it still could, the Slack approval channel would have no teeth, since an agent could always self-serve past REVIEW with a fabricated justification
- [x] Org-level break-glass kill switch -- an organization can prohibit break-glass entirely via `organizations.break_glass_prohibited`, enforced fail-closed (an unreachable or misconfigured check refuses the override, it does not default to allowing it)
- [x] Fixed a silent session-persistence failure -- agent_sessions writes were failing on every request due to a non-UUID org_id default; replaced a brittle string comparison with real UUID validation
- [x] Durable audit trail for the MCP server (Supabase-backed, matching the REST API — falls back to local JSONL only when Supabase credentials aren't configured, with a startup warning)
- [x] Human-review-via-Slack channel for REVIEW verdicts -- REVIEW now posts to Slack with Approve/Reject buttons instead of being a dead end; approval is bound to the exact command text (a different command needs a fresh request), request signature verified via Slack's HMAC scheme with replay protection, and an already-resolved request can't be silently overwritten by a double-click
- [x] Informational Slack notification for BLOCK verdicts -- no buttons, nothing to approve, just real-time awareness for the team when an agent hits a hard block or overrides one via break-glass, instead of only finding out via the audit trail
- [x] Dockerfile for containerized deploy -- a drop-in alternative to Render's native Python buildpack (same Python version, same start command), for teams that need to self-host rather than use the hosted MCP server
- [ ] Interactive OAuth login (Authorization Code + PKCE) — needed once third-party self-service distribution opens; today tokens are issued directly via `scripts/issue_token.py`
- [ ] PyPI package + CLI (`pip install devmind-agent`, `devmind serve`)
- [ ] GitHub Action (`devmind-action`) — intercept agent PRs in CI/CD pipelines
- [ ] Kubernetes Admission Webhook — `infra_engine` enforced at the cluster level
- [ ] Agent reputation system — cross-session trust scores persisted in Supabase
- [ ] Compliance mapping (SOC2, ISO 27001, NIST AI RMF)
- [ ] Governance dashboard — visualize session risk, blocked actions, audit trail

---

## About this repo

The core governance engine is open source so you can audit exactly how decisions are made — no black box, no trust-us. The code here is the same code running in production behind the live API and MCP server above.

This is not a community-governed project. Feedback and bug reports on real-world usage are genuinely valuable and welcome — that's the signal that matters most right now. Pull requests to the core engines are not the intended contribution path.

**GitHub:** [github.com/mordecaiusm922-create/devmind](https://github.com/mordecaiusm922-create/devmind)
**Live API:** [devmind-2cej.onrender.com](https://devmind-2cej.onrender.com/health)
**Live MCP:** [devmind-mcp.onrender.com/mcp](https://devmind-mcp.onrender.com/mcp)