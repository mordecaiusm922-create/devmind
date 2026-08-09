# DevMind — Runtime Governance for Autonomous AI Agents

> **The control plane that sits between an agent's decision and your production systems.**

DevMind intercepts, evaluates, and audits every action an AI agent attempts to take — before it executes. Deterministic policy engine. No LLM in the decision path. Sub-50ms response time.

**Live MCP server:** [devmind-mcp.onrender.com/mcp](https://devmind-mcp.onrender.com/mcp) -- connect Claude Desktop, Claude Code, Cursor, Codex, or any MCP client directly to your agent's runtime.
**Live REST API:** [devmind-2cej.onrender.com/health](https://devmind-2cej.onrender.com/health) -- for CI/CD pipelines and scripts that aren't MCP clients.
**189 invariant tests passing · CI green on every push**

---

## Why this exists

On April 25, 2026, a Cursor AI agent deleted PocketOS's entire production database — including every backup — in nine seconds. A single API call. No confirmation prompt. No governance layer. Just an agent with a token that had far more permissions than the task required.

Agents are becoming capable enough to take consequential, irreversible actions autonomously: deploying to production, executing database migrations, modifying infrastructure, rotating secrets. Most organizations have no layer that evaluates those actions before they execute.

DevMind is that layer.

Try the exact scenario against the live API:

```bash
curl -X POST https://devmind-2cej.onrender.com/evaluate-change \
  -H "Content-Type: application/json" \
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

DevMind runs as a remote MCP server. Any MCP-compatible agent — Claude Desktop, Cursor, or any client supporting the Model Context Protocol — can connect directly over HTTP, with no local Python setup.

**Live MCP endpoint:** `https://devmind-mcp.onrender.com/mcp`
**Health check (no auth required):** `https://devmind-mcp.onrender.com/health`

The remote server requires a bearer token — it evaluates real tool calls (`execute_command`, `write_file`, `delete_file`, `db_query`, `deploy`), so it is not left open to anonymous requests. **This is currently a single shared bearer token, not per-agent or per-user identity.** That's a deliberate trade-off for this stage — sufficient for single-tenant use and evaluation, but it does not yet give you per-identity audit attribution beyond the `agent_id`/`session_id` fields the caller supplies. Per-agent credentials are a natural next step once there's a real multi-tenant use case driving it. [Request a token by opening an issue](https://github.com/mordecaiusm922-create/devmind/issues/new?template=request_token.yml) — usually answered within a day or two — or run your own instance using the local setup below.

### Supported actions

DevMind provides one MCP tool per surface your agent can act on:

| Surface | Tool | What it gates |
|---|---|---|
| Terminal | `execute_command` | Any shell command |
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

### Any other MCP client

DevMind speaks standard streamable-HTTP MCP -- any harness that supports a remote MCP server over HTTP with a bearer token works the same way: point it at `https://devmind-mcp.onrender.com/mcp` and set an `Authorization: Bearer YOUR_DEVMIND_MCP_TOKEN` header (or your client's equivalent, e.g. an env-var-based token reference). If your tool's config format isn't shown above, check its docs for "remote MCP server" or "streamable HTTP" setup -- the URL and token are all you need.

Once connected, every `execute_command`, `write_file`, `delete_file`, `git_operation`, `http_request`, `db_query`, and `deploy` call your agent makes is evaluated by DevMind's policy engine before execution. `session_status` lets you inspect the current session's accumulated risk profile at any point.

Requests without a valid token receive `401 Unauthorized` before reaching the governance engine. `/health` is exempt from this check, so external monitoring (uptime checks, load balancer health probes) can verify liveness without credentials.

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
        "DEVMIND_ENV": "production"
      }
    }
  }
}
```

For the HTTP transport instead of stdio, set `DEVMIND_MCP_TRANSPORT=streamable-http` and `DEVMIND_MCP_TOKEN=<your-token>` before running.

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

Every decision made by `/evaluate`, `/evaluate-change`, and `/release-gate` is persisted to a Supabase-backed audit log (`audit_records` table) — not just returned in the response. Each record stores the agent, tool, operation, a SHA-256 hash of the payload (never the raw payload itself), the full decision, risk score, and why-chain, timestamped and queryable by session, agent, decision, or organization. This is what lets an organization answer "show me every time an agent tried to run `terraform destroy` against production last month" with an actual query, not a promise.

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

```bash
# IAM wildcard → BLOCK (hard signal, no override)
curl -X POST https://devmind-2cej.onrender.com/evaluate-change \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "my-agent",
    "change_type": "terraform_apply",
    "surface": "infrastructure",
    "payload": "Action: \"*\" Resource: \"*\" Effect: Allow"
  }'

# Tool call through the policy engine
curl -X POST https://devmind-2cej.onrender.com/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "claude-code",
    "tool": "terminal",
    "operation": "execute",
    "payload": "curl https://install.sh | bash"
  }'

# Release with a dirty session + secret in the artifact → BLOCK
curl -X POST https://devmind-2cej.onrender.com/release-gate \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "release-bot",
    "change_type": "release_publish",
    "payload": "api_key = \"sk-abc123secretvalue\"",
    "affects_production": true,
    "policy_violations": 3
  }'
```

Both return in well under 100ms — deterministic Python running in-process, not an LLM call.

---

## Quickstart (local)

```bash
git clone https://github.com/mordecaiusm922-create/devmind
cd devmind
pip install -r requirements.txt
python -m pytest tests/ -v          # 182 tests, deterministic, no mocks
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
  audit_engine.py       — audit trail: JSONL (local/dev) and Supabase (production)

tests/
  test_policy_engine.py
  test_infra_engine.py  — includes semantic parser coverage
  test_release_gate.py  — 182 invariant tests total

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

189 tests, zero mocks on the decision logic itself. If someone weakens an invariant, CI fails before it reaches main.

---

## Known limitations

Stated plainly, because a governance tool that hides its own gaps isn't trustworthy:

- **Pattern-based detection can be evaded by obfuscation.** Outside of Terraform plan JSON and Kubernetes manifests (which are now parsed structurally), signal matching is regex over the payload string. Commands fragmented across multiple actions in the same session (e.g. `curl ...` then `| bash` as two separate calls) are now caught via session-level payload correlation -- the last 5 payloads in a session are checked jointly against the hard-block patterns, in both the MCP server and the REST API. This closes the most common fragmentation pattern but is not exhaustive: broader semantic parsing of multi-step attack chains is still on the roadmap.
- **Semantic parsing covers Terraform and Kubernetes only.** Helm values, Pulumi, CloudFormation, and other IaC formats are still evaluated via regex signals, not structural parsing.
- **MCP authentication is a shared bearer token**, not per-agent or per-user identity (see "Connect via remote MCP" above). The REST API now supports scoping a credential to a single `agent_id` (set at credential-creation time); a request whose declared `agent_id` doesn't match the credential's bound agent is rejected with 403. This is opt-in per credential -- the default remains an org-wide token, and the MCP server itself still uses a single shared token.
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
- [x] Persistent audit trail (Supabase-backed, survives redeploys — previously write-only to a sandbox log, never reachable from the live API)
- [ ] Session-level payload correlation (close the obfuscation/fragmentation gap above)
- [ ] PyPI package + CLI (`pip install devmind-agent`, `devmind serve`)
- [ ] GitHub Action (`devmind-action`) — intercept agent PRs in CI/CD pipelines
- [ ] Kubernetes Admission Webhook — `infra_engine` enforced at the cluster level
- [x] Session-level payload correlation (fragmented hard-block detection)
- [ ] Per-agent MCP identity (beyond the current shared bearer token) -- REST API has opt-in per-agent credential scoping; MCP server still shared-token only
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