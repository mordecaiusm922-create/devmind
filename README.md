# DevMind — Runtime Governance for Autonomous AI Agents

> **The control plane that sits between an agent's decision and your production systems.**

DevMind intercepts, evaluates, and audits every action an AI agent attempts to take — before it executes. Deterministic policy engine. No LLM in the decision path. Sub-50ms response time.

**Live API:** [devmind-2cej.onrender.com/health](https://devmind-2cej.onrender.com/health)
**Live MCP server:** [devmind-mcp.onrender.com/mcp](https://devmind-mcp.onrender.com/mcp)
**178 invariant tests passing · CI green on every push**

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
  SessionAudit  ──▶ │   Release Gate       │ ──▶ GovernanceDecision
  + ArtifactScan    │   release_gate.py    │
                    └─────────────────────┘

  AgentSession  →  unit of memory       (pattern across actions in a session)
  Organization  →  unit of persistence  (policy, incident history, reputation)
```

Three engines, one decision contract. `AgentAction` (tool calls — terminal, filesystem, database, cloud) routes through the **policy engine**. `AgentChange` (Terraform applies, K8s manifests, Helm releases) routes through the **infra engine**, which evaluates blast radius before anything else. Session-level release decisions route through the **release gate**, which weighs accumulated session risk at 70%.

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

## Connect via remote MCP (no local install required)

DevMind runs as a remote MCP server. Any MCP-compatible agent — Claude Desktop, Cursor, or any client supporting the Model Context Protocol — can connect directly over HTTP, with no local Python setup.

**Live MCP endpoint:** `https://devmind-mcp.onrender.com/mcp`

### Claude Desktop

Add to your MCP settings (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "devmind": {
      "url": "https://devmind-mcp.onrender.com/mcp",
      "transport": "streamable-http"
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
      "url": "https://devmind-mcp.onrender.com/mcp"
    }
  }
}
```

Once connected, every `execute_command`, `write_file`, `delete_file`, `git_operation`, `http_request`, `db_query`, and `deploy` call your agent makes is evaluated by DevMind's policy engine before execution. `session_status` lets you inspect the current session's accumulated risk profile at any point.

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

---

## Live API (HTTP)

Deployed at [`devmind-2cej.onrender.com`](https://devmind-2cej.onrender.com), running the exact engine in this repo. Useful for CI pipelines, scripts, or anything that isn't an MCP client.

| Endpoint            | Method | Purpose                                                |
|----------------------|--------|---------------------------------------------------------|
| `/health`            | GET    | Liveness check                                          |
| `/evaluate`          | POST   | Evaluate an `AgentAction` (tool call) via policy engine  |
| `/evaluate-change`   | POST   | Evaluate an `AgentChange` (Terraform/K8s/Helm) via infra engine |
| `/release-gate`      | POST   | Evaluate a session + artifact scan via release gate       |
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
```

Both return in well under 100ms — deterministic Python running in-process, not an LLM call.

---

## Quickstart (local)

```bash
git clone https://github.com/mordecaiusm922-create/devmind
cd devmind
pip install -r requirements.txt
python -m pytest tests/ -v          # 178 tests, deterministic, no mocks
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
  release_gate.py      — evaluate_release() — session + artifact release governance
  audit_engine.py       — permanent, structured decision log

tests/
  test_policy_engine.py
  test_infra_engine.py
  test_release_gate.py  — 178 invariant tests total

api.py                  — FastAPI wrapper exposing all three engines over HTTP
devmind_server.py        — MCP server exposing DevMind as agent-callable tools
simulate_real_risks.py  — 28 real-world scenarios across fintech, healthcare,
                           SaaS, infrastructure, and supply chain
```

---

## Decision ladder — infra engine

`evaluate_change()` applies rules in this order — first decisive match wins:

1. **Hard blocks** — deterministic, no override. IAM wildcards, hardcoded secrets, public S3 buckets, open security groups, privileged containers, `hostNetwork`/`hostPID`, cluster-admin bindings.
2. **Blast radius gate** — `ORG` or `ACCOUNT` scope → `ESCALATE`, unconditionally. This is the invariant that would have caught PocketOS.
3. **Production escalation** — a critical signal plus `affects_production=True` → `BLOCK`.
4. **Signal-based risk scoring** — 25+ weighted regex signals across Terraform, Kubernetes, and generic surfaces.
5. **Risk threshold decision** — probabilistic fallback when no hard rule fires (≥85 `BLOCK`, ≥50 `REVIEW`).

The policy engine (`policy_engine.py`) mirrors this ordering for tool-call actions, with its own signal library for terminal, filesystem, database, and cloud surfaces.

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

178 tests, zero mocks on the decision logic itself. If someone weakens an invariant, CI fails before it reaches main.

---

## What DevMind is not

- Not an LLM wrapper — the decision engine is deterministic Python, not a model call.
- Not a static scanner — it evaluates actions at the moment of intent, before execution.
- Not a generic firewall — it understands agent-specific surfaces: terminal, filesystem, database, cloud, Terraform, Kubernetes, Helm, releases.

---

## Roadmap

- [x] Remote MCP server (`devmind-mcp.onrender.com`)
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