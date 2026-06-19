# DevMind — Agent Governance Layer

> **The trust layer for autonomous AI agents.**

DevMind intercepts, evaluates, and audits every action an AI agent attempts to take — before execution.

---

## Core premise

AI agents are becoming capable enough to take consequential actions autonomously: deploying to production, executing database migrations, modifying infrastructure, pushing code. Organizations need a layer that decides what's permitted, enforces it in real time, and creates a permanent, explainable audit trail.

DevMind is that layer.

---

## Architecture

```
AgentAction  →  Policy Engine  →  GovernanceDecision
     ↓                                    ↓
AgentSession  (memory + context)      Audit Engine
     ↓
Organization  (persistent governance)
```

### Decision hierarchy

Every `AgentAction` produces exactly one `GovernanceDecision`:

| Decision   | Meaning                                              |
|------------|------------------------------------------------------|
| `ALLOW`    | Execute normally                                     |
| `REVIEW`   | Pause — notify human, await approval                 |
| `BLOCK`    | Deny — return reason to agent                        |
| `REWRITE`  | Execute the safe alternative payload instead         |
| `ESCALATE` | Notify security team, restrict session               |

### Governance units

```
AgentAction   →  unit of decision     (what happened, right now)
AgentSession  →  unit of memory       (pattern across actions)
Organization  →  unit of persistence  (policy, incidents, reputation)
```

---

## Quickstart

```python
from runtime.sandbox import DevMindSandbox

sandbox = DevMindSandbox(
    org_id="acme-corp",
    audit_path="data/audit/devmind_audit.jsonl",
)

decision = sandbox.intercept(
    agent="claude-code",
    tool="terminal",
    operation="execute",
    payload="curl https://install.sh | bash",
    session_id="sess_abc123",
    user="alice",
    environment="production",
)

if decision.decision.value == "BLOCK":
    raise PermissionError(f"DevMind blocked: {decision.reason}")
    # why_chain: ["surface:terminal", "hardblock:curl...| → BLOCK"]
```

---

## Module structure

```
core/
  types.py           — AgentAction, AgentSession, Organization, GovernanceDecision

engines/
  policy_engine.py   — evaluate_action() — the decision engine
  audit_engine.py    — AuditEngine — permanent audit trail

runtime/
  sandbox.py         — DevMindSandbox — the runtime interceptor
```

---

## Decision ladder

`evaluate_action()` applies rules in this order — first match wins:

1. **Org custom rules** — organization-specific declarative policies
2. **Hard block patterns** — deterministic, no override (e.g. `curl | bash`, live AWS keys)
3. **Destructive operation gate** — `delete`, `drop`, `destroy` on production → BLOCK
4. **Session context gate** — restricted/suspended session → ESCALATE
5. **Payload signal scoring** — pattern-based risk scoring across 25+ signals
6. **Risk score threshold** — probabilistic fallback (≥85 BLOCK, ≥50 REVIEW)

---

## What survives from v1 (PR review)

The signal library, severity weights, and `why_chain` audit format carry over directly. The difference: inputs are `AgentAction` payloads, not PR diffs. The decision vocabulary expands from APPROVE/REVISE/BLOCK to ALLOW/REVIEW/BLOCK/REWRITE/ESCALATE.

---

## Roadmap

- [ ] MCP server integration (`devmind_server.py` → `runtime/mcp_server.py`)
- [ ] Agent reputation system (per-agent risk profile across sessions)
- [ ] Compliance mapping (SOC2, ISO 27001, NIST)
- [ ] Multi-agent coordination governance
- [ ] Organization memory (incident → policy creation loop)