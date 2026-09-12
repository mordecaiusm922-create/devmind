# DevMind — Compliance Crosswalk

Status: internal reference / sales material. This is NOT a certification,
an audit opinion, or legal advice. It maps DevMind's existing, shipped
features to the compliance frameworks enterprise buyers most often ask
about for AI agent tooling, so those conversations start from evidence
instead of a blank page.

DevMind is not SOC2 or ISO 42001 certified. Certification is an
auditor-driven process with a real cost and a months-long observation
window (SOC2 Type II typically 6-12 months) -- pursuing it only makes
sense once a real customer's procurement process requires it. What
follows is the control mapping that certification work would start
from, kept accurate to the actual codebase rather than aspirational.

## Why this mapping exists

Enterprise buyers evaluating AI agent tooling in 2026 increasingly
reference the same handful of frameworks by name during procurement:
NIST AI RMF, SOC 2 (via the AICPA Trust Services Criteria), ISO/IEC
42001, and -- for EU-facing deployments -- the EU AI Act. None of them
certify a specific product; they describe *what a program needs to be
able to show*. DevMind's actual value to a buyer going through that
process is that several of the hardest-to-satisfy controls are already
built into the product, not bolted on afterward.

## The mapping

| Framework control | What it requires | DevMind feature | Where in the code |
|---|---|---|---|
| SOC 2 CC6 (logical access) | Every link in a delegated-authority chain (user -> agent -> tool -> resource) must be independently identifiable and reviewable -- the control family auditors find hardest to map onto agentic systems, since access isn't a single user-to-resource decision anymore | Per-agent bearer tokens scoped to an organization (`api_credentials`), governance sessions scoped to the authenticated caller rather than shared across every user of a server process | `devmind_server.py::SupabaseTokenVerifier`, `_resolve_session_id()` |
| SOC 2 CC7.3 / CC7.5 (incident detection & communication) | Documented detection of anomalous activity, with a defined communication path | Hard-block and critical-signal detection with real-time Slack notification, both for actions blocked outright and for break-glass overrides | `engines/policy_engine.py::SIGNALS`, `_send_slack_block_notification()` |
| SOC 2 CC9 (risk treatment / response) | A defined, evidenced process for responding to and recording elevated-risk events | Break-glass override: requires an explicit justification, is logged to a dedicated table with maximum audit severity, and can be prohibited per-organization | `break_glass_log`, `_log_break_glass_override()`, `_is_break_glass_prohibited_for_org()` |
| NIST AI RMF MANAGE-4.1 (post-deployment monitoring & incident investigation) | Complete, tamper-evident logs of tool calls and decision points | Durable audit trail of every governed action and its verdict, independent of the human-review/break-glass logs above | `audit_records` (via `engines/audit_engine.py`) |
| NIST AI RMF human-in-the-loop checkpoints | Mandatory human confirmation for high-risk or irreversible actions | REVIEW verdicts route to a named human via Slack (Approve/Reject), bound to the exact command text so an approval can't be reused for a different action | `review_requests`, `_check_review_approval()` |
| NIST AI RMF GOVERN 6.1 (accountability lines) | Explicit ownership for AI decisions, not diffused between teams | Org-level policy control: an organization can prohibit break-glass entirely, independent of what any individual agent or operator requests | `organizations.break_glass_prohibited` |
| ISO/IEC 42001 (AI management system, Clause 10.2 nonconformity & corrective action) | A record of what went wrong and what was done about it | Every BLOCK, REVIEW, and override decision carries a `why_chain` -- the reasoning steps that produced it, not just the verdict | `core/types.py::GovernanceDecision.why_chain` |

## What this table does not claim

- It does not claim DevMind satisfies any framework's control in full --
  most controls also require organizational process (documented
  ownership, incident response runbooks, periodic review) that no
  software provides by itself.
- It does not cover model-level governance (bias, explainability,
  training-data lineage) -- SOC 2 explicitly does not certify this
  either; it is the layer ISO 42001 and the NIST AI 600-1 Generative AI
  Profile exist to cover, and is out of scope for what DevMind does
  (governing agent *actions*, not model behavior).
- It does not cover the EU AI Act's Annex III high-risk-system
  obligations, which apply to specific AI use cases (e.g. biometric
  identification, credit scoring) that DevMind's target use case
  (infrastructure/SRE agent governance) does not fall under as
  currently understood -- worth re-checking if a customer's specific
  deployment changes that.

## Practical use

For a prospect's security/compliance review: this table is the answer
to "how does DevMind support our SOC 2 / NIST AI RMF program" --
point to the specific table/function for each control rather than a
general claim. For an internal roadmap signal: any control row without
a durable-storage backing (Supabase table) today is weaker evidence
than one with it, and is a reasonable prioritization signal for what
to harden next as real customers start asking.
