"""
Synthetic SRE traffic stress test for the allowlist (shadow mode).

NOT a replacement for real usage data -- allowlist_shadow_log has only
8 rows in Supabase as of today, and all 8 are the founder's own
smoke-test commands from earlier sessions (rm -rf /, DROP TABLE
customers, echo verification strings), not real SRE traffic. This
script exists to surface obvious allowlist gaps *before* a real user
hits them, using a broader, more realistic corpus than what exists
today -- it deliberately does NOT write to the real
allowlist_shadow_log table, to keep that table's future counts a
clean signal of real usage only.

Runs each command through the REAL policy engine (GovernedSandbox,
same code path devmind_server.py uses) in one continuous session, the
same way a real SRE's incident-response session would accumulate
state -- not isolated one-off calls. LLM escalation is disabled
(deterministic layer only), matching what the shadow-log comparison
already measures.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from runtime.backend_connector import GovernedSandbox
from engines.allowlist import is_allowlisted


# =============================================================================
# Corpus: realistic SRE commands across a real incident-response session.
# Organized by intent, not just by allowlist category, since a real
# gap often looks like "same verb, unexpected shape" (sudo prefix,
# extra flags, piped output) rather than a wholly different command.
# =============================================================================

CORPUS = [
    # --- Diagnostic investigation: exact allowlist matches ---
    ("kubectl get pods -n production", "diagnostic"),
    ("kubectl describe pod payments-api-7d9f8-x2k1p -n production", "diagnostic"),
    ("kubectl logs payments-api-7d9f8-x2k1p -n production --tail=200", "diagnostic"),
    ("systemctl status nginx", "diagnostic"),
    ("journalctl -u nginx --since '10 minutes ago'", "diagnostic"),
    ("docker ps -a", "diagnostic"),
    ("docker logs api-gateway --tail 500", "diagnostic"),
    ("git log --oneline -20", "diagnostic"),
    ("git diff HEAD~1", "diagnostic"),
    ("git status", "diagnostic"),
    ("terraform plan -out=tfplan", "diagnostic"),
    ("terraform show tfplan", "diagnostic"),
    ("dig api.internal.example.com", "diagnostic"),
    ("ping -c 4 10.0.4.12", "diagnostic"),
    ("curl -I https://api.example.com/healthz", "diagnostic"),
    ("helm list -n production", "diagnostic"),
    ("helm status payments-api -n production", "diagnostic"),
    ("aws s3 ls s3://prod-backups/", "diagnostic"),
    ("aws ec2 describe-instances --filters 'Name=tag:env,Values=prod'", "diagnostic"),
    ("ps aux | grep nginx", "diagnostic (has pipe -- chain operator)"),
    ("df -h", "diagnostic"),
    ("du -sh /var/log/*", "diagnostic"),
    ("tail -f /var/log/nginx/error.log", "diagnostic"),
    ("cat /etc/nginx/nginx.conf", "diagnostic"),

    # --- Approved remediation: exact matches ---
    ("systemctl restart nginx", "remediation"),
    ("kubectl rollout restart deployment/payments-api -n production", "remediation"),
    ("git pull origin main", "remediation"),
    ("git fetch --all", "remediation"),
    ("docker restart api-gateway", "remediation"),

    # --- Capacity / SLO ---
    ("free -h", "capacity"),
    ("top -bn1", "capacity"),
    ("vmstat 1 5", "capacity"),
    ("iostat -x 1 3", "capacity"),
    ("nproc", "capacity"),

    # --- Realistic near-misses: same intent, unexpected shape ---
    ("sudo systemctl restart nginx", "near-miss: sudo prefix defeats the prefix match"),
    ("sudo kubectl get pods -n production", "near-miss: sudo prefix"),
    ("kubectl get pods --all-namespaces -o wide", "near-miss: different flags, same verb"),
    ("KUBECONFIG=/home/sre/.kube/prod-config kubectl get pods", "near-miss: env var prefix"),
    ("cd /var/log && tail -100 nginx/error.log", "near-miss: chained with &&"),
    ("watch -n 2 kubectl get pods -n production", "near-miss: wrapped in watch"),
    ("time terraform plan", "near-miss: wrapped in time"),
    ("git --no-pager log -20", "near-miss: --no-pager flag before subcommand"),
    ("systemctl restart nginx.service", "near-miss: explicit .service suffix"),
    ("kubectl -n production get pods", "near-miss: -n before get, not after"),

    # --- Genuinely destructive: should NOT be allowlisted, and should
    # still hard-block or review under the real policy engine ---
    ("kubectl delete namespace production", "destructive"),
    ("terraform destroy -auto-approve", "destructive"),
    ("rm -rf /var/lib/postgresql/data", "destructive"),
    ("DROP TABLE payments CASCADE", "destructive"),
    ("git push --force origin main", "destructive"),
    ("aws s3 rm s3://prod-backups/ --recursive", "destructive"),
    ("kubectl exec -it payments-db -- psql -c 'TRUNCATE users'", "destructive"),
    ("chmod -R 777 /etc", "destructive"),
    ("iptables -F", "destructive"),

    # --- Ambiguous / plausible-but-unlisted: legitimate SRE work that
    # currently isn't in any allowlist category, a real signal for
    # what might be worth adding later ---
    ("kubectl scale deployment/payments-api --replicas=5 -n production", "unlisted: scaling"),
    ("kubectl rollout undo deployment/payments-api -n production", "unlisted: rollback"),
    ("kubectl cordon node-7", "unlisted: node maintenance"),
    ("kubectl drain node-7 --ignore-daemonsets", "unlisted: node maintenance"),
    ("aws ecs update-service --cluster prod --service api --desired-count 3", "unlisted: ecs scaling"),
    ("systemctl daemon-reload", "unlisted: config reload"),
    ("nginx -s reload", "unlisted: config reload"),
    ("crontab -l", "unlisted: read-only, but not in DIAGNOSTIC list"),
    ("netstat -tulpn", "unlisted: read-only network inspection"),
    ("ss -tulpn", "unlisted: modern netstat equivalent"),
    ("kubectl top pods -n production", "unlisted: read-only but not CAPACITY_SLO"),
    ("kubectl top nodes", "unlisted: read-only but not CAPACITY_SLO"),
    ("helm upgrade payments-api ./chart -n production", "unlisted: deploy action"),
    ("terraform apply tfplan", "unlisted: applying a plan, distinct from terraform plan"),
    ("docker exec -it api-gateway sh", "unlisted: interactive shell into container"),
]


def run_corpus(sandbox, shared_session: bool) -> list[dict]:
    rows = []
    for i, (command, label) in enumerate(CORPUS):
        session_id = "synthetic-incident-session-1" if shared_session else f"synthetic-isolated-{i}"
        decision = sandbox.intercept(
            agent="synthetic-sre-session",
            tool="terminal",
            operation="execute",
            payload=command,
            session_id=session_id,
            environment="production",
            extra_context={"rationale": "synthetic stress test"},
        )
        allowlist_allowed, allowlist_reason = is_allowlisted(command)
        blocklist_decision_name = getattr(decision.decision, "name", str(decision.decision))
        agreement = "AGREE" if (allowlist_allowed == (blocklist_decision_name == "ALLOW")) else "DISAGREE"
        rows.append({
            "command": command,
            "label": label,
            "blocklist": blocklist_decision_name,
            "allowlist_allowed": allowlist_allowed,
            "allowlist_reason": allowlist_reason,
            "agreement": agreement,
            "risk_score": decision.risk_score,
        })
    return rows


def report(rows: list[dict], heading: str) -> None:
    total = len(rows)
    agree = sum(1 for r in rows if r["agreement"] == "AGREE")
    disagree = [r for r in rows if r["agreement"] == "DISAGREE"]

    print(f"\n{'='*100}")
    print(f"{heading}")
    print(f"TOTAL: {total} commands | AGREE: {agree} ({100*agree/total:.1f}%) | DISAGREE: {len(disagree)}")
    print(f"{'='*100}\n")

    print("--- DISAGREEMENTS ---\n")
    for r in disagree:
        print(f"[{r['label']}]")
        print(f"  command:    {r['command']}")
        print(f"  blocklist:  {r['blocklist']} (risk_score={r['risk_score']})")
        print(f"  allowlist:  {'ALLOW' if r['allowlist_allowed'] else 'REVIEW'} ({r['allowlist_reason']})")
        print()

    print("--- destructive commands: confirm blocklist still catches them ---\n")
    for r in rows:
        if r["label"] == "destructive":
            flag = "OK" if r["blocklist"] in ("BLOCK", "ESCALATE", "REVIEW") else "!!PROBLEM!!"
            print(f"  [{flag}] {r['command']!r:60s} -> {r['blocklist']} (score={r['risk_score']})")

    print("\n--- unlisted-but-plausible: candidates for new allowlist entries ---\n")
    for r in rows:
        if r["label"].startswith("unlisted"):
            print(f"  {r['command']!r:70s} -> blocklist={r['blocklist']:8s} allowlist_reason={r['allowlist_reason']}")


def main() -> None:
    sandbox = GovernedSandbox(
        org_id="synthetic-stress-test",
        audit_path="/tmp/synthetic_stress_audit.jsonl",
        audit_engine=None,
        llm_enabled=False,
    )

    isolated_rows = run_corpus(sandbox, shared_session=False)
    report(isolated_rows, "PASS 1: ISOLATED SESSION PER COMMAND (baseline classification, no session-escalation effects)")

    shared_rows = run_corpus(sandbox, shared_session=True)
    report(shared_rows, "PASS 2: ONE SHARED SESSION FOR ALL 68 COMMANDS (mimics a real chaotic incident-response session)")

    print(f"\n{'='*100}")
    print("PASS 1 vs PASS 2 verdict deltas (same command, different session history)")
    print(f"{'='*100}\n")
    for r1, r2 in zip(isolated_rows, shared_rows):
        if r1["blocklist"] != r2["blocklist"]:
            print(f"  {r1['command']!r:70s} isolated={r1['blocklist']:8s} shared={r2['blocklist']}")


if __name__ == "__main__":
    main()
