from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field

from evaluate import evaluate_payload
from policy import PolicyEngine
from verify import verify_sql_semantics

policy_engine = PolicyEngine()

class CandidatePayload(BaseModel):
    id: str | None = None
    diff: str = ""
    strategy: str = ""
    explanation: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class SafetyFlowRequest(BaseModel):
    prompt: str
    candidates: list[CandidatePayload] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)
    mode: str = "secure"
    intent: dict[str, Any] = Field(default_factory=dict)
    evidence: dict[str, Any] = Field(default_factory=dict)
    history: list[dict[str, Any]] = Field(default_factory=list)
    files: list[dict[str, Any]] = Field(default_factory=list)
    repo: str | None = None
    properties: list[str] = Field(default_factory=list)
    n_candidates: int = 3
    max_repair_attempts: int = 1


_SECRET_ASSIGN_RE = re.compile(
    r"(?im)^\+?\s*(SECRET_KEY|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY)\s*=\s*['\"][^'\"]{8,}['\"]"
)
_ENV_READ_RE = re.compile(r"\b(os\.environ(?:\.get)?|os\.getenv|environ\.get)\b")
_FAIL_FAST_RE = re.compile(r"\braise\s+\w*error\b|\bassert\s+", re.IGNORECASE)
_PARAM_SQL_RE = re.compile(r"execute\s*\([^,\n]+,\s*(\[|\(|\{)", re.IGNORECASE)
_UNSAFE_SQL_RE = re.compile(r"execute\s*\([^,\n]*(\+|%|\.format\(|f['\"])", re.IGNORECASE)
_AUTH_GUARD_RE = re.compile(
    r"(?im)^\+\s*(if\s+not\s+.*?(policy\.|can_|authorize|has_permission|is_admin)|@\w*permission\w*|@\w*login_required)"
)
_REMOVED_AUTH_RE = re.compile(
    r"(?im)^-\s*(if|raise|return).*?(is_admin|permission|authorize|can_|policy|rbac)"
)
_DIFF_FILE_RE = re.compile(r"^diff --git a/(?P<left>\S+) b/(?P<right>\S+)", re.MULTILINE)

_CRITICAL_RULES: tuple[dict[str, Any], ...] = (
    {"id": "hardcoded_secret", "surface": "secrets", "severity": "critical", "property": "no_hardcoded_secret", "pattern": r"(api[_-]?key|secret[_-]?key|password|token|private[_-]?key)\s*=\s*['\"][^'\"]{8,}"},
    {"id": "env_secret_committed", "surface": "secrets", "severity": "critical", "property": "no_hardcoded_secret", "pattern": r"\.env|database_url\s*=|db_password\s*=|sendgrid|twilio|slack[_-]?token|discord[_-]?token"},
    {"id": "private_key_committed", "surface": "secrets", "severity": "critical", "property": "no_hardcoded_secret", "pattern": r"-----begin (rsa |openssh |ec )?private key-----|ssl.*private.*key"},
    {"id": "cloud_credentials", "surface": "secrets", "severity": "critical", "property": "no_hardcoded_secret", "pattern": r"aws_access_key_id|aws_secret_access_key|akia[0-9a-z]{12,}|oauth.*client_secret"},
    {"id": "frontend_secret", "surface": "secrets", "severity": "high", "property": "no_hardcoded_secret", "pattern": r"(frontend|public|vite|react).*client_secret|next_public_.*secret"},
    {"id": "auth_guard_removed", "surface": "auth", "severity": "critical", "property": "auth_guard_present", "pattern": r"^-\s*@?(require_auth|login_required|requires_permission|permission_required)|^-\s*if\s+not\s+.*(authorize|permission|is_admin|owner)"},
    {"id": "ownership_missing", "surface": "auth", "severity": "high", "property": "auth_guard_present", "pattern": r"(skip_ownership|without_ownership|owner_check\s*=\s*false|resource\.owner_id\s*!=)"},
    {"id": "role_bypass", "surface": "auth", "severity": "critical", "property": "fail_closed", "pattern": r"(is_admin\s*=\s*true|role\s*=\s*['\"]admin|bypass.*role|mfa_enabled\s*=\s*false|cors.*\*)"},
    {"id": "jwt_algorithm_confusion", "surface": "auth", "severity": "critical", "property": "fail_closed", "pattern": r"verify_signature\s*=\s*false|algorithms\s*=\s*\[\s*['\"]none|jwt.*algorithm.*none"},
    {"id": "session_cookie_unsafe", "surface": "auth", "severity": "high", "property": "fail_closed", "pattern": r"httponly\s*=\s*false|secure\s*=\s*false|session.*max_age\s*=\s*none|oauth.*state\s*=\s*none|reset.*rate_limit\s*=\s*none"},
    {"id": "sql_injection", "surface": "data", "severity": "critical", "property": "parameterized_sql", "pattern": r"execute\s*\([^,\n]*(\+|%|\.format\(|f['\"])|select .* where .* \+|sql\s*=\s*f['\"]"},
    {"id": "command_injection", "surface": "runtime", "severity": "critical", "property": "runtime_safety_policy", "pattern": r"(os\.system|subprocess\.(call|run|popen)).*(request|input|args|shell\s*=\s*true)|curl\s+\{.*\}\s*\|\s*bash"},
    {"id": "xss_or_template_injection", "surface": "runtime", "severity": "high", "property": "runtime_safety_policy", "pattern": r"innerhtml|dangerouslysetinnerhtml|mark_safe|safe\s*\|.*user|render_template_string|template.*\+.*request"},
    {"id": "unsafe_parser_or_deserialization", "surface": "runtime", "severity": "critical", "property": "runtime_safety_policy", "pattern": r"pickle\.loads|yaml\.load\(|xxe|external_entities\s*=\s*true|ldap.*\+.*request|path.*\.\./|read_file\(.*request"},
    {"id": "nosql_injection", "surface": "data", "severity": "high", "property": "data_safety_policy", "pattern": r"\$where|mongo.*request\.|find_one\(request\.json|query\s*=\s*req\.json"},
    {"id": "public_cloud_resource", "surface": "infra", "severity": "critical", "property": "least_privilege_infra", "pattern": r"acl\s*=\s*['\"]public-read|public_access\s*=\s*true|0\.0\.0\.0/0|publicly_accessible\s*=\s*true"},
    {"id": "iam_wildcard", "surface": "infra", "severity": "critical", "property": "least_privilege_infra", "pattern": r"actions?\s*=\s*\[\s*['\"]\*['\"]|action\s*=\s*['\"]\*['\"]|resource\s*=\s*['\"]\*['\"]|\*:\*"},
    {"id": "privileged_container", "surface": "infra", "severity": "critical", "property": "least_privilege_infra", "pattern": r"privileged\s*:\s*true|runAsUser\s*:\s*0|allowPrivilegeEscalation\s*:\s*true"},
    {"id": "unsafe_infra_config", "surface": "infra", "severity": "high", "property": "least_privilege_infra", "pattern": r"image:\s*[^:\s]+:latest|from\s+\S+:latest|backup.*false|skip_final_snapshot\s*=\s*true|max_size\s*=\s*0|ssl_policy\s*=\s*none|tls\s*=\s*false|secretkeyref|encryption.*false"},
    {"id": "ci_untrusted_secret_access", "surface": "ci_cd", "severity": "critical", "property": "no_untrusted_secret_access", "pattern": r"pull_request_target[\s\S]{0,300}(secrets\.|github_token|permissions:\s*write-all)|workflow_run[\s\S]{0,300}(secrets\.|github_token)"},
    {"id": "ci_supply_chain", "surface": "ci_cd", "severity": "high", "property": "safe_ci_supply_chain", "pattern": r"curl .*\|.*bash|uses:\s*[\w.-]+/[\w.-]+@(main|master|latest)|skip[_-]?tests\s*=\s*true|npm install .*github\.com|echo .*secrets\.|unsigned|signature.*false|source.*curl"},
    {"id": "dependency_cve", "surface": "dependencies", "severity": "critical", "property": "dependency_policy", "pattern": r"cve-\d{4}-\d+|critical vulnerability|malicious package|postinstall.*curl|typosquat"},
    {"id": "dependency_unpinned_or_risky", "surface": "dependencies", "severity": "medium", "property": "dependency_policy", "pattern": r"==\s*\*|version\s*=\s*['\"]latest|:\s*['\"]latest['\"]|from git\+|last_commit.*3 years|license.*gpl|install.*http request|process\.env.*import"},
    {"id": "destructive_migration", "surface": "data", "severity": "critical", "property": "data_safety_policy", "pattern": r"drop column|drop table|remove_index|drop_index|delete from .*users|foreign_key.*false"},
    {"id": "data_leak_or_dos", "surface": "data", "severity": "high", "property": "data_safety_policy", "pattern": r"console\.log\(.*password|logger\..*(ssn|password|token)|select \*|return user\.__dict__|pagination\s*=\s*false|limit\s*=\s*none|deleted_at.*filter.*removed|production.*development|backup.*public|backup.*encryption.*false|n_plus_one|for .* in .*:.*query"},
    {"id": "runtime_regression", "surface": "runtime", "severity": "high", "property": "runtime_safety_policy", "pattern": r"timeout\s*=\s*0|while true|retry.*while|backoff\s*=\s*false|cache\.invalidate.*removed|traceback\.format_exc\(\)|debug\s*=\s*true|healthcheck|except exception:\s*pass|rollback\s*=\s*none|react2shell|react server components"},
    {"id": "concurrency_financial_risk", "surface": "runtime", "severity": "critical", "property": "runtime_safety_policy", "pattern": r"charge\(|transfer\(|payment[\s\S]{0,120}(no_lock|without_lock|thread|race)|lock.*removed"},
    {"id": "ai_execution_risk", "surface": "ai", "severity": "critical", "property": "ai_safety_policy", "pattern": r"llm.*(exec|eval|subprocess|database)|prompt injection|tool_call.*no_sandbox|langflow.*cve|rce"},
    {"id": "ai_data_or_cost_risk", "surface": "ai", "severity": "high", "property": "ai_safety_policy", "pattern": r"math\.random\(\).*token|token.*math\.random\(\)|embeddings.*pii|production_pii|train_model\(.*pii|fine[_-]?tune.*secret|rate_limit\s*=\s*none|llm.*innerhtml|staging.*ai.*auth\s*=\s*false"},
    {"id": "insider_or_process_risk", "surface": "human", "severity": "high", "property": "human_review_policy", "pattern": r"branch_protection\s*=\s*false|direct push to main|self[-_ ]approved|audit.*logs.*removed|prod.*config.*laptop|shared credentials|service_account.*admin|employee.*departure|zero[-_ ]day|justified secret access\s*=\s*false|secret access.*false"},
)
_COMPILED_CRITICAL_RULES = [
    {**rule, "regex": re.compile(str(rule["pattern"]), re.IGNORECASE | re.MULTILINE)}
    for rule in _CRITICAL_RULES
]
_SEVERITY_RISK = {"critical": 0.90, "high": 0.76, "medium": 0.56, "low": 0.32}


def run_safety_flow(req: SafetyFlowRequest) -> dict[str, Any]:
    candidates = [_candidate_to_dict(c, i) for i, c in enumerate(req.candidates)]
    prior_data: dict[str, Any] = {}
    if req.repo:
        try:
            from memory import get_prior_for_prompt
            prior_data = get_prior_for_prompt(req.repo, req.prompt)
        except Exception:
            pass
    if not candidates:
        candidates = _generate_candidates(req.prompt, req.context, req.n_candidates)

    representation = _build_change_representation(req, candidates, prior_data)

    payload = {
        "prompt": req.prompt,
        "candidates": candidates,
        "context": req.context,
        "mode": req.mode,
        "intent": req.intent or _infer_intent(req.prompt, req.context),
        "evidence": req.evidence,
        "history": req.history,
        "files": req.files,
        "repo": req.repo,
    }
    properties = _infer_properties(req.prompt, req.context, req.properties, representation)
    evaluation = evaluate_payload(payload)["evaluation"]

    verifications = {
        candidate["id"]: _verify_candidate(candidate, properties)
        for candidate in candidates
    }
    runtime_evidence = {
        candidate["id"]: _runtime_evidence(candidate, properties, representation)
        for candidate in candidates
    }

    repair_candidates: list[dict[str, Any]] = []
    if req.max_repair_attempts > 0:
        repair_candidates = _repair_candidates(candidates, verifications, properties, req.context)
        if repair_candidates:
            candidates = candidates + repair_candidates
            payload["candidates"] = candidates
            representation = _build_change_representation(req, candidates, prior_data)
            evaluation = evaluate_payload(payload)["evaluation"]
            verifications = {
                candidate["id"]: _verify_candidate(candidate, properties)
                for candidate in candidates
            }
            runtime_evidence = {
                candidate["id"]: _runtime_evidence(candidate, properties, representation)
                for candidate in candidates
            }

    ranking = _rank_candidates(evaluation["scores"], verifications, runtime_evidence, prior_data, representation, candidates)
    selected = ranking[0] if ranking else None
    repair_iterations = _repair_iteration_deltas(repair_candidates, evaluation, verifications)
    repair_converged = _repair_converged(repair_candidates, selected, verifications)
    evaluation["repair_iterations"] = len(repair_iterations)
    evaluation["repair_iteration_deltas"] = repair_iterations
    evaluation["repair_converged"] = repair_converged
    evaluation["selected_delta"] = _selected_delta(selected, evaluation)
    decision = _final_decision(req.mode, selected, evaluation, representation)
    operational_metrics = _operational_metrics(ranking, verifications, runtime_evidence, evaluation)
    risk = _safety_flow_risk(representation, selected, decision)
    if req.repo:
        risk = _calibrate_risk(req.repo, risk)
    deployment_policy = _deployment_policy(req.mode, representation, runtime_evidence, risk, selected)
    decision, risk = _apply_deployment_policy(decision, risk, deployment_policy)
    record = _record_flow_result(req, selected, decision, representation, operational_metrics, risk)

    return {
        "flow": [
            "observe",
            "retrieve",
            "generate",
            "score",
            "verify",
            "repair",
            "risk_adjust",
            "rank",
            "decide",
            "record",
        ],
        "policy": {
            "objective": "maximize risk_adjusted_utility",
            "formula": "utility + prior_adjustment - blast_radius_penalty - 0.14*violations - 0.25*critical_violations - 0.08*uncertainty + 0.04*verified",
            "security_gate": "critical violations cannot be approved",
            "critical_mode_gate": "secure/robust/critical modes require verification",
        },
        "generated": len(req.candidates) == 0,
        "repair_attempted": bool(repair_candidates),
        "repair_converged": repair_converged,
        "repair_iterations": repair_iterations,
        "representation": representation,
        "properties": properties,
        "candidates": candidates,
        "evaluation": evaluation,
        "verification": verifications,
        "runtime_evidence": runtime_evidence,
        "ranking": ranking,
        "selected": selected,
        "decision": decision,
        "deployment_policy": deployment_policy,
        "risk": risk,
        "operational_metrics": operational_metrics,
        "prior": prior_data,
        "recorded": record,
    }


def _candidate_to_dict(candidate: CandidatePayload, idx: int) -> dict[str, Any]:
    data = candidate.model_dump()
    data["id"] = data["id"] or f"c{idx + 1}"
    return data


def _infer_intent(prompt: str, context: dict[str, Any]) -> dict[str, Any]:
    text = f"{prompt} {context}".lower()
    if any(k in text for k in ("secret", "sql", "injection", "auth", "permission", "token")):
        return {"label": "secure_fix", "confidence": 0.78}
    if any(k in text for k in ("latency", "performance", "slow", "throughput")):
        return {"label": "performance_fix", "confidence": 0.68}
    return {"label": "general_fix", "confidence": 0.55}


def _infer_properties(
    prompt: str,
    context: dict[str, Any],
    explicit: list[str],
    representation: dict[str, Any],
) -> list[str]:
    props = list(dict.fromkeys(explicit))
    text = f"{prompt} {context}".lower()
    surface = set(representation.get("risk_surface", []))
    findings = representation.get("critical_findings", []) or []

    if any(k in text for k in ("secret", "token", "api_key", "password")) or "secrets" in surface:
        props.extend(["no_hardcoded_secret", "secret_from_environment", "fail_fast"])
    if any(k in text for k in ("sql", "query", "injection", "cursor.execute")) or "data" in surface:
        props.extend(["no_raw_sql", "parameterized_sql", "validate_email_present"])
    if any(k in text for k in ("auth", "authorization", "permission", "rbac", "is_admin")) or "auth" in surface:
        props.extend(["auth_guard_present", "no_auth_guard_removal", "fail_closed"])
    if "ci_cd" in surface:
        props.extend(["no_untrusted_secret_access"])
    if "infra" in surface:
        props.extend(["explicit_rollback_path"])
    for finding in findings:
        prop = finding.get("property")
        if prop:
            props.append(str(prop))

    return list(dict.fromkeys(props))


def _generate_candidates(prompt: str, context: dict[str, Any], n: int) -> list[dict[str, Any]]:
    text = f"{prompt} {context}".lower()
    filename = str(context.get("filename") or context.get("file") or "app.py")

    if any(k in text for k in ("sql", "query", "injection")):
        templates = [
            (
                "parameterized-sql",
                f"+cursor.execute(\"SELECT * FROM users WHERE email = %s\", [email])",
                "Use bound parameters so user input is never concatenated into SQL.",
            ),
            (
                "orm-filter",
                "+user = User.objects.filter(email=email).first()",
                "Use ORM query construction to avoid raw SQL interpolation.",
            ),
            (
                "validate-and-parameterize",
                "+validate_email(email)\n+cursor.execute(\"SELECT * FROM users WHERE email = %s\", [email])",
                "Validate input shape and use parameterized SQL.",
            ),
        ]
    elif any(k in text for k in ("auth", "authorization", "permission", "rbac", "is_admin")):
        templates = [
            (
                "policy-check",
                "+if not policy.can_perform(user, resource):\n+    raise PermissionError(\"not authorized\")\n+return perform_action(resource)",
                "Fail closed through a centralized authorization policy.",
            ),
            (
                "explicit-admin-guard",
                "+if not user.is_admin:\n+    raise PermissionError(\"admin required\")\n+return perform_action(resource)",
                "Add an explicit permission guard before the sensitive action.",
            ),
            (
                "decorator-guard",
                "+@requires_permission(\"resource:write\")\n+def handler(request):\n+    return perform_action(resource)",
                "Protect the entrypoint with a permission decorator.",
            ),
        ]
    elif any(k in text for k in ("secret", "token", "api_key", "password")):
        templates = [
            (
                "env-fail-fast",
                "+import os\n+SECRET_KEY = os.environ.get(\"SECRET_KEY\")\n+if not SECRET_KEY:\n+    raise RuntimeError(\"SECRET_KEY environment variable is not set\")",
                "Read secret from the environment and fail closed if it is missing.",
            ),
            (
                "env-only",
                "+import os\n+SECRET_KEY = os.environ.get(\"SECRET_KEY\")",
                "Read secret from the environment with a minimal change.",
            ),
            (
                "config-loader",
                "+SECRET_KEY = config.require_secret(\"SECRET_KEY\")",
                "Use a config helper that requires secret material at runtime.",
            ),
        ]
    elif any(k in text for k in ("terraform", "kubernetes", "k8s", "iam", "s3", "security group", "rds", "docker", "infra", "cloud", "public", "privileged")):
        templates = [
            (
                "least-privilege-infra",
                "+# restrict public access and wildcard permissions\n+policy = least_privilege(policy)\n+rollback = \"terraform plan && revert previous module version\"",
                "Constrain cloud permissions, remove public exposure, and require an explicit rollback path.",
            ),
            (
                "private-networking",
                "+cidr_blocks = [var.private_cidr]\n+publicly_accessible = false\n+rollback = \"restore previous security group\"",
                "Move exposed infrastructure back behind private networking.",
            ),
            (
                "pinned-runtime",
                "+image = \"service@sha256:verified-digest\"\n+allowPrivilegeEscalation = false\n+rollback = \"rollout undo deployment/service\"",
                "Pin runtime artifacts and disable privileged execution.",
            ),
        ]
    elif any(k in text for k in ("pull_request_target", "github actions", "workflow", "ci/cd", "supply chain", "curl | bash", "artifact", "secrets.")):
        templates = [
            (
                "ci-readonly-pinned",
                "+permissions:\n+  contents: read\n+# pin actions by sha and do not expose secrets to untrusted jobs",
                "Use read-only workflow permissions, pin actions, and avoid secrets in untrusted contexts.",
            ),
            (
                "verified-build",
                "+run: npm ci && npm test\n+# verify artifact signature before deploy",
                "Restore tests and artifact verification in the deploy pipeline.",
            ),
            (
                "trusted-dependency-source",
                "+# install dependencies from the official registry with lockfile verification",
                "Avoid unverified forks and install scripts in the build path.",
            ),
        ]
    elif any(k in text for k in ("dependency", "cve", "npm", "package", "requirements", "license", "typosquat", "postinstall")):
        templates = [
            (
                "dependency-upgrade-pin",
                "+# upgrade vulnerable dependency, pin exact version, and verify lockfile hash",
                "Upgrade or remove vulnerable packages and pin the safe version.",
            ),
            (
                "dependency-audit-gate",
                "+# block build on critical CVE, malicious package, GPL policy violation, or install-time network access",
                "Add a dependency policy gate for CVEs, licensing, and install-time behavior.",
            ),
            (
                "remove-risky-package",
                "+# remove unofficial fork and replace with maintained official package",
                "Replace risky dependencies with maintained and trusted packages.",
            ),
        ]
    elif any(k in text for k in ("migration", "drop column", "pii", "pagination", "backup", "index", "n+1", "soft delete", "data leak")):
        templates = [
            (
                "data-safety-guard",
                "+# require backup, pagination, field redaction, and rollback before data migration",
                "Guard data changes with backup, redaction, pagination, and rollback requirements.",
            ),
            (
                "safe-migration",
                "+# expand-contract migration: add new column, backfill, verify, then remove in a later deploy",
                "Convert destructive migration into a staged migration.",
            ),
            (
                "redact-sensitive-output",
                "+return redact_sensitive_fields(user, fields=[\"password\", \"token\", \"ssn\"])",
                "Prevent sensitive fields and PII from leaving the service boundary.",
            ),
        ]
    elif any(k in text for k in ("timeout", "retry", "backoff", "cache", "race", "payment", "memory leak", "healthcheck", "debug", "stack trace", "production")):
        templates = [
            (
                "runtime-guardrails",
                "+timeout = bounded_timeout(default=30)\n+retry = exponential_backoff(max_attempts=3)\n+rollback = \"disable feature flag\"",
                "Restore bounded timeout, backoff, and rollback controls.",
            ),
            (
                "safe-payment-lock",
                "+with payment_lock(account_id):\n+    charge_once(request)",
                "Protect financial operations with explicit locking/idempotency.",
            ),
            (
                "safe-error-handling",
                "+logger.error(\"request failed\", extra=redact_sensitive_context(ctx))\n+return generic_error_response()",
                "Avoid stack trace and credential exposure in production errors.",
            ),
        ]
    elif any(k in text for k in ("llm", "ai", "prompt injection", "embedding", "fine-tune", "model", "langflow", "sandbox")):
        templates = [
            (
                "ai-sandbox-policy",
                "+# run LLM tool calls in sandbox, require auth, rate limit, and sanitize HTML output",
                "Constrain AI execution with sandboxing, auth, rate limits, and output sanitization.",
            ),
            (
                "ai-data-boundary",
                "+# block PII/secrets from embeddings and fine-tuning datasets; enforce access control",
                "Protect sensitive data from model training and vector storage.",
            ),
            (
                "secure-token-generation",
                "+token = secrets.token_urlsafe(32)",
                "Use cryptographic randomness for security tokens.",
            ),
        ]
    elif any(k in text for k in ("branch protection", "main", "self-approved", "audit", "insider", "service account", "employee")):
        templates = [
            (
                "human-review-policy",
                "+# require branch protection, independent approval, audit logs, and justified secret access",
                "Force human governance on insider-risk changes.",
            ),
            (
                "least-privilege-service-account",
                "+# replace admin service account with scoped role and time-bound access",
                "Remove shared/admin credentials from development workflows.",
            ),
            (
                "audit-preserving-change",
                "+# preserve audit logging and require security owner approval",
                "Prevent removal of audit controls without independent review.",
            ),
        ]
    else:
        templates = [
            ("minimal-patch", "+# minimal fix placeholder", "Small patch with minimal blast radius."),
            ("robust-guard", "+assert invariant_holds()", "Add an invariant guard before changing behavior."),
            ("test-backed", "+# add regression test for the changed behavior", "Prefer a test-backed fix."),
        ]

    candidates = []
    for idx, (strategy, body, explanation) in enumerate(templates[: max(1, n)]):
        candidates.append(
            {
                "id": f"g{idx + 1}",
                "diff": (
                    f"diff --git a/{filename} b/{filename}\n"
                    f"--- a/{filename}\n"
                    f"+++ b/{filename}\n"
                    f"@@\n"
                    f"{body}\n"
                ),
                "strategy": strategy,
                "explanation": explanation,
                "metadata": {"generated_by": "safety_flow", "rank": idx + 1},
            }
        )
    return candidates


def _verify_candidate(candidate: dict[str, Any], properties: list[str]) -> dict[str, Any]:
    diff = str(candidate.get("diff") or "")
    text = f"{diff}\n{candidate.get('strategy', '')}\n{candidate.get('explanation', '')}"
    lower = text.lower()
    violations: list[str] = []
    critical: list[str] = []
    evidence: list[str] = []
    sql_semantics = verify_sql_semantics(
        diff,
        require_validate_email="validate_email_present" in properties,
    )

    for prop in properties:
        if prop == "no_hardcoded_secret":
            if _SECRET_ASSIGN_RE.search(diff):
                violations.append(prop)
                critical.append(prop)
            else:
                evidence.append(prop)
        elif prop == "secret_from_environment":
            if not _ENV_READ_RE.search(diff) and "require_secret" not in diff:
                violations.append(prop)
            else:
                evidence.append(prop)
        elif prop in {"fail_fast", "fail_closed"}:
            if not _FAIL_FAST_RE.search(diff):
                violations.append(prop)
            else:
                evidence.append(prop)
        elif prop == "no_raw_sql":
            if (
                (_UNSAFE_SQL_RE.search(diff) and not _PARAM_SQL_RE.search(diff))
                or bool(sql_semantics.get("critical_violations"))
            ):
                violations.append(prop)
                critical.append(prop)
            else:
                evidence.append(prop)
        elif prop == "parameterized_sql":
            if bool(sql_semantics.get("critical_violations")):
                violations.append(prop)
                critical.append(prop)
            elif not _PARAM_SQL_RE.search(diff) and "objects.filter" not in diff:
                violations.append(prop)
            else:
                evidence.append(prop)
        elif prop == "validate_email_present":
            if sql_semantics.get("sql_detected") and not sql_semantics.get("validate_email_present"):
                violations.append(prop)
            else:
                evidence.append(prop)
        elif prop == "auth_guard_present":
            if not _AUTH_GUARD_RE.search(diff):
                violations.append(prop)
            else:
                evidence.append(prop)
        elif prop == "no_auth_guard_removal":
            if _REMOVED_AUTH_RE.search(diff):
                violations.append(prop)
                critical.append(prop)
            else:
                evidence.append(prop)
        elif prop == "no_untrusted_secret_access":
            untrusted_trigger = "pull_request_target" in lower or "workflow_run" in lower
            secret_access = "secrets." in lower or "github_token" in lower or "write-all" in lower
            if untrusted_trigger and secret_access:
                violations.append(prop)
                critical.append(prop)
            else:
                evidence.append(prop)
        elif prop == "explicit_rollback_path":
            has_rollback = any(
                marker in lower
                for marker in (
                    "rollback",
                    "rollout undo",
                    "revert",
                    "previous_version",
                    "terraform plan",
                    "terraform apply -refresh-only",
                )
            )
            if not has_rollback:
                violations.append(prop)
            else:
                evidence.append(prop)
        elif prop == "least_privilege_infra":
            unsafe = re.search(
                r"0\.0\.0\.0/0|public-read|publicly_accessible\s*=\s*true|action\s*=\s*['\"]\*|resource\s*=\s*['\"]\*|privileged\s*:\s*true|:latest",
                lower,
                re.IGNORECASE,
            )
            safe_markers = ("least_privilege", "private_cidr", "publicly_accessible = false", "sha256:", "allowprivilegeescalation = false")
            if unsafe or not any(marker in lower for marker in safe_markers):
                violations.append(prop)
                if unsafe:
                    critical.append(prop)
            else:
                evidence.append(prop)
        elif prop == "safe_ci_supply_chain":
            unsafe = re.search(r"pull_request_target[\s\S]{0,300}secrets\.|curl .*\|.*bash|@(main|master|latest)|skip[_-]?tests\s*=\s*true", lower)
            safe_markers = ("permissions:", "contents: read", "pin actions", "signature", "lockfile", "official registry")
            if unsafe or not any(marker in lower for marker in safe_markers):
                violations.append(prop)
                if unsafe:
                    critical.append(prop)
            else:
                evidence.append(prop)
        elif prop == "dependency_policy":
            unsafe = re.search(r"cve-\d{4}-\d+|postinstall.*curl|typosquat|latest|git\+", lower)
            safe_markers = ("upgrade", "pin", "lockfile", "audit", "remove", "maintained", "official package")
            if unsafe or not any(marker in lower for marker in safe_markers):
                violations.append(prop)
            else:
                evidence.append(prop)
        elif prop == "data_safety_policy":
            unsafe = re.search(r"drop column|drop table|select \*|console\.log\(.*password|pagination\s*=\s*false|deleted_at.*removed", lower)
            safe_markers = ("backup", "pagination", "redact", "expand-contract", "backfill", "rollback", "sensitive_fields")
            if unsafe or not any(marker in lower for marker in safe_markers):
                violations.append(prop)
                if unsafe and re.search(r"drop column|drop table", lower):
                    critical.append(prop)
            else:
                evidence.append(prop)
        elif prop == "runtime_safety_policy":
            unsafe = re.search(r"timeout\s*=\s*0|while true|backoff\s*=\s*false|traceback\.format_exc|debug\s*=\s*true|shell\s*=\s*true", lower)
            safe_markers = ("bounded_timeout", "exponential_backoff", "rollback", "payment_lock", "redact_sensitive", "generic_error_response")
            if unsafe or not any(marker in lower for marker in safe_markers):
                violations.append(prop)
                if unsafe and re.search(r"shell\s*=\s*true|payment|transfer|charge", lower):
                    critical.append(prop)
            else:
                evidence.append(prop)
        elif prop == "ai_safety_policy":
            unsafe = re.search(r"llm.*(exec|eval|database)|math\.random\(\).*token|rate_limit\s*=\s*none|innerhtml|fine[_-]?tune.*secret", lower)
            safe_markers = ("sandbox", "rate limit", "sanitize", "auth", "access control", "secrets.token_urlsafe", "block pii")
            if unsafe or not any(marker in lower for marker in safe_markers):
                violations.append(prop)
                if unsafe and re.search(r"exec|eval|database|rce", lower):
                    critical.append(prop)
            else:
                evidence.append(prop)
        elif prop == "human_review_policy":
            unsafe = re.search(r"branch_protection\s*=\s*false|self[-_ ]approved|audit.*removed|shared credentials|service_account.*admin", lower)
            safe_markers = ("branch protection", "independent approval", "audit logs", "justified secret access", "scoped role", "security owner")
            if unsafe or not any(marker in lower for marker in safe_markers):
                violations.append(prop)
            else:
                evidence.append(prop)

    violations = list(dict.fromkeys(violations))
    critical = list(dict.fromkeys(critical))
    evidence = list(dict.fromkeys(evidence))
    score = max(0.0, 1.0 - 0.14 * len(violations) - 0.20 * len(critical))
    return {
        "verified": not violations,
        "score": round(score, 4),
        "violations": violations,
        "critical_violations": critical,
        "evidence": evidence,
        "sql_semantics": sql_semantics,
    }


def _rank_candidates(
    scores: dict[str, Any],
    verifications: dict[str, Any],
    runtime_evidence: dict[str, Any],
    prior_data: dict[str, Any],
    representation: dict[str, Any],
    candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    ranking: list[dict[str, Any]] = []
    candidates_by_id = {str(candidate.get("id")): candidate for candidate in candidates}
    priors = prior_data.get("priors") or {}
    blast_radius = representation.get("blast_radius") or {}
    blast_score = float(blast_radius.get("score") or 0.0)
    graph_score = float((blast_radius.get("graph") or {}).get("score") or 0.0)

    for cid, score in scores.items():
        verification = verifications.get(cid, {})
        sandbox = runtime_evidence.get(cid, {})
        candidate = candidates_by_id.get(str(cid), {})
        strategy = str(candidate.get("strategy") or cid)
        utility = float(score.get("utility", 0.0))
        uncertainty = float(score.get("uncertainty", 0.0))
        violations = len(verification.get("violations", []))
        critical = len(verification.get("critical_violations", []))
        sandbox_score = float(sandbox.get("score") or 0.0)
        sandbox_failed = 1 if sandbox.get("status") == "failed" else 0
        verified_bonus = 0.04 if verification.get("verified") else 0.0
        prior = float(priors.get(strategy, priors.get(str(cid), 0.5)))
        prior_adjustment = (prior - 0.5) * 0.08
        blast_radius_penalty = blast_score * (0.02 if verification.get("verified") else 0.06)
        graph_penalty = graph_score * 0.04
        runtime_penalty = (1.0 - sandbox_score) * 0.10 + sandbox_failed * 0.12
        expected_loss = (
            (1.0 - utility) * (0.45 + blast_score)
            + 0.10 * violations
            + 0.25 * critical
            + 0.08 * uncertainty
            + runtime_penalty
            + graph_penalty
        )
        adjusted = (
            utility
            + prior_adjustment
            - blast_radius_penalty
            - graph_penalty
            - runtime_penalty
            - 0.14 * violations
            - 0.25 * critical
            - 0.08 * uncertainty
            + verified_bonus
        )
        ranking.append(
            {
                "candidate": cid,
                "strategy": strategy,
                "utility": round(utility, 4),
                "risk_adjusted_utility": round(max(0.0, adjusted), 4),
                "expected_loss": round(max(0.0, expected_loss), 4),
                "prior": round(prior, 4),
                "prior_adjustment": round(prior_adjustment, 4),
                "blast_radius_penalty": round(blast_radius_penalty, 4),
                "graph_penalty": round(graph_penalty, 4),
                "runtime_penalty": round(runtime_penalty, 4),
                "verification_score": verification.get("score", 0.0),
                "runtime_evidence_score": round(sandbox_score, 4),
                "runtime_evidence_status": sandbox.get("status", "inconclusive"),
                "security": score.get("security"),
                "correctness": score.get("correctness"),
                "robustness": score.get("robustness"),
                "uncertainty": score.get("uncertainty"),
                "verified": verification.get("verified", False),
                "violations": verification.get("violations", []),
                "critical_violations": verification.get("critical_violations", []),
                "rationale": score.get("rationale", []),
            }
        )

    return sorted(
        ranking,
        key=lambda item: (
            not item["critical_violations"],
            item["verified"],
            item["risk_adjusted_utility"],
            -item["expected_loss"],
            item["security"] or 0,
        ),
        reverse=True,
    )


def _final_decision(
    mode: str,
    selected: dict[str, Any] | None,
    evaluation: dict[str, Any],
    representation: dict[str, Any],
) -> dict[str, Any]:
    if selected is None:
        return {"action": "abstain", "reason": "No candidate available."}

    blast = representation.get("blast_radius") or {}
    blast_level = str(blast.get("level") or "low")
    uncertainty = float(selected.get("uncertainty") or 0.0)
    findings = representation.get("critical_findings", []) or []
    severe_findings = [
        f for f in findings
        if str(f.get("severity", "")).lower() in {"critical", "high"}
    ]

    if selected["critical_violations"]:
        return {
            "action": "reject",
            "reason": "Best candidate still has critical safety violations.",
            "candidate": selected["candidate"],
            "merge_blocker": True,
        }

    if selected["violations"]:
        return {
            "action": "revise",
            "reason": "Best candidate has unresolved verification violations.",
            "candidate": selected["candidate"],
            "merge_blocker": False,
        }

    if selected.get("runtime_evidence_status") == "failed":
        return {
            "action": "revise",
            "reason": "Runtime evidence sandbox failed for the selected candidate.",
            "candidate": selected["candidate"],
            "merge_blocker": False,
        }

    if severe_findings:
        top = severe_findings[0]
        return {
            "action": "needs_verification",
            "reason": f"Observed change contains {top.get('severity')} finding {top.get('id')}; verified candidate still requires review before merge.",
            "candidate": selected["candidate"],
            "merge_blocker": True,
            "finding_count": len(findings),
        }

    if blast_level == "critical" and uncertainty >= 0.22:
        return {
            "action": "needs_verification",
            "reason": "Candidate passed local checks, but critical blast radius and uncertainty require explicit verification.",
            "candidate": selected["candidate"],
            "merge_blocker": True,
        }

    if uncertainty >= 0.35:
        return {
            "action": "needs_verification",
            "reason": "Candidate passed policy checks, but uncertainty is too high for automatic approval.",
            "candidate": selected["candidate"],
            "merge_blocker": False,
        }

    # Delegate final decision to central PolicyEngine
    policy = policy_engine.decide(
        evaluation=evaluation,
        selected=selected,
        mode=mode,
    )
    return {
        "action": policy.action.value,
        "reason": policy.reason,
        "candidate": policy.candidate,
        "merge_blocker": policy.merge_blocker,
        "requires_verification": policy.requires_verification,
        "requires_repair": policy.requires_repair,
        "sensitive_mode": policy.sensitive_mode,
        "policy_flags": policy.policy_flags,
    }


def _build_change_representation(
    req: SafetyFlowRequest,
    candidates: list[dict[str, Any]],
    prior_data: dict[str, Any],
) -> dict[str, Any]:
    files = _files_from_request_or_candidates(req, candidates)
    critical_findings = _detect_critical_findings(req.prompt, req.context, files) if req.files else []
    surface = _risk_surface(req.prompt, req.context, files)
    for finding in critical_findings:
        finding_surface = str(finding.get("surface") or "")
        if finding_surface and finding_surface not in surface:
            surface.append(finding_surface)
    graph_stats: dict[str, Any] = {}
    high_risk_nodes: list[dict[str, Any]] = []

    try:
        from graph import build_repo_graph, find_high_risk_nodes

        graph = build_repo_graph({"repo": req.repo or "unknown/repo", "files": files})
        graph_stats = graph.get("stats", {})
        high_risk_nodes = find_high_risk_nodes(graph)[:8]
    except Exception:
        graph_stats = {"node_count": 0, "edge_count": 0, "file_count": len(files)}
    execution_evidence = _observed_execution_evidence(files)

    trust_boundaries = _trust_boundaries(surface, files)
    blast_radius = _blast_radius(files, surface, candidates, graph_stats, high_risk_nodes)

    return {
        "repo": req.repo,
        "intent": req.intent or _infer_intent(req.prompt, req.context),
        "files": [
            {
                "filename": f.get("filename"),
                "status": f.get("status", "modified"),
                "additions": int(f.get("additions") or 0),
                "deletions": int(f.get("deletions") or 0),
            }
            for f in files
        ],
        "file_count": len(files),
        "risk_surface": surface,
        "critical_findings": critical_findings,
        "trust_boundaries": trust_boundaries,
        "blast_radius": blast_radius,
        "execution_evidence": execution_evidence,
        "graph": graph_stats,
        "high_risk_nodes": high_risk_nodes,
        "memory_prior": prior_data,
        "confidence_inputs": {
            "candidate_count": len(candidates),
            "has_runtime_logs": bool(req.context.get("logs") or req.context.get("stacktrace")),
            "has_tests": any("test" in str(f.get("filename", "")).lower() for f in files),
            "has_history": bool(req.history),
        },
    }


def _files_from_request_or_candidates(
    req: SafetyFlowRequest,
    candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if req.files:
        normalized = []
        for f in req.files:
            filename = str(f.get("filename") or f.get("path") or "")
            if not filename:
                continue
            normalized.append(
                {
                    "filename": filename,
                    "diff": str(f.get("diff") or f.get("patch") or f.get("raw_patch") or ""),
                    "raw_patch": str(f.get("raw_patch") or f.get("diff") or ""),
                    "status": str(f.get("status") or "modified"),
                    "additions": int(f.get("additions") or 0),
                    "deletions": int(f.get("deletions") or 0),
                }
            )
        if normalized:
            return normalized

    fallback = str(req.context.get("filename") or req.context.get("file") or "app.py")
    by_file: dict[str, dict[str, Any]] = {}
    for candidate in candidates:
        diff = str(candidate.get("diff") or "")
        match = _DIFF_FILE_RE.search(diff)
        filename = match.group("right") if match else fallback
        if filename not in by_file:
            by_file[filename] = {
                "filename": filename,
                "diff": "",
                "raw_patch": "",
                "status": "modified",
                "additions": 0,
                "deletions": 0,
            }
        by_file[filename]["diff"] += "\n" + diff
        additions, deletions = _diff_churn(diff)
        by_file[filename]["additions"] += additions
        by_file[filename]["deletions"] += deletions

    return list(by_file.values()) or [
        {
            "filename": fallback,
            "diff": "",
            "raw_patch": "",
            "status": "modified",
            "additions": 0,
            "deletions": 0,
        }
    ]


def _diff_churn(diff: str) -> tuple[int, int]:
    additions = 0
    deletions = 0
    for line in diff.splitlines():
        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+"):
            additions += 1
        elif line.startswith("-"):
            deletions += 1
    return additions, deletions


def _detect_critical_findings(
    prompt: str,
    context: dict[str, Any],
    files: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    context_text = f"{prompt}\n{context}"

    for f in files:
        filename = str(f.get("filename") or "")
        diff = str(f.get("diff") or f.get("raw_patch") or "")
        text = f"{context_text}\n{filename}\n{diff}"
        for rule in _COMPILED_CRITICAL_RULES:
            if not rule["regex"].search(text):
                continue
            key = (str(rule["id"]), filename)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                {
                    "id": rule["id"],
                    "surface": rule["surface"],
                    "severity": rule["severity"],
                    "property": rule["property"],
                    "file": filename,
                    "confidence": _SEVERITY_RISK.get(str(rule["severity"]), 0.5),
                }
            )

    findings.sort(
        key=lambda f: _SEVERITY_RISK.get(str(f.get("severity", "low")), 0.0),
        reverse=True,
    )
    return findings


def _risk_surface(prompt: str, context: dict[str, Any], files: list[dict[str, Any]]) -> list[str]:
    text = " ".join(
        [
            prompt,
            str(context),
            " ".join(str(f.get("filename", "")) for f in files),
            " ".join(str(f.get("diff", "")) for f in files),
        ]
    ).lower()

    rules: tuple[tuple[str, tuple[str, ...]], ...] = (
        ("secrets", ("secret", "token", "api_key", "password", "private_key", "credential", ".env", "client_secret", "sendgrid", "twilio")),
        ("auth", ("auth", "authorization", "permission", "rbac", "jwt", "oauth", "session", "is_admin", "ownership", "cors", "mfa")),
        ("data", ("sql", "query", "database", "migration", "schema", "cursor.execute", "postgres", "mysql", "pii", "pagination", "soft delete")),
        ("ci_cd", (".github/workflows", "pull_request_target", "workflow_run", "github_token", "actions/", "artifact", "curl | bash", "supply chain")),
        ("infra", ("terraform", "kubernetes", "k8s", "helm", "docker", "render.yaml", "iam", "deploy", "s3", "rds", "security group", "0.0.0.0/0")),
        ("latency", ("latency", "performance", "throughput", "timeout", "benchmark", "queue")),
        ("runtime", ("stacktrace", "exception", "runtime", "production", "incident", "logs", "retry", "backoff", "healthcheck", "memory leak")),
        ("dependencies", ("requirements.txt", "package-lock", "poetry.lock", "dependabot", "dependency", "npm", "cve", "license", "postinstall")),
        ("ai", ("llm", "prompt injection", "embedding", "fine-tune", "langflow", "model", "ai api")),
        ("human", ("branch protection", "self-approved", "audit logs", "insider", "service account", "employee departure")),
    )

    surface = [name for name, keys in rules if any(k in text for k in keys)]
    return list(dict.fromkeys(surface))


def _trust_boundaries(surface: list[str], files: list[dict[str, Any]]) -> list[str]:
    filenames = " ".join(str(f.get("filename", "")).lower() for f in files)
    boundaries: list[str] = []

    if "secrets" in surface:
        boundaries.append("secret_material_boundary")
    if "auth" in surface:
        boundaries.append("user_authorization_boundary")
    if "data" in surface:
        boundaries.append("external_input_to_database_boundary")
    if "ci_cd" in surface:
        boundaries.append("untrusted_ci_execution_boundary")
    if "infra" in surface or any(k in filenames for k in ("terraform", "k8s", "helm", "render.yaml")):
        boundaries.append("cloud_control_plane_boundary")
    if "latency" in surface:
        boundaries.append("slo_latency_boundary")
    if "dependencies" in surface:
        boundaries.append("software_supply_chain_boundary")
    if "runtime" in surface:
        boundaries.append("production_runtime_boundary")
    if "ai" in surface:
        boundaries.append("ai_tool_execution_boundary")
    if "human" in surface:
        boundaries.append("human_governance_boundary")

    return boundaries


def _blast_radius(
    files: list[dict[str, Any]],
    surface: list[str],
    candidates: list[dict[str, Any]],
    graph_stats: dict[str, Any] | None = None,
    high_risk_nodes: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    surface_weights = {
        "ci_cd": 0.78,
        "infra": 0.76,
        "auth": 0.70,
        "secrets": 0.66,
        "data": 0.60,
        "dependencies": 0.48,
        "latency": 0.44,
        "runtime": 0.40,
        "ai": 0.72,
        "human": 0.58,
    }
    reasons = [f"{name}_surface" for name in surface]
    score = max((surface_weights.get(name, 0.20) for name in surface), default=0.18)
    file_count = len(files)
    churn = sum(int(f.get("additions") or 0) + int(f.get("deletions") or 0) for f in files)
    candidate_churn = max((_diff_churn(str(c.get("diff") or ""))[0] for c in candidates), default=0)
    graph_stats = graph_stats or {}
    high_risk_nodes = high_risk_nodes or []
    graph_score = _graph_blast_score(graph_stats, high_risk_nodes)

    if file_count >= 8:
        score += 0.10
        reasons.append("many_files")
    elif file_count >= 3:
        score += 0.05
        reasons.append("several_files")

    if churn >= 200 or candidate_churn >= 80:
        score += 0.08
        reasons.append("large_churn")
    elif churn >= 40 or candidate_churn >= 20:
        score += 0.04
        reasons.append("moderate_churn")

    if graph_score >= 0.50:
        score += min(0.14, graph_score * 0.14)
        reasons.append("graph_high_risk_nodes")
    elif graph_score >= 0.25:
        score += min(0.08, graph_score * 0.12)
        reasons.append("graph_dependency_surface")

    # Surface classifier - reduce false positives for docs/test PRs
    try:
        from surface_classifier import classify_change_surface
        if files:
            _surface = classify_change_surface(files=files, diff='')
            score = score * _surface.risk_multiplier
            if _surface.risk_multiplier < 0.5:
                reasons.append(f'surface:{_surface.surface}')
    except Exception:
        pass
    score = max(0.0, min(1.0, score))
    if score >= 0.82:
        level = "critical"
    elif score >= 0.60:
        level = "high"
    elif score >= 0.35:
        level = "medium"
    else:
        level = "low"

    return {
        "score": round(score, 4),
        "level": level,
        "reasons": reasons,
        "file_count": file_count,
        "total_churn": churn,
        "max_candidate_churn": candidate_churn,
        "graph": {
            "score": round(graph_score, 4),
            "node_count": int(graph_stats.get("node_count") or 0),
            "edge_count": int(graph_stats.get("edge_count") or 0),
            "high_risk_node_count": len(high_risk_nodes),
        },
    }


def _graph_blast_score(graph_stats: dict[str, Any], high_risk_nodes: list[dict[str, Any]]) -> float:
    node_count = int(graph_stats.get("node_count") or 0)
    edge_count = int(graph_stats.get("edge_count") or 0)
    file_count = max(1, int(graph_stats.get("file_count") or 1))
    density = min(1.0, edge_count / max(1, node_count * 2))
    fanout = min(1.0, edge_count / max(1, file_count * 8))
    risky = min(1.0, sum(float(node.get("score") or 0.0) for node in high_risk_nodes) / 3.0)
    return max(0.0, min(1.0, 0.45 * risky + 0.35 * fanout + 0.20 * density))


def _repair_candidates(
    candidates: list[dict[str, Any]],
    verifications: dict[str, Any],
    properties: list[str],
    context: dict[str, Any],
) -> list[dict[str, Any]]:
    repaired: list[dict[str, Any]] = []
    seen_signatures: set[tuple[str, str]] = set()

    for candidate in candidates:
        cid = str(candidate.get("id"))
        verification = verifications.get(cid, {})
        violations = set(verification.get("violations") or [])
        critical = set(verification.get("critical_violations") or [])
        if not violations and not critical:
            continue

        filename = _candidate_filename(candidate, context)
        repair = _repair_patch_for_violations(filename, violations | critical, properties)
        if not repair:
            continue

        signature = (cid, repair["strategy"])
        if signature in seen_signatures:
            continue
        seen_signatures.add(signature)

        repaired.append(
            {
                "id": f"{cid}_repair",
                "diff": repair["diff"],
                "strategy": repair["strategy"],
                "explanation": repair["explanation"],
                "metadata": {
                    "generated_by": "safety_flow_repair",
                    "repaired_from": cid,
                    "fixed_properties": sorted(violations | critical),
                },
            }
        )

    return repaired


def _repair_patch_for_violations(
    filename: str,
    violations: set[str],
    properties: list[str],
) -> dict[str, str] | None:
    if {"no_hardcoded_secret", "secret_from_environment", "fail_fast"} & violations:
        body = (
            '+import os\n'
            '+SECRET_KEY = os.environ.get("SECRET_KEY")\n'
            '+if not SECRET_KEY:\n'
            '+    raise RuntimeError("SECRET_KEY environment variable is not set")'
        )
        return {
            "strategy": "repair-env-fail-fast",
            "diff": _format_diff(filename, body),
            "explanation": "Replace hardcoded secret material with an environment-backed value and fail fast when missing.",
        }

    if {"no_raw_sql", "parameterized_sql", "validate_email_present"} & violations:
        body = '+validate_email(email)\n+cursor.execute("SELECT * FROM users WHERE email = %s", [email])'
        return {
            "strategy": "repair-parameterized-sql",
            "diff": _format_diff(filename, body),
            "explanation": "Validate the email input and use bound parameters so external input cannot change the SQL structure.",
        }

    if {"auth_guard_present", "no_auth_guard_removal", "fail_closed"} & violations:
        body = (
            '+if not policy.can_perform(user, resource):\n'
            '+    raise PermissionError("not authorized")\n'
            '+return perform_action(resource)'
        )
        return {
            "strategy": "repair-policy-guard",
            "diff": _format_diff(filename, body),
            "explanation": "Restore a fail-closed authorization guard before the sensitive operation.",
        }

    if "no_untrusted_secret_access" in violations:
        body = (
            '+permissions:\n'
            '+  contents: read\n'
            '+# no secrets are exposed to untrusted pull_request_target jobs'
        )
        return {
            "strategy": "repair-ci-readonly",
            "diff": _format_diff(filename, body),
            "explanation": "Constrain CI permissions and avoid exposing secrets to untrusted workflow contexts.",
        }

    domain_policy_violations = {
        "least_privilege_infra",
        "safe_ci_supply_chain",
        "dependency_policy",
        "data_safety_policy",
        "runtime_safety_policy",
        "ai_safety_policy",
        "human_review_policy",
    }

    if "explicit_rollback_path" in violations and not (domain_policy_violations & violations):
        body = '+# rollback: revert this change or run the platform rollback command before retrying'
        return {
            "strategy": "repair-rollback-plan",
            "diff": _format_diff(filename, body),
            "explanation": "Attach an explicit rollback path for the infrastructure change.",
        }

    if "least_privilege_infra" in violations:
        body = (
            '+# restrict public access and wildcard permissions\n'
            '+policy = least_privilege(policy)\n'
            '+publicly_accessible = false\n'
            '+rollback = "terraform plan && revert previous module version"'
        )
        return {
            "strategy": "repair-least-privilege-infra",
            "diff": _format_diff(filename, body),
            "explanation": "Remove public exposure and wildcard permissions with an explicit rollback path.",
        }

    if "safe_ci_supply_chain" in violations:
        body = (
            '+permissions:\n'
            '+  contents: read\n'
            '+# pin actions by sha, run tests, and verify artifact signature before deploy'
        )
        return {
            "strategy": "repair-safe-ci-supply-chain",
            "diff": _format_diff(filename, body),
            "explanation": "Harden CI/CD permissions, action pinning, tests, and artifact verification.",
        }

    if "dependency_policy" in violations:
        body = '+# upgrade vulnerable dependency, pin exact version, verify lockfile hash, and remove risky package'
        return {
            "strategy": "repair-dependency-policy",
            "diff": _format_diff(filename, body),
            "explanation": "Apply dependency policy controls for CVEs, pinning, licensing, and install behavior.",
        }

    if "data_safety_policy" in violations:
        body = '+# require backup, pagination, redaction, expand-contract migration, and rollback before data changes'
        return {
            "strategy": "repair-data-safety-policy",
            "diff": _format_diff(filename, body),
            "explanation": "Guard data changes with backup, staged migration, redaction, and rollback.",
        }

    if "runtime_safety_policy" in violations:
        body = (
            '+timeout = bounded_timeout(default=30)\n'
            '+retry = exponential_backoff(max_attempts=3)\n'
            '+rollback = "disable feature flag"\n'
            '+logger.error("request failed", extra=redact_sensitive_context(ctx))'
        )
        return {
            "strategy": "repair-runtime-safety-policy",
            "diff": _format_diff(filename, body),
            "explanation": "Restore runtime guardrails for timeout, backoff, rollback, and safe error handling.",
        }

    if "ai_safety_policy" in violations:
        body = '+# run LLM tool calls in sandbox, require auth, rate limit, sanitize output, and block PII/secrets'
        return {
            "strategy": "repair-ai-safety-policy",
            "diff": _format_diff(filename, body),
            "explanation": "Constrain AI execution and data access with sandboxing, auth, rate limits, and sanitization.",
        }

    if "human_review_policy" in violations:
        body = '+# require branch protection, independent approval, audit logs, justified secret access, and scoped role'
        return {
            "strategy": "repair-human-review-policy",
            "diff": _format_diff(filename, body),
            "explanation": "Require governance controls for insider-risk or process-risk changes.",
        }

    return None


def _format_diff(filename: str, body: str) -> str:
    return (
        f"diff --git a/{filename} b/{filename}\n"
        f"--- a/{filename}\n"
        f"+++ b/{filename}\n"
        f"@@\n"
        f"{body}\n"
    )


def _candidate_filename(candidate: dict[str, Any], context: dict[str, Any]) -> str:
    diff = str(candidate.get("diff") or "")
    match = _DIFF_FILE_RE.search(diff)
    if match:
        return match.group("right")
    return str(context.get("filename") or context.get("file") or "app.py")


def _repair_iteration_deltas(
    repair_candidates: list[dict[str, Any]],
    evaluation: dict[str, Any],
    verifications: dict[str, Any],
) -> list[dict[str, Any]]:
    scores = evaluation.get("scores") or {}
    deltas = evaluation.get("deltas") or {}
    iterations: list[dict[str, Any]] = []

    for idx, candidate in enumerate(repair_candidates, start=1):
        cid = str(candidate.get("id"))
        parent_id = str((candidate.get("metadata") or {}).get("repaired_from") or "")
        before = scores.get(parent_id, {}) if isinstance(scores, dict) else {}
        after = scores.get(cid, {}) if isinstance(scores, dict) else {}
        delta = deltas.get(cid, {}) if isinstance(deltas, dict) else {}
        verification = verifications.get(cid, {}) if isinstance(verifications, dict) else {}

        iterations.append(
            {
                "iteration": idx,
                "candidate": cid,
                "previous_candidate": parent_id or None,
                "fixed_properties": list((candidate.get("metadata") or {}).get("fixed_properties") or []),
                "security_before": before.get("security"),
                "security_after": after.get("security"),
                "utility_before": before.get("utility"),
                "utility_after": after.get("utility"),
                "uncertainty_before": before.get("uncertainty"),
                "uncertainty_after": after.get("uncertainty"),
                "security_delta": round(float(delta.get("security_delta") or 0.0), 4),
                "utility_delta": round(float(delta.get("utility_delta") or 0.0), 4),
                "uncertainty_delta": round(float(delta.get("uncertainty_delta") or 0.0), 4),
                "verified": bool(verification.get("verified")),
                "violations": list(verification.get("violations") or []),
                "critical_violations": list(verification.get("critical_violations") or []),
            }
        )

    return iterations


def _repair_converged(
    repair_candidates: list[dict[str, Any]],
    selected: dict[str, Any] | None,
    verifications: dict[str, Any],
) -> bool:
    if not repair_candidates:
        return True
    if not selected:
        return False

    selected_id = str(selected.get("candidate") or "")
    verification = verifications.get(selected_id, {})
    return bool(verification.get("verified")) and not verification.get("critical_violations")


def _selected_delta(selected: dict[str, Any] | None, evaluation: dict[str, Any]) -> dict[str, float]:
    zero = {"security_delta": 0.0, "utility_delta": 0.0, "uncertainty_delta": 0.0}
    if not selected:
        return zero
    deltas = evaluation.get("deltas") or {}
    candidate_delta = deltas.get(str(selected.get("candidate") or "")) if isinstance(deltas, dict) else None
    if not isinstance(candidate_delta, dict):
        return zero
    return {
        "security_delta": round(float(candidate_delta.get("security_delta") or 0.0), 4),
        "utility_delta": round(float(candidate_delta.get("utility_delta") or 0.0), 4),
        "uncertainty_delta": round(float(candidate_delta.get("uncertainty_delta") or 0.0), 4),
    }


def _operational_metrics(
    ranking: list[dict[str, Any]],
    verifications: dict[str, Any],
    runtime_evidence: dict[str, Any],
    evaluation: dict[str, Any],
) -> dict[str, Any]:
    total = max(1, len(verifications))
    verified = sum(1 for v in verifications.values() if v.get("verified"))
    critical = sum(1 for v in verifications.values() if v.get("critical_violations"))
    runtime_passed = sum(1 for v in runtime_evidence.values() if v.get("status") == "passed")
    runtime_failed = sum(1 for v in runtime_evidence.values() if v.get("status") == "failed")
    top_k = ranking[: min(3, len(ranking))]
    unsafe_top_k = sum(
        1
        for item in top_k
        if item.get("violations") or item.get("critical_violations") or not item.get("verified")
    )
    selected = ranking[0] if ranking else {}
    selected_margin = 0.0
    if len(ranking) > 1:
        selected_margin = float(ranking[0]["risk_adjusted_utility"]) - float(ranking[1]["risk_adjusted_utility"])

    mean_uncertainty = 0.0
    if top_k:
        mean_uncertainty = sum(float(item.get("uncertainty") or 0.0) for item in top_k) / len(top_k)

    return {
        "verification_pass_rate": round(verified / total, 4),
        "runtime_evidence_pass_rate": round(runtime_passed / max(1, len(runtime_evidence)), 4),
        "runtime_evidence_failure_rate": round(runtime_failed / max(1, len(runtime_evidence)), 4),
        "critical_violation_rate": round(critical / total, 4),
        "unsafe_top_k": unsafe_top_k,
        "mean_uncertainty_top_k": round(mean_uncertainty, 4),
        "selected_margin": round(selected_margin, 4),
        "selected_expected_loss": selected.get("expected_loss"),
        "repair_convergence": bool(evaluation.get("repair_converged", False)),
        "requires_verification": bool(evaluation.get("requires_verification")),
        "requires_repair": bool(evaluation.get("requires_repair")),
    }


def _safety_flow_risk(
    representation: dict[str, Any],
    selected: dict[str, Any] | None,
    decision: dict[str, Any],
) -> dict[str, Any]:
    findings = representation.get("critical_findings", []) or []
    finding_score = 0
    if findings:
        finding_score = max(
            int(round(_SEVERITY_RISK.get(str(f.get("severity", "low")), 0.32) * 100))
            for f in findings
        )

    blast = representation.get("blast_radius") or {}
    blast_score = int(round(float(blast.get("score") or 0.0) * 100))
    graph_score = int(round(float((blast.get("graph") or {}).get("score") or 0.0) * 100))
    selected_score = 0
    if selected:
        selected_score = int(round(float(selected.get("expected_loss") or 0.0) * 100))
        if selected.get("critical_violations"):
            selected_score = max(selected_score, 88)
        elif selected.get("violations"):
            selected_score = max(selected_score, 62)
        if selected.get("runtime_evidence_status") == "failed":
            selected_score = max(selected_score, 70)

    score = max(finding_score, blast_score, selected_score, graph_score)
    action = str(decision.get("action") or "").lower()
    if action == "reject":
        score = max(score, 90)
    elif decision.get("merge_blocker"):
        score = max(score, 80)
    elif action in {"revise", "needs_verification"}:
        score = max(score, 45)

    score = max(0, min(100, score))
    if score >= 85:
        triage = "P0"
    elif score >= 65:
        triage = "P1"
    elif score >= 40:
        triage = "P2"
    else:
        triage = "P3"

    if score >= 80:
        band = "critical"
    elif score >= 60:
        band = "high"
    elif score >= 40:
        band = "medium"
    elif score >= 20:
        band = "low"
    else:
        band = "minimal"

    return {
        "score": score,
        "band": band,
        "triage": triage,
        "p_exploit": round(min(0.99, score / 100.0), 4),
        "source_scores": {
            "findings": finding_score,
            "blast_radius": blast_score,
            "graph": graph_score,
            "candidate_expected_loss": selected_score,
        },
    }


def _runtime_evidence(
    candidate: dict[str, Any],
    properties: list[str],
    representation: dict[str, Any],
) -> dict[str, Any]:
    try:
        from execution_sandbox import verify_runtime_evidence

        return verify_runtime_evidence(candidate, properties, representation)
    except Exception as exc:
        return {
            "mode": "deterministic_local",
            "status": "inconclusive",
            "score": 0.5,
            "checks": [{"name": "sandbox_error", "status": "warn", "evidence": str(exc)}],
            "failed_checks": [],
            "warning_checks": ["sandbox_error"],
        }


def _observed_execution_evidence(files: list[dict[str, Any]]) -> dict[str, Any]:
    try:
        from execution_sandbox import verify_observed_change

        return verify_observed_change(files)
    except Exception as exc:
        return {
            "mode": "observed_change_static_execution",
            "status": "inconclusive",
            "score": 0.5,
            "checks": [{"name": "observed_execution_error", "status": "warn", "evidence": str(exc)}],
            "failed_checks": [],
            "warning_checks": ["observed_execution_error"],
        }


def _calibrate_risk(repo: str, risk: dict[str, Any]) -> dict[str, Any]:
    try:
        from calibration import calibrate_probability

        raw = float(risk.get("p_exploit") or 0.0)
        calibrated = calibrate_probability(repo, raw)
        risk["p_exploit_raw"] = calibrated["raw_probability"]
        risk["p_exploit"] = calibrated["probability"]
        risk["calibration"] = {
            "method": calibrated["method"],
            "summary": calibrated["summary"],
        }
        if "bin" in calibrated:
            risk["calibration"]["bin"] = calibrated["bin"]
    except Exception as exc:
        risk["calibration"] = {"method": "unavailable", "error": str(exc)}
    return risk


def _deployment_policy(
    mode: str,
    representation: dict[str, Any],
    runtime_evidence: dict[str, Any],
    risk: dict[str, Any],
    selected: dict[str, Any] | None,
) -> dict[str, Any]:
    try:
        return policy_engine.evaluate_deployment(
            representation=representation,
            runtime_evidence=runtime_evidence,
            risk=risk,
            selected=selected,
            mode=mode,
        ).__dict__
    except Exception as exc:
        return {
            "action": "REVIEW",
            "merge_blocker": True,
            "reason": f"Deployment policy evaluation failed: {exc}",
            "violations": [],
            "warnings": [{"policy": "policy_engine_error", "evidence": str(exc)}],
            "evidence": {},
        }


def _apply_deployment_policy(
    decision: dict[str, Any],
    risk: dict[str, Any],
    deployment_policy: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    action = str(deployment_policy.get("action") or "").upper()
    if action == "BLOCK":
        decision = {
            **decision,
            "action": "reject",
            "reason": deployment_policy.get("reason", "Deployment policy blocked this change."),
            "merge_blocker": True,
            "deployment_policy_action": "BLOCK",
        }
        risk = {**risk, "score": max(int(risk.get("score") or 0), 90), "band": "critical", "triage": "P0"}
        risk["p_exploit"] = max(float(risk.get("p_exploit") or 0.0), 0.90)
    elif action == "REVIEW" and decision.get("action") == "approve":
        decision = {
            **decision,
            "action": "needs_verification",
            "reason": deployment_policy.get("reason", "Deployment policy requires review."),
            "merge_blocker": bool(deployment_policy.get("merge_blocker", False)),
            "deployment_policy_action": "REVIEW",
        }
        risk = {**risk, "score": max(int(risk.get("score") or 0), 55)}
        if risk["score"] >= 80:
            risk["band"] = "critical"
        elif risk["score"] >= 60:
            risk["band"] = "high"
        else:
            risk["band"] = "medium"
    else:
        decision = {**decision, "deployment_policy_action": action or "UNKNOWN"}
    return decision, risk


def _record_flow_result(
    req: SafetyFlowRequest,
    selected: dict[str, Any] | None,
    decision: dict[str, Any],
    representation: dict[str, Any],
    operational_metrics: dict[str, Any],
    risk_model: dict[str, Any],
) -> dict[str, Any] | None:
    if not req.repo:
        return None

    try:
        from memory import store_event

        pr_number = req.context.get("pr_number") or req.context.get("pr") or 0
        risk = 1.0
        if selected:
            risk = round(1.0 - float(selected.get("risk_adjusted_utility") or 0.0), 4)

        return store_event(
            repo=req.repo,
            event_type="safety_flow",
            entity=f"pr#{pr_number}" if pr_number else "safety-flow",
            text=req.prompt,
            label=decision.get("action"),
            risk=risk,
            decision=decision.get("action"),
            outcome="verified_candidate" if selected and selected.get("verified") else "needs_work",
            metadata={
                "selected": selected,
                "decision": decision,
                "risk_surface": representation.get("risk_surface", []),
                "trust_boundaries": representation.get("trust_boundaries", []),
                "blast_radius": representation.get("blast_radius", {}),
                "operational_metrics": operational_metrics,
                "risk": risk_model,
                "p_exploit": risk_model.get("p_exploit"),
                "repair_converged": operational_metrics.get("repair_convergence"),
            },
        )
    except Exception as exc:
        return {"stored": False, "error": str(exc)}

