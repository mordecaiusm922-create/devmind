from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class InfraFinding:
    rule_id: str
    severity: str        # critical/high/medium/low
    surface: str         # terraform/kubernetes/github_actions/iam/docker/helm
    title: str
    description: str
    file: str = ""
    line: int = 0
    evidence: str = ""
    cwe: str = ""
    fix_hint: str = ""


@dataclass
class InfraAnalysisResult:
    findings: list[InfraFinding] = field(default_factory=list)
    risk_score: int = 0
    surfaces_detected: list[str] = field(default_factory=list)
    has_critical: bool = False
    has_iam_wildcard: bool = False
    has_public_exposure: bool = False
    has_secret_exposure: bool = False
    has_privilege_escalation: bool = False
    block_merge: bool = False
    summary: str = ""


# ── TERRAFORM ─────────────────────────────────────────────────────────────
TF_RULES = [
    (
        r'effect\s*=\s*"Allow".*actions\s*=\s*\[.*"\*"',
        "TF001", "critical", "IAM wildcard action",
        "IAM policy allows all actions (*). This grants unrestricted access.",
        "Use least-privilege: specify exact actions needed.",
        "CWE-732",
    ),
    (
        r'resources\s*=\s*\[.*"\*".*\]',
        "TF002", "critical", "IAM wildcard resource",
        "IAM policy applies to all resources (*). Limit to specific ARNs.",
        "Specify exact resource ARNs.",
        "CWE-732",
    ),
    (
        r'acl\s*=\s*"public-read"',
        "TF003", "critical", "S3 bucket public-read ACL",
        "S3 bucket is publicly readable. Data exposure risk.",
        "Use private ACL and bucket policies.",
        "CWE-284",
    ),
    (
        r'block_public_acls\s*=\s*false|block_public_policy\s*=\s*false',
        "TF004", "critical", "S3 public access not blocked",
        "S3 bucket does not block public access.",
        "Set all block_public_* to true.",
        "CWE-284",
    ),
    (
        r'publicly_accessible\s*=\s*true',
        "TF005", "critical", "RDS/DB publicly accessible",
        "Database is publicly accessible from the internet.",
        "Set publicly_accessible = false and use VPC.",
        "CWE-284",
    ),
    (
        r'cidr_blocks\s*=\s*\[.*"0\.0\.0\.0/0"',
        "TF006", "high", "Security group open to world (0.0.0.0/0)",
        "Security group allows inbound from all IPs.",
        "Restrict CIDR to known IP ranges.",
        "CWE-284",
    ),
    (
        r'encrypted\s*=\s*false',
        "TF007", "high", "Storage encryption disabled",
        "Storage resource has encryption disabled.",
        "Set encrypted = true.",
        "CWE-311",
    ),
    (
        r'skip_final_snapshot\s*=\s*true',
        "TF008", "medium", "RDS skip final snapshot",
        "Database will be deleted without a final snapshot.",
        "Set skip_final_snapshot = false in production.",
        "CWE-664",
    ),
    (
        r'deletion_protection\s*=\s*false',
        "TF009", "medium", "Deletion protection disabled",
        "Resource can be accidentally deleted.",
        "Enable deletion_protection = true.",
        "CWE-664",
    ),
    (
        r'force_destroy\s*=\s*true',
        "TF010", "high", "S3 force_destroy enabled",
        "Bucket and all contents can be permanently destroyed.",
        "Set force_destroy = false in production.",
        "CWE-664",
    ),
]

# ── KUBERNETES ────────────────────────────────────────────────────────────
K8S_RULES = [
    (
        r'privileged:\s*true',
        "K8S001", "critical", "Privileged container",
        "Container runs in privileged mode — full host access.",
        "Remove privileged: true. Use specific capabilities instead.",
        "CWE-250",
    ),
    (
        r'hostNetwork:\s*true',
        "K8S002", "critical", "hostNetwork enabled",
        "Pod shares host network namespace. Network isolation bypass.",
        "Remove hostNetwork: true.",
        "CWE-668",
    ),
    (
        r'hostPID:\s*true',
        "K8S003", "critical", "hostPID enabled",
        "Pod shares host PID namespace. Process isolation bypass.",
        "Remove hostPID: true.",
        "CWE-668",
    ),
    (
        r'runAsUser:\s*0|runAsNonRoot:\s*false',
        "K8S004", "high", "Container runs as root",
        "Container runs as root user. Privilege escalation risk.",
        "Set runAsNonRoot: true and runAsUser to non-zero.",
        "CWE-250",
    ),
    (
        r'allowPrivilegeEscalation:\s*true',
        "K8S005", "critical", "Privilege escalation allowed",
        "Container can gain more privileges than parent process.",
        "Set allowPrivilegeEscalation: false.",
        "CWE-250",
    ),
    (
        r'value:\s*\$\(.*SECRET|valueFrom:.*secretKeyRef',
        "K8S006", "high", "Secret exposed in env var",
        "Kubernetes secret exposed as environment variable.",
        "Use mounted secret volumes instead of env vars.",
        "CWE-312",
    ),
    (
        r'image:.*:latest',
        "K8S007", "medium", "Docker image uses :latest tag",
        "Using :latest tag makes deployments non-deterministic.",
        "Pin to specific image digest or version tag.",
        "CWE-1104",
    ),
    (
        r'readOnlyRootFilesystem:\s*false',
        "K8S008", "medium", "Root filesystem writable",
        "Container filesystem is writable. Persistence attack risk.",
        "Set readOnlyRootFilesystem: true.",
        "CWE-732",
    ),
    (
        r'automountServiceAccountToken:\s*true',
        "K8S009", "medium", "Service account token auto-mounted",
        "Service account token mounted automatically in pod.",
        "Set automountServiceAccountToken: false unless needed.",
        "CWE-522",
    ),
    (
        r'cpu:\s*$|memory:\s*$|resources:\s*\{\}',
        "K8S010", "low", "No resource limits",
        "Container has no CPU/memory limits. DoS risk.",
        "Set resource requests and limits.",
        "CWE-400",
    ),
]

# ── GITHUB ACTIONS ────────────────────────────────────────────────────────
GHA_RULES = [
    (
        r'on:\s*pull_request_target',
        "GHA001", "critical", "pull_request_target with potential secret exposure",
        "pull_request_target runs in privileged context. Secrets accessible from fork PRs.",
        "Use pull_request instead, or add explicit trust boundary checks.",
        "CWE-829",
    ),
    (
        r'curl.*\|.*sh|curl.*\|.*bash|wget.*\|.*sh',
        "GHA002", "critical", "curl pipe to shell",
        "Downloading and executing arbitrary scripts. Supply chain attack vector.",
        "Download, verify checksum, then execute separately.",
        "CWE-494",
    ),
    (
        r'uses:.*@(?!v\d|[a-f0-9]{40})',
        "GHA003", "high", "GitHub Action not pinned to SHA",
        "Action version not pinned to full SHA. Supply chain risk.",
        "Pin actions to full commit SHA: uses: actions/checkout@abc123...",
        "CWE-829",
    ),
    (
        r'\$\{\{.*github\.event\..*\}\}.*run:',
        "GHA004", "critical", "Untrusted input in run step",
        "GitHub event data used directly in run step. Script injection risk.",
        "Assign to env var first, then use env var in run step.",
        "CWE-94",
    ),
    (
        r'secrets\.\w+.*run:|run:.*secrets\.',
        "GHA005", "high", "Secret used directly in run step",
        "Secret value may be exposed in logs.",
        "Use secrets as env vars, not inline in run steps.",
        "CWE-312",
    ),
    (
        r'permissions:\s*write-all|permissions:\s*\*',
        "GHA006", "critical", "Overpermissive workflow permissions",
        "Workflow has write-all or wildcard permissions.",
        "Use minimal permissions: contents: read only.",
        "CWE-732",
    ),
]

# ── DOCKER ────────────────────────────────────────────────────────────────
DOCKER_RULES = [
    (
        r'USER\s+root|USER\s+0',
        "DOCKER001", "high", "Dockerfile runs as root",
        "Container explicitly runs as root user.",
        "Add USER directive with non-root user.",
        "CWE-250",
    ),
    (
        r'FROM.*:latest',
        "DOCKER002", "medium", "Base image uses :latest",
        "Non-deterministic builds with :latest tag.",
        "Pin to specific version or SHA digest.",
        "CWE-1104",
    ),
    (
        r'ENV\s+.*(?:PASSWORD|SECRET|KEY|TOKEN)\s*=',
        "DOCKER003", "critical", "Secret in ENV instruction",
        "Secrets baked into Docker image layer. Exposed in image history.",
        "Use runtime secrets or build args with --secret.",
        "CWE-312",
    ),
    (
        r'ADD\s+https?://',
        "DOCKER004", "medium", "ADD from URL without verification",
        "Downloading content without integrity verification.",
        "Use RUN curl + checksum verification instead.",
        "CWE-494",
    ),
    (
        r'COPY\s+\.\s+\.',
        "DOCKER005", "low", "Copying entire context",
        "Entire build context copied — may include secrets.",
        "Use .dockerignore and copy specific files.",
        "CWE-312",
    ),
]

# ── AWS IAM (JSON policies) ───────────────────────────────────────────────
IAM_RULES = [
    (
        r'"Action"\s*:\s*"\*"',
        "IAM001", "critical", "IAM Action wildcard",
        "IAM policy allows all actions. Full account compromise risk.",
        "Specify exact actions needed (least privilege).",
        "CWE-732",
    ),
    (
        r'"Resource"\s*:\s*"\*"',
        "IAM002", "critical", "IAM Resource wildcard",
        "IAM policy applies to all resources.",
        "Specify exact resource ARNs.",
        "CWE-732",
    ),
    (
        r'"Effect"\s*:\s*"Allow".*"NotAction"',
        "IAM003", "high", "IAM NotAction with Allow",
        "Allows everything EXCEPT listed actions. Very broad permission.",
        "Use explicit Action list instead of NotAction.",
        "CWE-732",
    ),
    (
        r'sts:AssumeRole.*"\*"',
        "IAM004", "critical", "Unrestricted AssumeRole",
        "Any principal can assume this role.",
        "Add Condition constraints to AssumeRole policy.",
        "CWE-732",
    ),
    (
        r'PassRole.*"\*"|iam:PassRole',
        "IAM005", "high", "iam:PassRole permission",
        "iam:PassRole can enable privilege escalation.",
        "Restrict PassRole to specific roles and services.",
        "CWE-269",
    ),
]


def _scan_rules(text: str, rules: list, surface: str, filename: str) -> list[InfraFinding]:
    findings = []
    for rule in rules:
        if len(rule) == 7:
            pattern, rule_id, severity, title, description, fix_hint, cwe = rule
        else:
            continue
        for match in re.finditer(pattern, text, re.I | re.S):
            line_num = text[:match.start()].count("\n") + 1
            findings.append(InfraFinding(
                rule_id=rule_id,
                severity=severity,
                surface=surface,
                title=title,
                description=description,
                file=filename,
                line=line_num,
                evidence=match.group(0)[:120],
                cwe=cwe,
                fix_hint=fix_hint,
            ))
    return findings


def analyze_infra(files: list[dict[str, Any]]) -> InfraAnalysisResult:
    all_findings: list[InfraFinding] = []
    surfaces: set[str] = set()

    for f in files:
        filename = f.get("filename", "") or f.get("path", "")
        patch = f.get("patch", "") or f.get("diff", "") or f.get("content", "") or ""
        if not patch:
            continue

        fn_lower = filename.lower()

        # Terraform
        if fn_lower.endswith(".tf") or fn_lower.endswith(".tfvars"):
            surfaces.add("terraform")
            all_findings += _scan_rules(patch, TF_RULES, "terraform", filename)

        # Kubernetes
        if any(fn_lower.endswith(ext) for ext in (".yaml", ".yml")):
            if any(k in fn_lower for k in ("deploy", "service", "ingress", "pod", "k8s", "kubernetes", "helm", "chart")):
                surfaces.add("kubernetes")
                all_findings += _scan_rules(patch, K8S_RULES, "kubernetes", filename)
            # GitHub Actions
            if ".github/workflows" in fn_lower or "github/workflows" in fn_lower:
                surfaces.add("github_actions")
                all_findings += _scan_rules(patch, GHA_RULES, "github_actions", filename)

        # Docker
        if "dockerfile" in fn_lower:
            surfaces.add("docker")
            all_findings += _scan_rules(patch, DOCKER_RULES, "docker", filename)

        # IAM JSON policies
        if fn_lower.endswith(".json") and any(k in fn_lower for k in ("iam", "policy", "role", "trust")):
            surfaces.add("iam")
            all_findings += _scan_rules(patch, IAM_RULES, "iam", filename)

        # Also scan all files for GHA patterns
        if ".github" in fn_lower:
            surfaces.add("github_actions")
            all_findings += _scan_rules(patch, GHA_RULES, "github_actions", filename)

    # Dedup by rule_id + file + line
    seen = set()
    unique_findings = []
    for f in all_findings:
        key = (f.rule_id, f.file, f.line)
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    # Score
    score = 0
    for f in unique_findings:
        if f.severity == "critical": score += 35
        elif f.severity == "high": score += 20
        elif f.severity == "medium": score += 10
        elif f.severity == "low": score += 3
    score = min(100, score)

    has_critical = any(f.severity == "critical" for f in unique_findings)
    has_iam = any(f.rule_id.startswith("IAM") or f.rule_id in ("TF001", "TF002") for f in unique_findings)
    has_public = any(f.rule_id in ("TF003", "TF004", "TF005", "TF006") for f in unique_findings)
    has_secret = any(f.rule_id in ("DOCKER003", "K8S006", "GHA005") for f in unique_findings)
    has_privesc = any(f.rule_id in ("K8S001", "K8S005", "IAM005", "GHA001") for f in unique_findings)

    return InfraAnalysisResult(
        findings=unique_findings,
        risk_score=score,
        surfaces_detected=sorted(surfaces),
        has_critical=has_critical,
        has_iam_wildcard=has_iam,
        has_public_exposure=has_public,
        has_secret_exposure=has_secret,
        has_privilege_escalation=has_privesc,
        block_merge=has_critical,
        summary=f"{len(unique_findings)} findings across {', '.join(surfaces) or 'unknown'} ({score}/100)",
    )
