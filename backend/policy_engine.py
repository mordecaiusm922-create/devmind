from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable


# -----------------------------
# Config / taxonomÃ­a de riesgo
# -----------------------------

DECISIONS = {"APPROVE", "REVISE", "BLOCK"}

BLOCK_INTENTS = {
    "sql_injection_fix",
    "secret_fix",
    "hardcoded_secret_fix",
}

REVISE_INTENTS = {
    "secure_fix",
    "auth_fix",
}

TRIVIAL_SURFACES = {
    "documentation",
    "comment_only",
    "frontend_only",
    "test_only",
    "dependency_only",
}

SENSITIVE_DOMAINS = {
    "payment",
    "billing",
    "auth",
    "token",
    "oauth",
    "authz",
    "security",
}

AUTH_KEYWORDS = {
    "oauth", "oauth2", "jwt", "authentication", "authorization",
    "login flow", "sso", "saml", "session", "permissions", "rbac",
}

BUGFIX_KEYWORDS = {
    "null pointer", "nullpointerexception", "null reference", "none type",
    "nil pointer", "undefined", "panic",
}

LOGGING_KEYWORDS = {
    "logging", "log.", "logger", "print(", "console.log",
}

# Regex-based hardblock signals are stronger than substring checks.
HARD_BLOCK_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(db[_-]?password|db[_-]?pass|secret[_-]?key|api[_-]?key|aws_secret_access_key)\b", re.I),
    re.compile(r"\bprivate key\b", re.I),
    re.compile(r"\btoken leak\b", re.I),
    re.compile(r"\bsecret exposure\b", re.I),
    re.compile(r"\beval\s*\(", re.I),
    re.compile(r"\|\s*bash\b", re.I),
    re.compile(r"curl\s+https?://", re.I),
    re.compile(r"\bverify\s*=\s*false\b", re.I),
    re.compile(r"\bdisable\s+ssl\b", re.I),
    re.compile(r"\bpublic-read\b", re.I),
    re.compile(r"\bwildcard\b", re.I),
    re.compile(r"\biam wildcard\b", re.I),
    re.compile(r"\bprivileged\s*:\s*true\b", re.I),
    re.compile(r"\bhostnetwork\s*:\s*true\b", re.I),
    re.compile(r"\bforce_destroy\s*=\s*true\b", re.I),
    re.compile(r"\bremove input validation\b", re.I),
    re.compile(r"\bcredential(s)?\s*=\s*['\"][^'\"]{4,}", re.I),
)

# Keyword signals are cheaper and broader.
BLOCK_KEYWORDS = {
    "sql injection",
    "hardcoded",
    "secret_key",
    "api_key",
    "private key",
    "db_password",
    "db_pass",
    "force_destroy",
    "public-read",
    "wildcard",
    "iam wildcard",
    "privileged: true",
    "hostnetwork",
    "remove input validation",
    "disable ssl",
    "verify=false",
    "token leak",
    "secret exposure",
}


@dataclass(frozen=True)
class Signal:
    name: str
    severity: str  # "critical" | "high" | "medium" | "low"
    surface: str
    pattern: re.Pattern[str]


SIGNALS: tuple[Signal, ...] = (
    Signal("hardcoded_secret", "critical", "secrets", re.compile(r"\b(api[_-]?key|secret[_-]?key|password|token|private[_-]?key)\s*=\s*['\"][^'\"]+['\"]", re.I)),
    Signal("private_key_committed", "critical", "secrets", re.compile(r"-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----", re.I)),
    Signal("aws_credentials", "critical", "secrets", re.compile(r"\baws_(access_key_id|secret_access_key)\b|AKIA[0-9A-Z]{16}", re.I)),
    Signal("sql_injection", "critical", "data", re.compile(r"execute\s*\([^,\n]*(\+|%|\.format\(|f['\"])", re.I)),
    Signal("raw_sql_concat", "critical", "data", re.compile(r"select .* where .* \+|sql\s*=\s*f['\"]", re.I)),
    Signal("command_injection", "critical", "runtime", re.compile(r"(os\.system|subprocess\.(call|run|popen)).*(request|input|args|shell\s*=\s*true)|curl\s+\{.*\}\s*\|\s*bash", re.I)),
    Signal("xss", "high", "runtime", re.compile(r"innerHTML|dangerouslySetInnerHTML|mark_safe|render_template_string", re.I)),
    Signal("unsafe_deserialization", "critical", "runtime", re.compile(r"pickle\.loads|yaml\.load\(|marshal\.loads|eval\s*\(", re.I)),
    Signal("public_cloud_resource", "critical", "infra", re.compile(r"publicly_accessible\s*=\s*true|0\.0\.0\.0/0|public-read|acl\s*=\s*['\"]public-read", re.I)),
    Signal("iam_wildcard", "critical", "infra", re.compile(r"action\s*=\s*['\"]\*['\"]|resource\s*=\s*['\"]\*['\"]|\*:\*", re.I)),
    Signal("privileged_container", "critical", "infra", re.compile(r"privileged\s*:\s*true|allowPrivilegeEscalation\s*:\s*true|runAsUser\s*:\s*0", re.I)),
    Signal("ci_untrusted_secret_access", "critical", "ci_cd", re.compile(r"pull_request_target[\s\S]{0,300}(secrets\.|github_token|permissions:\s*write-all)", re.I)),
    Signal("supply_chain_risk", "high", "ci_cd", re.compile(r"curl .*\|\s*bash|uses:\s*[\w.-]+/[\w.-]+@(main|master|latest)|skip[_-]?tests\s*=\s*true", re.I)),
    Signal("dependency_risk", "medium", "dependencies", re.compile(r"cve-\d{4}-\d+|typosquat|postinstall.*curl|version\s*=\s*['\"]latest['\"]", re.I)),
    Signal("logging_sensitive_data", "high", "runtime", re.compile(r"(console\.log|logger\.\w+|print\().*(password|token|ssn|secret)", re.I)),
    Signal("auth_change", "high", "auth", re.compile(r"(oauth2?|jwt|authentication|authorization|login flow|sso|saml|rbac|session)", re.I)),
    Signal("destructive_migration", "critical", "data", re.compile(r"drop table|drop column|delete from .*users|force_destroy\s*=\s*true", re.I)),
)


SEVERITY_WEIGHT = {
    "critical": 1.00,
    "high": 0.72,
    "medium": 0.48,
    "low": 0.20,
}


# -----------------------------
# Surface detection
# -----------------------------

def detect_surface(prompt: str, files: list[dict[str, Any]]) -> str:
    """
    Return the dominant surface for the change.
    A real policy engine should classify by file mix, not only by prompt.
    """
    prompt_l = prompt.lower()
    filenames = [str(f.get("filename", "")).lower() for f in files if f.get("filename")]
    contents = " ".join(str(f.get("content", "")) for f in files).lower()

    if not files:
        return "runtime"

    # File-based surface inference
    ext_counts: dict[str, int] = {}
    for name in filenames:
        ext = name.rsplit(".", 1)[-1] if "." in name else ""
        ext_counts[ext] = ext_counts.get(ext, 0) + 1

    def all_match(pred: Iterable[bool]) -> bool:
        vals = list(pred)
        return bool(vals) and all(vals)

    if all_match(
        ("requirements" in fn or fn in {"package.json", "package-lock.json", "yarn.lock", "pipfile", "poetry.lock"} or fn.endswith((".txt", ".toml", ".lock")))
        for fn in filenames
    ):
        return "dependency_only"

    if all_match(
        (fn.endswith((".md", ".rst", ".txt")) or "readme" in fn or "license" in fn)
        and "requirements" not in fn
        for fn in filenames
    ):
        return "documentation"

    if all_match(fn.endswith(".css") or "style" in fn for fn in filenames):
        return "frontend_only"

    if all_match("test" in fn or "spec" in fn for fn in filenames):
        return "test_only"

    # Prompt hints only when file evidence is weak.
    if any(k in prompt_l for k in {"comment", "typo", "rename", "refactor"}) and len(contents) < 200:
        if not any(ext in {"py", "js", "ts", "go", "rb", "java", "cpp", "cs", "rs", "php"} for ext in ext_counts):
            return "comment_only"

    if any(k in prompt_l for k in {"terraform", "kubernetes", "docker", "iam", "s3", "rds", "security group"}) or re.search(r"\binfra\b", prompt_l):
        return "infra"

    if any(k in prompt_l for k in {"sql", "query", "database", "migration", "schema", "postgres", "mysql", "sqlite"}):
        return "data"

    if any(k in prompt_l for k in AUTH_KEYWORDS):
        return "auth"

    if any(k in prompt_l for k in {"deploy", "workflow", "actions", "github actions", ".github/workflows", "pull_request_target"}):
        return "ci_cd"

    return "runtime"


# -----------------------------
# Signal extraction
# -----------------------------

def _scan_signals(text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for signal in SIGNALS:
        if signal.pattern.search(text):
            findings.append(
                {
                    "name": signal.name,
                    "severity": signal.severity,
                    "surface": signal.surface,
                    "weight": SEVERITY_WEIGHT[signal.severity],
                }
            )
    return findings


def _contains_any(text: str, phrases: Iterable[str]) -> list[str]:
    text_l = text.lower()
    return [p for p in phrases if p.lower() in text_l]


def _risk_score_from_signals(signals: list[dict[str, Any]], *, trivial: bool = False) -> int:
    if not signals:
        return 5 if trivial else 12

    score = 10
    for s in signals:
        w = float(s.get("weight", 0.2))
        if s["severity"] == "critical":
            score += int(55 * w)  # critical jumps hard
        elif s["severity"] == "high":
            score += int(28 * w)
        elif s["severity"] == "medium":
            score += int(16 * w)
        else:
            score += int(8 * w)

    return max(0, min(100, score))


def _band_from_score(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "minimal"


def _decision(decision: str, reason: str, surface: str, chain: list[str], risk_score: int, band: str) -> dict[str, Any]:
    return {
        "decision": decision,
        "reason": reason,
        "surface": surface,
        "why_chain": chain,
        "risk_score": risk_score,
        "band": band,
    }


# -----------------------------
# Main policy engine
# -----------------------------

def policy_decision(
    prompt: str,
    files: list[dict[str, Any]],
    mode: str,
    intent_label: str,
    infra_block: bool,
    infra_score: int,
    safety_action: str,
) -> dict[str, Any]:
    """
    Production-style policy decision:
    1) hardblock deterministically
    2) detect surface
    3) score signals
    4) apply gate precedence
    5) return explainable decision
    """
    prompt_l = prompt.lower()
    file_text = " ".join(str(f.get("content", "")) for f in files)
    filenames = " ".join(str(f.get("filename", "")) for f in files)
    full_text = f"{prompt}\n{filenames}\n{file_text}".lower()

    surface = detect_surface(prompt, files)
    chain = [f"surface:{surface}", f"intent:{intent_label}", f"mode:{mode}"]

    hardblock_matches = [p.pattern for p in HARD_BLOCK_PATTERNS if p.search(full_text)]
    keyword_matches = _contains_any(full_text, BLOCK_KEYWORDS)
    signals = _scan_signals(full_text)
    signal_names = {s["name"] for s in signals}

    trivial = surface in TRIVIAL_SURFACES
    risk_score = _risk_score_from_signals(signals, trivial=trivial)
    band = _band_from_score(risk_score)

    # 0. Hard block deterministic
    if hardblock_matches:
        chain += ["hardblock_pattern_matched", f"matched:{hardblock_matches[0].pattern}"]
        return _decision("BLOCK", "hardblock_pattern", surface, chain, max(risk_score, 95), "critical")

    # 1. Infra gate before convenience heuristics
    if infra_block or infra_score >= 35:
        chain += [f"infra_score:{infra_score}", "critical_infra_finding"]
        return _decision("BLOCK", "infra_critical_finding", surface, chain, max(risk_score, 90), "critical")

    # 2. Intent-based hard blocks
    if intent_label in BLOCK_INTENTS:
        chain += [f"block_intent:{intent_label}", "intent_policy_block"]
        return _decision("BLOCK", f"block_intent:{intent_label}", surface, chain, max(risk_score, 85), "critical")

    # 4. Sensitive logging is never auto-approved in sensitive domains
    if _contains_any(prompt_l, LOGGING_KEYWORDS):
        if any(d in prompt_l for d in SENSITIVE_DOMAINS):
            chain += ["logging_detected", "sensitive_domain_matched", "compliance_surface_risk"]
            return _decision("REVISE", "logging_sensitive_domain", surface, chain, max(risk_score, 55), "medium")

    # 5. Safety flow says verify/repair on non-trivial surfaces
    if safety_action in {"NEEDS_VERIFICATION", "NEEDS_REPAIR"}:
        chain += [f"safety_flow_action:{safety_action}", "verification_required"]
        return _decision(
            "REVISE",
            f"safety_flow:{safety_action}",
            surface,
            chain,
            max(risk_score, 58),
            _band_from_score(max(risk_score, 25)),
        )

    # 3. Trivial surfaces: approve before lower gates can override
    if trivial:
        if not keyword_matches and not signals:
            chain += ["trivial_surface", "no_security_signals", "auto_approve"]
            return _decision("APPROVE", "trivial_surface", surface, chain, 5, "minimal")
        chain += ["trivial_surface_but_risk_signals_present"]
        return _decision("REVISE", "trivial_surface_with_risk", surface, chain, max(risk_score, 25), _band_from_score(max(risk_score, 25)))
    # 6. Strong keyword gate, but avoid false positives with trivial text
    if keyword_matches:
        chain += [f"block_keyword:{keyword_matches[0]}", "security_pattern_matched"]
        return _decision("BLOCK", "block_keyword", surface, chain, max(risk_score, 85), "critical")

    # 7. Auth changes are revisable, not directly auto-approved
    if any(k in full_text for k in AUTH_KEYWORDS) or "auth_change" in signal_names:
        if surface in {"runtime", "data", "infra"}:
            chain += ["auth_surface_detected", "trust_boundary_change", "requires_security_review"]
            return _decision("REVISE", "auth_change", surface, chain, max(risk_score, 60), "high")
    # 8. Runtime bugfixes should be reviewed if they touch behavior
    if any(k in prompt_l for k in BUGFIX_KEYWORDS) and surface == "runtime":
        chain += ["runtime_bugfix_detected", "regression_risk_elevated"]
        return _decision("REVISE", "runtime_bugfix", surface, chain, max(risk_score, 45), "medium")

    # 9. Balanced mode can approve only when low risk and no signals
    if mode == "balanced":
        if not signals and not keyword_matches:
            chain += ["balanced_mode", "no_risk_signals_detected", "auto_approve"]
            return _decision("APPROVE", "balanced_mode_no_risk", surface, chain, 10, "low")
        chain += ["balanced_mode_but_risk_present"]
        return _decision("REVISE", "balanced_mode_risk_present", surface, chain, max(risk_score, 35), _band_from_score(max(risk_score, 35)))

    # 10. Revise intents
    if intent_label in REVISE_INTENTS:
        chain += [f"revise_intent:{intent_label}", "requires_security_review"]
        return _decision("REVISE", f"revise_intent:{intent_label}", surface, chain, max(risk_score, 35), _band_from_score(max(risk_score, 35)))

    # 11. Default: use risk score to decide
    if risk_score >= 75:
        chain += ["high_risk_score", "block_by_threshold"]
        return _decision("BLOCK", "risk_threshold", surface, chain, risk_score, _band_from_score(risk_score))

    if risk_score >= 35:
        chain += ["moderate_risk_score", "review_required"]
        return _decision("REVISE", "risk_threshold", surface, chain, risk_score, _band_from_score(risk_score))

    chain += ["no_risk_signals_detected", "auto_approve"]
    return _decision("APPROVE", "no_risk_signals", surface, chain, risk_score, band)


# -----------------------------
# Optional helper: explainable audit
# -----------------------------

def policy_audit(prompt: str, files: list[dict[str, Any]], intent_label: str = "unknown") -> dict[str, Any]:
    """
    Lightweight audit view for debugging / telemetry.
    """
    surface = detect_surface(prompt, files)
    text = f"{prompt}\n" + " ".join(str(f.get("content", "")) for f in files)
    hardblocks = [p.pattern.pattern for p in HARD_BLOCK_PATTERNS if p.search(text)]
    signals = _scan_signals(text.lower())
    score = _risk_score_from_signals(signals, trivial=surface in TRIVIAL_SURFACES)

    return {
        "surface": surface,
        "intent_label": intent_label,
        "hardblock_count": len(hardblocks),
        "hardblocks": hardblocks[:5],
        "signals": signals,
        "risk_score": score,
        "band": _band_from_score(score),
    }










