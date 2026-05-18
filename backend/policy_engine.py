HARDBLOCK_PATTERNS = [
    "db credentials", "db_password", "db_pass", "secret exposure",
    "private key", "aws_secret_access_key", "token leak", "api_key ="
]

BLOCK_KEYWORDS = [
    "sql injection", "eval(", "| bash", "curl https",
    "hardcoded", "secret_key", "disable ssl", "verify=false",
    "public-read", "wildcard", "iam wildcard", "privileged: true",
    "hostnetwork", "remove input validation", "force_destroy",
    "credential", "db_password", "db_pass",
]

BLOCK_INTENTS = {"sql_injection_fix", "secret_fix", "hardcoded_secret_fix"}
REVISE_INTENTS = {"secure_fix", "auth_fix"}
AUTH_KEYWORDS = ["oauth", "oauth2", "jwt", "authentication", "authorization", "login flow", "sso", "saml"]
TRIVIAL_SURFACES = {"documentation", "comment_only", "frontend_only", "test_only", "dependency_only"}
SENSITIVE_DOMAINS = ["payment", "billing", "auth", "credential", "token", "oauth"]
LOGGING_KEYWORDS = ["logging", "log.", "logger", "print(", "console.log"]
BUGFIX_KEYWORDS = ["null pointer", "nullpointerexception", "null reference", "none type"]


def detect_surface(prompt: str, files: list) -> str:
    filenames = [f.get("filename", "").lower() for f in files]
    extensions = [fn.rsplit(".", 1)[-1] if "." in fn else "" for fn in filenames]

    if filenames and all("requirements" in fn or fn in {"package.json", "package-lock.json", "yarn.lock", "pipfile", "poetry.lock"} or (ext in {"txt", "toml", "lock"} and "require" in fn)
                         for fn, ext in zip(filenames, extensions) if fn):
        return "dependency_only"
    if filenames and all((ext in {"md", "rst"} or "readme" in fn or "license" in fn) and "requirements" not in fn
                         for fn, ext in zip(filenames, extensions) if fn):
        return "documentation"
    if filenames and all(ext == "css" or "style" in fn
                         for fn, ext in zip(filenames, extensions) if fn):
        return "frontend_only"
    if filenames and all("test" in fn or "spec" in fn for fn in filenames if fn):
        return "test_only"
    if filenames and all("requirements" in fn or "package" in fn or ext in {"txt", "toml", "lock"}
                         for fn, ext in zip(filenames, extensions) if fn):
        return "dependency_only"
    if any(kw in prompt.lower() for kw in ["comment", "typo", "rename", "refactor"]):
        content = " ".join(f.get("content", "") for f in files)
        if len(content) < 200 and not any(ext in {"py","js","ts","go","rb","java"} for ext in extensions):
            return "comment_only"
    return "runtime"


def policy_decision(prompt: str, files: list, mode: str, intent_label: str,
                    infra_block: bool, infra_score: int, safety_action: str) -> dict:
    full_text = (prompt + " " + " ".join(f.get("content", "") for f in files)).lower()
    surface = detect_surface(prompt, files)
    chain = [f"surface:{surface}", f"intent:{intent_label}", f"mode:{mode}"]

    # 0. Hardblock deterministico
    if any(p in full_text for p in HARDBLOCK_PATTERNS):
        chain += ["credential_exposure_detected", "hardblock_pattern_matched", "deployment_policy_block"]
        return {"decision": "BLOCK", "reason": "hardblock_pattern", "surface": surface, "why_chain": chain}

    # 0b. Logging en dominio sensible
    if any(kw in prompt.lower() for kw in LOGGING_KEYWORDS):
        if any(d in prompt.lower() for d in SENSITIVE_DOMAINS):
            chain += ["logging_detected", "sensitive_domain_matched", "compliance_surface_risk"]
            return {"decision": "REVISE", "reason": "logging_sensitive_domain", "surface": surface, "why_chain": chain}

    # 1. Infra
    if infra_block or infra_score >= 35:
        chain += [f"infra_score:{infra_score}", "critical_infra_finding", "deployment_policy_block"]
        return {"decision": "BLOCK", "reason": "infra_critical_finding", "surface": surface, "why_chain": chain}

    # 2. Trivial surface
    if surface in TRIVIAL_SURFACES:
        if not any(kw in full_text for kw in BLOCK_KEYWORDS):
            chain += ["no_runtime_execution", "no_security_signals", "auto_approve"]
            return {"decision": "APPROVE", "reason": "trivial_surface", "surface": surface, "why_chain": chain}

    # 3. Block keywords
    if any(kw in full_text for kw in BLOCK_KEYWORDS):
        matched = [kw for kw in BLOCK_KEYWORDS if kw in full_text]
        chain += [f"block_keyword:{matched[0]}", "security_pattern_matched", "deployment_policy_block"]
        return {"decision": "BLOCK", "reason": "block_keyword", "surface": surface, "why_chain": chain}

    # 4. Block intents
    if intent_label in BLOCK_INTENTS:
        chain += [f"high_risk_intent:{intent_label}", "intent_policy_block"]
        return {"decision": "BLOCK", "reason": f"block_intent:{intent_label}", "surface": surface, "why_chain": chain}

    # 4b. Auth changes = REVISE
    if any(kw in full_text for kw in AUTH_KEYWORDS) and surface == "runtime":
        chain += ["auth_surface_detected", "trust_boundary_change", "requires_security_review"]
        return {"decision": "REVISE", "reason": "auth_change", "surface": surface, "why_chain": chain}

    # 5. Runtime bugfix
    if any(kw in prompt.lower() for kw in BUGFIX_KEYWORDS) and surface == "runtime":
        chain += ["runtime_bugfix_detected", "regression_risk_elevated", "requires_verification"]
        return {"decision": "REVISE", "reason": "runtime_bugfix", "surface": surface, "why_chain": chain}

    # 6. Balanced = APPROVE
    if mode == "balanced":
        chain += ["no_risk_signals_detected", "balanced_mode_policy", "auto_approve"]
        return {"decision": "APPROVE", "reason": "balanced_mode_no_risk", "surface": surface, "why_chain": chain}

    # 7. Revise intents
    if intent_label in REVISE_INTENTS:
        chain += [f"revise_intent:{intent_label}", "requires_security_review"]
        return {"decision": "REVISE", "reason": f"revise_intent:{intent_label}", "surface": surface, "why_chain": chain}

    # 8. Safety flow action
    if safety_action in {"NEEDS_VERIFICATION", "NEEDS_REPAIR", "REVISE"}:
        chain += [f"safety_flow_action:{safety_action}", "verification_required"]
        return {"decision": "REVISE", "reason": f"safety_flow:{safety_action}", "surface": surface, "why_chain": chain}

    chain += ["no_risk_signals_detected", "auto_approve"]
    return {"decision": "APPROVE", "reason": "no_risk_signals", "surface": surface, "why_chain": chain}
