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
TRIVIAL_SURFACES = {"documentation", "comment_only", "frontend_only", "test_only", "dependency_only"}
SENSITIVE_DOMAINS = ["payment", "billing", "auth", "credential", "token", "oauth"]
LOGGING_KEYWORDS = ["logging", "log.", "logger", "print(", "console.log"]
BUGFIX_KEYWORDS = ["null pointer", "nullpointerexception", "null reference", "none type"]


def detect_surface(prompt: str, files: list) -> str:
    filenames = [f.get("filename", "").lower() for f in files]
    extensions = [fn.rsplit(".", 1)[-1] if "." in fn else "" for fn in filenames]

    if filenames and all(ext in {"md", "txt", "rst"} or "readme" in fn or "license" in fn
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
        if len(content) < 200:
            return "comment_only"
    return "runtime"


def policy_decision(prompt: str, files: list, mode: str, intent_label: str,
                    infra_block: bool, infra_score: int, safety_action: str) -> dict:
    full_text = (prompt + " " + " ".join(f.get("content", "") for f in files)).lower()
    surface = detect_surface(prompt, files)

    # 0. Hardblock deterministico
    if any(p in full_text for p in HARDBLOCK_PATTERNS):
        return {"decision": "BLOCK", "reason": "hardblock_pattern", "surface": surface}

    # 0b. Logging en dominio sensible
    if any(kw in prompt.lower() for kw in LOGGING_KEYWORDS):
        if any(d in prompt.lower() for d in SENSITIVE_DOMAINS):
            return {"decision": "REVISE", "reason": "logging_sensitive_domain", "surface": surface}

    # 1. Infra
    if infra_block or infra_score >= 35:
        return {"decision": "BLOCK", "reason": "infra_critical_finding", "surface": surface}

    # 2. Trivial surface
    if surface in TRIVIAL_SURFACES:
        if not any(kw in full_text for kw in BLOCK_KEYWORDS):
            return {"decision": "APPROVE", "reason": "trivial_surface", "surface": surface}

    # 3. Block keywords
    if any(kw in full_text for kw in BLOCK_KEYWORDS):
        return {"decision": "BLOCK", "reason": "block_keyword", "surface": surface}

    # 4. Block intents
    if intent_label in BLOCK_INTENTS:
        return {"decision": "BLOCK", "reason": f"block_intent:{intent_label}", "surface": surface}

    # 5. Runtime bugfix
    if any(kw in prompt.lower() for kw in BUGFIX_KEYWORDS) and surface == "runtime":
        return {"decision": "REVISE", "reason": "runtime_bugfix", "surface": surface}

    # 6. Balanced = APPROVE
    if mode == "balanced":
        return {"decision": "APPROVE", "reason": "balanced_mode_no_risk", "surface": surface}

    # 7. Revise intents
    if intent_label in REVISE_INTENTS:
        return {"decision": "REVISE", "reason": f"revise_intent:{intent_label}", "surface": surface}

    # 8. Safety flow action
    if safety_action in {"NEEDS_VERIFICATION", "NEEDS_REPAIR", "REVISE"}:
        return {"decision": "REVISE", "reason": f"safety_flow:{safety_action}", "surface": surface}

    return {"decision": "APPROVE", "reason": "no_risk_signals", "surface": surface}
