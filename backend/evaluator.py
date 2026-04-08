"""
evaluator.py — deterministic quality layer for DevMind summaries.

Three responsibilities:
  1. pre_analyse(pr_data)      → structural signals extracted BEFORE the LLM call,
                                  injected into the prompt so the model has richer context.
  2. evaluate(summary, pr_data) → scores and flags computed AFTER the LLM call,
                                  attached to the response.
  3. infer_risk_floor(files)   → minimum risk level based on file path heuristics;
                                  the model can only go up from here, never below.
"""

import re
from dataclasses import dataclass, field, asdict

# ── Generic phrase detector ────────────────────────────────────────────────────
# Phrases that signal the model ignored the specificity rules.
# Scored by severity: 2 = always vague, 1 = sometimes acceptable.

GENERIC_PHRASES: list[tuple[str, int]] = [
    # severity 2 — never acceptable
    (r"\bimproves code quality\b", 2),
    (r"\brefactors? (?:the )?code\b", 2),
    (r"\bmakes? (?:some )?changes? to\b", 2),
    (r"\bupdates? (?:the )?logic\b", 2),
    (r"\badds? functionality\b", 2),
    (r"\bthis PR (?:modifies?|updates?|changes?)\b", 2),
    (r"\bgeneral (?:improvements?|cleanup)\b", 2),
    (r"\bvarious (?:fixes?|improvements?|updates?)\b", 2),
    (r"\bmay cause issues\b", 2),
    (r"\bcould (?:potentially )?(?:break|affect|impact)\b", 2),
    (r"\bsome (?:files?|functions?|methods?)\b", 2),
    # severity 1 — weak but not fatal
    (r"\bclean(?:s|ed|ing)? up\b", 1),
    (r"\bminor (?:fixes?|changes?|tweaks?)\b", 1),
    (r"\bimprove[sd]? performance\b", 1),
    (r"\benhance[sd]? (?:the )?(?:user experience|UX|readability)\b", 1),
    (r"\boptimize[sd]?\b", 1),
    (r"\bunclear from (?:the )?(?:context|description)\b", 1),
]

# ── Specificity signals — things that make a summary trustworthy ───────────────

# Patterns that indicate concrete technical grounding
SPECIFIC_PATTERNS: list[tuple[str, int]] = [
    # file extensions in text (model referenced an actual file)
    (r"\b\w+\.(py|js|ts|tsx|jsx|go|rb|java|rs|sql|yaml|yml|json|toml|sh|env)\b", 3),
    # function/method call syntax
    (r"\b\w+\((?:\w+)?\)", 2),
    # class names (CamelCase, at least 2 segments)
    (r"\b[A-Z][a-z]+[A-Z][a-zA-Z]+\b", 2),
    # config keys / env vars
    (r"\b[A-Z][A-Z_]{3,}\b", 2),
    # path segments
    (r"\b(?:src|api|db|auth|routes?|models?|services?|utils?|handlers?|middleware)/\w+", 2),
    # SQL keywords (model is talking about DB schema)
    (r"\b(?:SELECT|INSERT|UPDATE|DELETE|CREATE TABLE|ALTER TABLE|INDEX ON)\b", 3),
    # HTTP methods + paths
    (r"\b(?:GET|POST|PUT|PATCH|DELETE)\s+/\w+", 2),
    # version numbers / semver
    (r"\bv?\d+\.\d+(?:\.\d+)?\b", 1),
    # numeric line counts (model is being quantitative)
    (r"\b\d{2,} (?:lines?|files?|tests?|cases?)\b", 1),
]

# ── Risk inference — file path heuristics ─────────────────────────────────────
# Maps regex patterns (matched against file paths) to (risk_floor, tag).
# risk_floor: "low" | "medium" | "high"
# tag: short label shown in the frontend

RISK_FILE_RULES: list[tuple[str, str, str]] = [
    # Auth & credentials — high
    (r"auth|oauth|jwt|token|session|passw|cred|secret|key(?!board)", "high",  "auth"),
    # Database schema changes — high
    (r"migrat|schema|alembic|flyway|liquibase|\.sql$",               "high",  "db-migration"),
    # Payment / billing — high
    (r"payment|billing|stripe|checkout|invoice|wallet|charge",       "high",  "payments"),
    # Infrastructure / deployment — high
    (r"docker|dockerfile|\.terraform|cloudformation|k8s|kubernetes|helm|deploy|infra", "high", "infra"),
    # Security config — high
    (r"csp|cors|security|firewall|acl|permission|rbac|policy",       "high",  "security"),
    # Concurrency primitives — medium
    (r"lock|mutex|semaphor|async|await|thread|worker|queue|celery",  "medium","concurrency"),
    # Database ORM / queries — medium
    (r"model[s]?/|orm|repository|dao|query|prisma|sequelize|sqlalchemy|hibernate", "medium", "db-query"),
    # API surface — medium
    (r"route[s]?/|endpoint|controller|handler|view[s]?/|serializer", "medium","api"),
    # Configuration files — medium
    (r"config|settings|\.env|environment|feature.flag",               "medium","config"),
    # Test files — low (changes here rarely break prod)
    (r"test[s]?/|spec[s]?/|__test__|\.test\.|\.spec\.",              "low",   "tests"),
]

# Lines-changed threshold below which a sensitive file is treated as trivially touched.
# Prevents a 1-line comment fix in auth.py from pinning the whole PR to high risk.
TRIVIAL_CHURN_THRESHOLD = 8

RISK_LEVELS = {"low": 0, "medium": 1, "high": 2}
RISK_LABELS = {0: "low", 1: "medium", 2: "high"}
# — Security pattern detector ————————————————————————————————————————
SECURITY_PATTERNS: list[tuple[str, str]] = [
    (r"password|passwd|pwd",           "sensitive_data"),
    (r"token|api_key|secret|jwt",      "sensitive_data"),
    (r"except\s+Exception",            "broad_exception"),
    (r"verify\s*=\s*False",            "tls_disabled"),
    (r"charge|payment|transfer",       "financial_logic"),
    (r"eval\(|exec\(|__import__",      "code_injection"),
    (r"request\.(get|post|data|form)",  "input_handling"),
    (r"CVE-\d{4}-\d+",                 "known_cve"),
]

# ── Public interface ───────────────────────────────────────────────────────────

@dataclass
class PreAnalysis:
    """Structural signals computed before the LLM call."""
    risk_floor: str                      # "low" | "medium" | "high"
    risk_tags: list[str]                 # e.g. ["auth", "db-migration"]
    flagged_files: list[str]             # filenames that triggered risk rules
    total_diff_chars: int
    files_with_diff: int
    files_skipped_noise: int
    files_skipped_budget: int
    trivially_touched: list[str]  # sensitive files dampened due to low churn

    def to_prompt_context(self) -> str:
        """Renders as a compact block injected into the LLM prompt."""
        lines = [
            "## DevMind pre-analysis (computed from file paths — do not ignore)",
            f"Risk floor (minimum): {self.risk_floor.upper()}",
        ]
        if self.risk_tags:
            lines.append(f"Sensitive areas detected: {', '.join(self.risk_tags)}")
        if self.flagged_files:
            lines.append("Flagged files:")
            for f in self.flagged_files[:8]:
                lines.append(f"  - {f}")
        lines.append(
            f"Diff coverage: {self.files_with_diff} files with diff, "
            f"{self.files_skipped_budget} truncated due to budget, "
            f"{self.files_skipped_noise} excluded as noise."
        )
        if self.files_skipped_budget > 0:
            lines.append(
                "NOTE: Some files were not included in the diff. "
                "Acknowledge this limitation in your analysis."
            )
        return "\n".join(lines)


@dataclass
class Evaluation:
    """Quality signals computed after the LLM call."""
    confidence: str                           # "high" | "medium" | "low"
    confidence_score: float                   # 0.0–1.0
    specificity_score: float                  # 0.0–1.0 — how concrete is the text
    generic_phrases_found: list[str]          # exact matches, deduplicated
    generic_penalty: int                      # total severity points deducted
    is_flagged: bool                          # True if summary is too vague to trust
    flag_reason: str | None                   # human-readable explanation

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class UsefulnessCheck:
    """
    Developer-perspective usefulness check.
    Answers: "Can a dev act on this summary without opening the PR?"
    Distinct from Evaluation (which checks prompt adherence).
    """
    is_useful: bool
    usefulness_level: str          # "high" | "medium" | "low"
    has_filenames: bool
    has_functions: bool
    has_specific_changes: bool
    missing: list[str]             # what was expected but absent
    evidence: dict[str, list[str]] # what was found per category

    def to_dict(self) -> dict:
        return asdict(self)


# ── Usefulness check patterns ─────────────────────────────────────────────────
# These are looser than SPECIFIC_PATTERNS — we just need evidence of each
# category being present, not a weighted score.

_FILENAME_RE  = re.compile(r"\b[\w/-]+\.(?:py|js|ts|tsx|jsx|go|rb|java|rs|sql|yaml|yml|json|toml|sh|cfg|ini|env|md)\b")
_FUNCTION_RE  = re.compile(r"\b(\w+)\((?:[\w,\s*]*)\)|`(\w+)`|\b(?:def|function|func|fn)\s+(\w+)")
_CHANGE_RE    = re.compile(
    r"\b(?:add(?:s|ed)?|remov(?:e[sd]?)|replac(?:e[sd]?)|renam(?:e[sd]?)|"
    r"mov(?:e[sd]?)|fix(?:es|ed)?|introduc(?:e[sd]?)|deprecat(?:e[sd]?)|"
    r"migrat(?:e[sd]?)|extract(?:s|ed)?|split[s]?|merges?)\b"
)


def usefulness_check(summary: dict) -> UsefulnessCheck:
    """
    Checks whether a summary gives a developer concrete, actionable information.
    Runs on the same summary dict returned by the LLM.
    """
    text_parts = [
        summary.get("what", ""),
        summary.get("why", ""),
        summary.get("impact", ""),
        summary.get("review_focus", ""),
        (summary.get("risk") or {}).get("reason", ""),
        " ".join(summary.get("key_changes") or []),
    ]
    full_text = " ".join(text_parts)

    # ── 1. Filename presence ──────────────────────────────────────────────────
    filenames_found = _FILENAME_RE.findall(full_text)
    has_filenames = len(filenames_found) > 0

    # ── 2. Function/identifier presence ──────────────────────────────────────
    func_matches = _FUNCTION_RE.findall(full_text)
    functions_found = [next(g for g in m if g) for m in func_matches if any(m)]
    has_functions = len(functions_found) > 0

    # ── 3. Concrete change verbs ──────────────────────────────────────────────
    change_matches = _CHANGE_RE.findall(full_text.lower())
    has_specific_changes = len(change_matches) >= 2  # at least 2 distinct action verbs

    # ── 4. Missing categories ─────────────────────────────────────────────────
    missing = []
    if not has_filenames:
        missing.append("file names")
    if not has_functions:
        missing.append("function or identifier names")
    if not has_specific_changes:
        missing.append("concrete change verbs (add/remove/replace/fix/...)")

    # ── 5. Usefulness level ───────────────────────────────────────────────────
    present = sum([has_filenames, has_functions, has_specific_changes])
    if present == 3:
        usefulness_level = "high"
        is_useful = True
    elif present == 2:
        usefulness_level = "medium"
        is_useful = True
    else:
        usefulness_level = "low"
        is_useful = False

    return UsefulnessCheck(
        is_useful=is_useful,
        usefulness_level=usefulness_level,
        has_filenames=has_filenames,
        has_functions=has_functions,
        has_specific_changes=has_specific_changes,
        missing=missing,
        evidence={
            "filenames":  filenames_found[:5],
            "functions":  functions_found[:5],
            "change_verbs": list(dict.fromkeys(change_matches))[:8],
        },
    )


def pre_analyse(pr_data: dict) -> PreAnalysis:
    """
    Runs before the LLM. Extracts structural risk signals from file paths.
    Returns a PreAnalysis that gets injected into the prompt.
    """
    files = pr_data.get("files", [])

    risk_level = 0
    risk_tags: list[str] = []
    flagged_files: list[str] = []
    trivially_touched: list[str] = []
    files_with_diff = 0
    files_skipped_noise = 0
    files_skipped_budget = 0

    for f in files:
        filename = f.get("filename", "").lower()
        skip = f.get("skipped_reason")

        if skip == "generated/lockfile":
            files_skipped_noise += 1
        elif skip == "budget_exceeded":
            files_skipped_budget += 1
        elif f.get("diff"):
            files_with_diff += 1

        for pattern, floor, tag in RISK_FILE_RULES:
            if re.search(pattern, filename, re.IGNORECASE):
                floor_level = RISK_LEVELS.get(floor, 0)

                # ── False-positive dampening ──────────────────────────────
                # A sensitive file touched with only trivial changes (e.g. a
                # comment fix in auth.py, or a whitespace change in .env.example)
                # should not hard-pin the PR to "high".
                # Rule: if total churn on this file is < TRIVIAL_CHURN_THRESHOLD
                # lines, we cap its contribution one level below the rule's floor.
                # We still record the tag so the developer knows the file was touched.
                churn = f.get("additions", 0) + f.get("deletions", 0)
                if churn < TRIVIAL_CHURN_THRESHOLD and floor_level > 0:
                    floor_level = floor_level - 1  # e.g. high→medium, medium→low
                    if f["filename"] not in trivially_touched:
                        trivially_touched.append(f["filename"])

                if floor_level > risk_level:
                    risk_level = floor_level
                if tag not in risk_tags:
                    risk_tags.append(tag)
                if f["filename"] not in flagged_files:
                    flagged_files.append(f["filename"])
                break  # one rule per file is enough

    # — Security scan on diff content ————————————————
    security_flags: list[str] = []
    full_diff = " ".join([
        pr_data.get("title", ""),
        pr_data.get("body", "") or "",
        " ".join(pr_data.get("commit_messages", [])),
        " ".join(f.get("diff") or "" for f in files),
    ])
    for pattern, flag in SECURITY_PATTERNS:
        if re.search(pattern, full_diff, re.IGNORECASE):
            if flag not in security_flags:
                security_flags.append(flag)
    if security_flags and "security" not in risk_tags:
        risk_tags.append("security")
    if "known_cve" in security_flags or "tls_disabled" in security_flags:
        if risk_level < RISK_LEVELS["medium"]:
            risk_level = RISK_LEVELS["medium"]
    total_diff_chars = sum(
        len(f.get("diff") or "") for f in files
    )

    return PreAnalysis(
        risk_floor=RISK_LABELS[risk_level],
        risk_tags=risk_tags,
        flagged_files=flagged_files,
        total_diff_chars=total_diff_chars,
        files_with_diff=files_with_diff,
        files_skipped_noise=files_skipped_noise,
        files_skipped_budget=files_skipped_budget,
        trivially_touched=trivially_touched,
    )


def evaluate(summary: dict, pr_data: dict) -> Evaluation:
    """
    Runs after the LLM. Scores the summary for specificity and genericity.
    Returns an Evaluation attached to the API response.
    """
    # Concatenate all text fields we want to evaluate
    text_fields = {
        "what":         summary.get("what", ""),
        "why":          summary.get("why", ""),
        "impact":       summary.get("impact", ""),
        "review_focus": summary.get("review_focus", ""),
        "risk_reason":  (summary.get("risk") or {}).get("reason", ""),
        "key_changes":  " ".join(summary.get("key_changes") or []),
    }
    full_text = " ".join(text_fields.values())
    full_text_lower = full_text.lower()

    # ── 1. Generic phrase detection ───────────────────────────────────────────
    found_phrases: list[str] = []
    total_penalty = 0
    for pattern, severity in GENERIC_PHRASES:
        matches = re.findall(pattern, full_text_lower)
        if matches:
            found_phrases.append(matches[0])
            total_penalty += severity * len(matches)

    # ── 2. Specificity scoring ────────────────────────────────────────────────
    specificity_hits = 0
    specificity_max = 0
    for pattern, weight in SPECIFIC_PATTERNS:
        specificity_max += weight * 3  # assume 3 opportunities per pattern
        hits = len(re.findall(pattern, full_text))
        specificity_hits += min(hits, 3) * weight  # cap contribution per pattern

    raw_specificity = specificity_hits / specificity_max if specificity_max else 0
    specificity_score = round(min(raw_specificity, 1.0), 3)

    # ── 3. Length sanity check ────────────────────────────────────────────────
    # A very short summary is a red flag regardless of specificity
    total_chars = len(full_text)
    length_penalty = 0
    if total_chars < 200:
        length_penalty = 0.3
    elif total_chars < 400:
        length_penalty = 0.1

    # ── 4. Composite confidence score ─────────────────────────────────────────
    # Formula:
    #   base = specificity_score
    #   - generic_penalty: each severity-2 hit costs 0.15, severity-1 costs 0.07
    #   - length_penalty
    #   clamp to [0, 1]

    generic_deduction = 0.0
    for pattern, severity in GENERIC_PHRASES:
        if re.search(pattern, full_text_lower):
            generic_deduction += 0.15 if severity == 2 else 0.07

    raw_score = specificity_score - generic_deduction - length_penalty
    confidence_score = round(max(0.0, min(1.0, raw_score)), 3)

    # ── 5. Confidence label ───────────────────────────────────────────────────
    if confidence_score >= 0.55:
        confidence = "high"
    elif confidence_score >= 0.30:
        confidence = "medium"
    else:
        confidence = "low"

    # ── 6. Flag decision ──────────────────────────────────────────────────────
    is_flagged = False
    flag_reason = None

    if total_penalty >= 4:
        is_flagged = True
        flag_reason = (
            f"Summary contains {len(found_phrases)} generic phrase(s): "
            f"{', '.join(repr(p) for p in found_phrases[:3])}. "
            "Consider re-running or reviewing manually."
        )
    elif specificity_score < 0.10 and pr_data.get("changed_files", 0) > 2:
        is_flagged = True
        flag_reason = (
            "No specific file names, functions, or identifiers found in the summary "
            f"despite {pr_data['changed_files']} files changed. "
            "The diff may have been too large to analyse fully."
        )
    elif total_chars < 150:
        is_flagged = True
        flag_reason = "Summary is unusually short — likely incomplete."

    return Evaluation(
        confidence=confidence,
        confidence_score=confidence_score,
        specificity_score=specificity_score,
        generic_phrases_found=list(dict.fromkeys(found_phrases)),  # deduplicate, preserve order
        generic_penalty=total_penalty,
        is_flagged=is_flagged,
        flag_reason=flag_reason,
    )


def enforce_risk_floor(summary: dict, pre: PreAnalysis) -> dict:
    """
    Ensures the model's risk level is never BELOW the heuristic floor.
    If the model said 'low' but we detected auth files, escalate to 'medium'/'high'.
    Mutates summary in place and returns it.
    """
    risk = summary.get("risk", {})
    if not isinstance(risk, dict):
        return summary

    model_level = RISK_LEVELS.get(risk.get("level", "low"), 0)
    floor_level = RISK_LEVELS.get(pre.risk_floor, 0)

    if floor_level > model_level:
        old_level = risk.get("level", "low")
        risk["level"] = pre.risk_floor
        risk["reason"] = (
            f"[Risk escalated from {old_level} to {pre.risk_floor} — "
            f"sensitive areas detected: {', '.join(pre.risk_tags)}] "
            + risk.get("reason", "")
        )
        summary["risk"] = risk

    return summary
