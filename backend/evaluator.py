
from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Any

# =============================================================================
# DevMind evaluator.py
#
# Responsibilities:
#   1) pre_analyse(pr_data)
#      - deterministic structural signals before LLM call
#   2) evaluate(summary, pr_data)
#      - deterministic quality scoring after LLM call
#   3) enforce_risk_floor(summary, pre)
#      - never allow the LLM to undercut the structural floor
#
# Philosophy:
#   - LLM produces structured evidence and reasoning.
#   - Deterministic layer decides triage and merge blocking.
#   - Every score must be explainable from the PR.
# =============================================================================


# -----------------------------------------------------------------------------
# Generic language detector
# -----------------------------------------------------------------------------
GENERIC_PHRASES: list[tuple[str, int]] = [
    (r"\bimproves code quality\b", 2),
    (r"\brefactors? (?:the )?code\b", 2),
    (r"\bmakes? (?:some )?changes? to\b", 2),
    (r"\bupdates? (?:the )?logic\b", 2),
    (r"\badds? functionality\b", 2),
    (r"\bthis pr (?:modifies?|updates?|changes?)\b", 2),
    (r"\bgeneral (?:improvements?|cleanup)\b", 2),
    (r"\bvarious (?:fixes?|improvements?|updates?)\b", 2),
    (r"\bmay cause issues\b", 2),
    (r"\bcould (?:potentially )?(?:break|affect|impact)\b", 2),
    (r"\bsome (?:files?|functions?|methods?)\b", 2),
    (r"\bclean(?:s|ed|ing)? up\b", 1),
    (r"\bminor (?:fixes?|changes?|tweaks?)\b", 1),
    (r"\bimprove[sd]? performance\b", 1),
    (r"\benhance[sd]? (?:the )?(?:user experience|ux|readability)\b", 1),
    (r"\boptimize[sd]?\b", 1),
    (r"\bunclear from (?:the )?(?:context|description)\b", 1),
]

# -----------------------------------------------------------------------------
# Specificity detector
# -----------------------------------------------------------------------------
SPECIFIC_PATTERNS: list[tuple[str, int]] = [
    (r"\b\w+\.(py|js|ts|tsx|jsx|go|rb|java|rs|sql|yaml|yml|json|toml|sh|env)\b", 3),
    (r"\b\w+\((?:\w+)?\)", 2),
    (r"\b[A-Z][a-z]+[A-Z][a-zA-Z]+\b", 2),
    (r"\b[A-Z][A-Z_]{3,}\b", 2),
    (r"\b(?:src|api|db|auth|routes?|models?|services?|utils?|handlers?|middleware)/\w+", 2),
    (r"\b(?:SELECT|INSERT|UPDATE|DELETE|CREATE TABLE|ALTER TABLE|INDEX ON)\b", 3),
    (r"\b(?:GET|POST|PUT|PATCH|DELETE)\s+/\w+", 2),
    (r"\bv?\d+\.\d+(?:\.\d+)?\b", 1),
    (r"\b\d{2,} (?:lines?|files?|tests?|cases?)\b", 1),
]

# -----------------------------------------------------------------------------
# File-path heuristics for structural risk floor
# -----------------------------------------------------------------------------
RISK_FILE_RULES: list[tuple[str, str, str]] = [
    (r"auth|oauth|jwt|token|session|passw|cred|secret|key(?!board)", "high", "auth"),
    (r"migrat|schema|alembic|flyway|liquibase|\.sql$", "high", "db-migration"),
    (r"payment|billing|stripe|checkout|invoice|wallet|charge", "high", "payments"),
    (r"docker|dockerfile|\.terraform|cloudformation|k8s|kubernetes|helm|deploy|infra", "high", "infra"),
    (r"csp|cors|security|firewall|acl|permission|rbac|policy", "high", "security"),
    (r"lock|mutex|semaphor|async|await|thread|worker|queue|celery", "medium", "concurrency"),
    (r"model[s]?/|orm|repository|dao|query|prisma|sequelize|sqlalchemy|hibernate", "medium", "db-query"),
    (r"route[s]?/|endpoint|controller|handler|view[s]?/|serializer", "medium", "api"),
    (r"config|settings|\.env|environment|feature.flag", "medium", "config"),
    (r"test[s]?/|spec[s]?/|__test__|\.test\.|\.spec\.", "low", "tests"),
]

TRIVIAL_CHURN_THRESHOLD = 8

RISK_LEVELS = {"low": 0, "medium": 1, "high": 2}
RISK_LABELS = {0: "low", 1: "medium", 2: "high"}

# -----------------------------------------------------------------------------
# Security pattern detector
# -----------------------------------------------------------------------------
SECURITY_PATTERNS: list[tuple[str, str]] = [
    (r"password|passwd|pwd", "sensitive_data"),
    (r"token|api_key|secret|jwt", "sensitive_data"),
    (r"except\s+Exception", "broad_exception"),
    (r"verify\s*=\s*False", "tls_disabled"),
    (r"charge|payment|transfer", "financial_logic"),
    (r"eval\(|exec\(|__import__", "code_injection"),
    (r"request\.(get|post|data|form)", "input_handling"),
    (r"CVE-\d{4}-\d+", "known_cve"),
]

# -----------------------------------------------------------------------------
# Dataclasses
# -----------------------------------------------------------------------------
@dataclass
class PreAnalysis:
    risk_floor: str
    risk_tags: list[str]
    flagged_files: list[str]
    total_diff_chars: int
    files_with_diff: int
    files_skipped_noise: int
    files_skipped_budget: int
    trivially_touched: list[str]

    def to_prompt_context(self) -> str:
        lines = [
            "## DevMind pre-analysis",
            f"Risk floor (minimum): {self.risk_floor.upper()}",
        ]
        if self.risk_tags:
            lines.append(f"Sensitive areas detected: {', '.join(self.risk_tags)}")
        if self.flagged_files:
            lines.append("Flagged files:")
            for f in self.flagged_files[:8]:
                lines.append(f"  - {f}")
        if self.trivially_touched:
            lines.append("Sensitive files with trivial churn:")
            for f in self.trivially_touched[:8]:
                lines.append(f"  - {f}")
        lines.append(
            f"Diff coverage: {self.files_with_diff} files with diff, "
            f"{self.files_skipped_budget} truncated due to budget, "
            f"{self.files_skipped_noise} excluded as noise."
        )
        if self.files_skipped_budget > 0:
            lines.append(
                "NOTE: Some files were not included in the diff. "
                "Acknowledge this limitation in the analysis."
            )
        return "\n".join(lines)


@dataclass
class Evaluation:
    confidence: str
    confidence_score: float
    specificity_score: float
    generic_phrases_found: list[str]
    generic_penalty: int
    is_flagged: bool
    flag_reason: str | None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class UsefulnessCheck:
    is_useful: bool
    usefulness_level: str
    has_filenames: bool
    has_functions: bool
    has_specific_changes: bool
    missing: list[str]
    evidence: dict[str, list[str]]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RiskSignals:
    p_signals: dict[str, float]
    p_score: float
    i_signals: dict[str, float]
    i_score: float
    c_signals: dict[str, float]
    c_score: float
    risk_score: int
    risk_band: str
    risk_label: str
    top_factors: list[str]
    triage: str
    merge_blocker: bool

    def to_dict(self) -> dict:
        return asdict(self)


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------
def infer_risk_floor(files: list[dict]) -> PreAnalysis:
    """
    Compatibility helper: build a minimal structural analysis from files only.
    """
    fake_pr = {"files": files, "changed_files": len(files), "additions": 0, "deletions": 0}
    return pre_analyse(fake_pr)


def pre_analyse(pr_data: dict) -> PreAnalysis:
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
                churn = f.get("additions", 0) + f.get("deletions", 0)

                if churn < TRIVIAL_CHURN_THRESHOLD and floor_level > 0:
                    floor_level = floor_level - 1
                    if f.get("filename") not in trivially_touched:
                        trivially_touched.append(f.get("filename", ""))

                risk_level = max(risk_level, floor_level)

                if tag not in risk_tags:
                    risk_tags.append(tag)
                if f.get("filename") not in flagged_files:
                    flagged_files.append(f.get("filename", ""))
                break

    full_diff = " ".join(
        [
            pr_data.get("title", "") or "",
            pr_data.get("body", "") or "",
            " ".join(pr_data.get("commit_messages", [])),
            " ".join(f.get("diff") or "" for f in files),
        ]
    )

    security_flags: list[str] = []
    for pattern, flag in SECURITY_PATTERNS:
        if re.search(pattern, full_diff, re.IGNORECASE):
            if flag not in security_flags:
                security_flags.append(flag)

    if security_flags and "security" not in risk_tags:
        risk_tags.append("security")

    if "known_cve" in security_flags or "tls_disabled" in security_flags:
        risk_level = max(risk_level, RISK_LEVELS["medium"])

    diff_only = " ".join(f.get("diff") or "" for f in files)
    cve_count = len(set(re.findall(r"CVE-\d{4}-\d+", full_diff)))
    cve_in_diff = len(set(re.findall(r"CVE-\d{4}-\d+", diff_only)))

    if cve_count >= 3 or cve_in_diff >= 2:
        risk_level = max(risk_level, RISK_LEVELS["high"])

    total_diff_chars = sum(len(f.get("diff") or "") for f in files)

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


def usefulness_check(summary: dict) -> UsefulnessCheck:
    text_parts = [
        summary.get("what", ""),
        summary.get("why", ""),
        summary.get("impact", ""),
        summary.get("review_focus", ""),
        (summary.get("risk") or {}).get("reason", ""),
        " ".join(summary.get("key_changes") or []),
    ]
    full_text = " ".join(text_parts)

    filenames_found = _FILENAME_RE.findall(full_text)
    has_filenames = len(filenames_found) > 0

    func_matches = _FUNCTION_RE.findall(full_text)
    functions_found = [next((g for g in m if g), "") for m in func_matches if any(m)]
    functions_found = [f for f in functions_found if f]
    has_functions = len(functions_found) > 0

    change_matches = _CHANGE_RE.findall(full_text.lower())
    has_specific_changes = len(change_matches) >= 2

    missing = []
    if not has_filenames:
        missing.append("file names")
    if not has_functions:
        missing.append("function or identifier names")
    if not has_specific_changes:
        missing.append("concrete change verbs")

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
            "filenames": filenames_found[:5],
            "functions": functions_found[:5],
            "change_verbs": list(dict.fromkeys(change_matches))[:8],
        },
    )


def evaluate(summary: dict, pr_data: dict) -> dict:
    """
    Deterministic post-LLM evaluation.
    Returns a dict because the summarizer expects scores/triage/merge_blocker.
    """
    pre = pre_analyse(pr_data)
    ev = _evaluate_summary_quality(summary, pr_data)
    signals = compute_risk_score(pre, summary, ev, pr_data)
    usefulness = usefulness_check(summary)

    return {
        "scores": {
            "risk_score": signals.risk_score,
            "risk_band": signals.risk_band,
            "risk_label": signals.risk_label,
            "exploitability_score": round(signals.p_score, 3),
            "impact_score": round(signals.i_score, 3),
            "confidence_score": round(signals.c_score, 3),
            "top_factors": signals.top_factors,
        },
        "triage": signals.triage,
        "merge_blocker": signals.merge_blocker,
        "risk_signals": signals.to_dict(),
        "evaluation": ev.to_dict(),
        "usefulness": usefulness.to_dict(),
    }


def enforce_risk_floor(summary: dict, pre: PreAnalysis) -> dict:
    risk = summary.get("risk", {})
    if not isinstance(risk, dict):
        return summary

    model_level = RISK_LEVELS.get(str(risk.get("level", "low")).lower(), 0)
    floor_level = RISK_LEVELS.get(pre.risk_floor, 0)

    if floor_level > model_level:
        old_level = risk.get("level", "low")
        risk["level"] = pre.risk_floor
        reason = str(risk.get("reason", "")).strip()
        prefix = (
            f"[Risk escalated from {old_level} to {pre.risk_floor} - "
            f"sensitive areas detected: {', '.join(pre.risk_tags)}] "
        )
        risk["reason"] = prefix + reason if reason else prefix.strip()
        summary["risk"] = risk

    return summary


# -----------------------------------------------------------------------------
# LLM quality evaluation
# -----------------------------------------------------------------------------
def _evaluate_summary_quality(summary: dict, pr_data: dict) -> Evaluation:
    text_fields = {
        "what": summary.get("what", ""),
        "why": summary.get("why", ""),
        "impact": summary.get("impact", ""),
        "review_focus": summary.get("review_focus", ""),
        "risk_reason": (summary.get("risk") or {}).get("reason", ""),
        "key_changes": " ".join(summary.get("key_changes") or []),
    }
    full_text = " ".join(text_fields.values())
    full_text_lower = full_text.lower()

    found_phrases: list[str] = []
    total_penalty = 0
    for pattern, severity in GENERIC_PHRASES:
        matches = re.findall(pattern, full_text_lower)
        if matches:
            found_phrases.append(matches[0])
            total_penalty += severity * len(matches)

    specificity_hits = 0
    specificity_max = 0
    for pattern, weight in SPECIFIC_PATTERNS:
        specificity_max += weight * 3
        hits = len(re.findall(pattern, full_text))
        specificity_hits += min(hits, 3) * weight

    raw_specificity = specificity_hits / specificity_max if specificity_max else 0.0
    specificity_score = round(min(raw_specificity, 1.0), 3)

    total_chars = len(full_text)
    length_penalty = 0.0
    if total_chars < 200:
        length_penalty = 0.3
    elif total_chars < 400:
        length_penalty = 0.1

    generic_deduction = 0.0
    for pattern, severity in GENERIC_PHRASES:
        if re.search(pattern, full_text_lower):
            generic_deduction += 0.15 if severity == 2 else 0.07

    raw_score = specificity_score - generic_deduction - length_penalty
    confidence_score = round(max(0.0, min(1.0, raw_score)), 3)

    if confidence_score >= 0.55:
        confidence = "high"
    elif confidence_score >= 0.30:
        confidence = "medium"
    else:
        confidence = "low"

    is_flagged = False
    flag_reason = None

    if total_penalty >= 4:
        is_flagged = True
        flag_reason = (
            f"Summary contains {len(found_phrases)} generic phrase(s): "
            f"{', '.join(repr(p) for p in found_phrases[:3])}."
        )
    elif specificity_score < 0.10 and pr_data.get("changed_files", 0) > 2:
        is_flagged = True
        flag_reason = (
            "No specific file names, functions, or identifiers found in the summary "
            f"despite {pr_data.get('changed_files', 0)} files changed."
        )
    elif total_chars < 150:
        is_flagged = True
        flag_reason = "Summary is unusually short and likely incomplete."

    return Evaluation(
        confidence=confidence,
        confidence_score=confidence_score,
        specificity_score=specificity_score,
        generic_phrases_found=list(dict.fromkeys(found_phrases)),
        generic_penalty=total_penalty,
        is_flagged=is_flagged,
        flag_reason=flag_reason,
    )


# -----------------------------------------------------------------------------
# Risk engine
# -----------------------------------------------------------------------------
_P_WEIGHTS = {
    "tag_auth": 0.90,
    "tag_payments": 0.90,
    "tag_infra": 0.80,
    "tag_security": 0.85,
    "tag_db_migration": 0.75,
    "tag_concurrency": 0.60,
    "tag_db_query": 0.50,
    "tag_api": 0.45,
    "tag_config": 0.40,
    "no_tests_touched": 0.40,
    "large_diff": 0.30,
    "many_files": 0.25,
    "has_cve_refs": 0.70,
    "security_patterns": 0.55,
}

_I_WEIGHTS = {
    "floor_high": 1.00,
    "floor_medium": 0.55,
    "floor_low": 0.20,
    "llm_high": 0.80,
    "llm_medium": 0.45,
    "llm_low": 0.15,
    "additions_large": 0.30,
    "additions_medium": 0.15,
    "deletions_large": 0.20,
    "many_changed_files": 0.25,
    "vulnerabilities_found": 0.60,
    "attack_path_present": 0.25,
    "ci_cd_risk_present": 0.20,
}

_C_WEIGHTS = {
    "specificity_high": 1.00,
    "specificity_med": 0.65,
    "specificity_low": 0.25,
    "not_flagged": 0.20,
    "diff_coverage_full": 0.15,
    "diff_coverage_partial": -0.20,
    "large_pr_chunked": -0.10,
    "no_diff_available": -0.30,
}


@dataclass
class RiskSignals:
    p_signals: dict[str, float]
    p_score: float
    i_signals: dict[str, float]
    i_score: float
    c_signals: dict[str, float]
    c_score: float
    risk_score: int
    risk_band: str
    risk_label: str
    top_factors: list[str]
    triage: str
    merge_blocker: bool

    def to_dict(self) -> dict:
        return asdict(self)


def _weighted_sum(signals: dict[str, float], weights: dict[str, float]) -> float:
    if not signals:
        return 0.0

    active = [(k, max(0.0, min(1.0, v)), weights.get(k, 0.0)) for k, v in signals.items()]
    denom = sum(abs(w) for _, _, w in active if w != 0)
    if denom <= 0:
        return 0.0

    numer = sum(v * w for _, v, w in active)
    score = numer / denom
    return max(0.0, min(1.0, score))


def _extract_p_signals(pre: PreAnalysis, pr_data: dict) -> dict[str, float]:
    signals: dict[str, float] = {}
    tags = set(pre.risk_tags)

    if "auth" in tags:
        signals["tag_auth"] = 1.0
    if "payments" in tags:
        signals["tag_payments"] = 1.0
    if "infra" in tags:
        signals["tag_infra"] = 1.0
    if "security" in tags:
        signals["tag_security"] = 1.0
    if "db-migration" in tags:
        signals["tag_db_migration"] = 1.0
    if "concurrency" in tags:
        signals["tag_concurrency"] = 1.0
    if "db-query" in tags:
        signals["tag_db_query"] = 1.0
    if "api" in tags:
        signals["tag_api"] = 1.0
    if "config" in tags:
        signals["tag_config"] = 1.0

    files = pr_data.get("files", [])
    has_tests = any(
        re.search(r"test[s]?/|spec[s]?/|__test__|\.(test|spec)\.", f.get("filename", ""), re.IGNORECASE)
        for f in files
    )
    if not has_tests:
        signals["no_tests_touched"] = 1.0

    additions = pr_data.get("additions", 0)
    changed_files = pr_data.get("changed_files", 0)
    if additions > 500:
        signals["large_diff"] = 1.0
    elif additions > 150:
        signals["large_diff"] = 0.5

    if changed_files > 15:
        signals["many_files"] = 1.0
    elif changed_files > 7:
        signals["many_files"] = 0.5

    full_diff = " ".join(f.get("diff") or "" for f in files)
    cve_count = len(set(re.findall(r"CVE-\d{4}-\d+", full_diff)))
    if cve_count > 0:
        signals["has_cve_refs"] = min(1.0, cve_count / 3)

    security_hits = sum(1 for pattern, _ in SECURITY_PATTERNS if re.search(pattern, full_diff, re.IGNORECASE))
    if security_hits > 0:
        signals["security_patterns"] = min(1.0, security_hits / 4)

    return signals


def _extract_i_signals(pre: PreAnalysis, summary: dict, pr_data: dict) -> dict[str, float]:
    signals: dict[str, float] = {}

    floor = pre.risk_floor
    if floor == "high":
        signals["floor_high"] = 1.0
    elif floor == "medium":
        signals["floor_medium"] = 1.0
    else:
        signals["floor_low"] = 1.0

    llm_risk = (summary.get("risk") or {}).get("level", "low")
    if llm_risk == "high":
        signals["llm_high"] = 1.0
    elif llm_risk == "medium":
        signals["llm_medium"] = 1.0
    else:
        signals["llm_low"] = 1.0

    additions = pr_data.get("additions", 0)
    deletions = pr_data.get("deletions", 0)
    changed_files = pr_data.get("changed_files", 0)

    if additions > 500:
        signals["additions_large"] = 1.0
    elif additions > 100:
        signals["additions_medium"] = 1.0

    if deletions > 200:
        signals["deletions_large"] = 1.0

    if changed_files > 10:
        signals["many_changed_files"] = 1.0

    vulns = summary.get("vulnerabilities", [])
    if vulns:
        signals["vulnerabilities_found"] = min(1.0, len(vulns) / 3)

    if summary.get("attack_path"):
        signals["attack_path_present"] = 1.0

    if summary.get("ci_cd_risks"):
        signals["ci_cd_risk_present"] = 1.0

    return signals


def _extract_c_signals(pre: PreAnalysis, ev: Evaluation, pr_data: dict) -> dict[str, float]:
    signals: dict[str, float] = {}

    cs = ev.confidence_score
    if cs >= 0.55:
        signals["specificity_high"] = 1.0
    elif cs >= 0.30:
        signals["specificity_med"] = 1.0
    else:
        signals["specificity_low"] = 1.0

    if not ev.is_flagged:
        signals["not_flagged"] = 1.0

    files_with_diff = pre.files_with_diff
    files_skipped = pre.files_skipped_budget
    total = files_with_diff + files_skipped

    if total > 0:
        coverage = files_with_diff / total
        if coverage >= 0.95:
            signals["diff_coverage_full"] = 1.0
        elif coverage < 0.70:
            signals["diff_coverage_partial"] = 1.0

    if pr_data.get("is_large_pr"):
        signals["large_pr_chunked"] = 1.0

    if files_with_diff == 0:
        signals["no_diff_available"] = 1.0

    return signals


def _combine_risk_components(p_score: float, i_score: float, c_score: float, summary: dict, ev: Evaluation) -> int:
    base = 0.50 * p_score + 0.35 * i_score + 0.15 * c_score

    if summary.get("attack_path"):
        base += 0.05
    if summary.get("vulnerabilities"):
        base += 0.05
    if ev.is_flagged:
        base -= 0.05

    score = round(max(0.0, min(1.0, base)) * 100)
    return int(score)


def _score_to_band(score: int) -> tuple[str, str]:
    if score >= 80:
        return "critical", "Critical -- immediate review"
    if score >= 60:
        return "high", "High -- review before merging"
    if score >= 40:
        return "medium", "Medium -- review specific areas"
    if score >= 20:
        return "low", "Low -- low risk changes"
    return "minimal", "Minimal -- low impact PR"


def _build_triage(summary: dict, signals: RiskSignals, ev: Evaluation) -> tuple[str, bool]:
    vulns = summary.get("vulnerabilities", [])
    severities = {str(v.get("severity", "low")).lower() for v in vulns}
    critical = "critical" in severities
    high = "high" in severities

    if critical or signals.risk_score >= 85:
        return "P0", True
    if high or signals.risk_score >= 65:
        return "P1", True
    if signals.risk_score >= 40:
        return "P2", False
    return "P3", False


def _build_top_factors(
    p_signals: dict[str, float],
    i_signals: dict[str, float],
) -> list[str]:
    labels = {
        "tag_auth": "Touches authentication logic",
        "tag_payments": "Involves payments or billing",
        "tag_infra": "Infrastructure or deploy changes",
        "tag_security": "Modifies security configuration",
        "tag_db_migration": "Includes database migrations",
        "tag_concurrency": "Affects concurrent or async code",
        "tag_db_query": "Modifies queries or data models",
        "tag_api": "Changes exposed API surface",
        "tag_config": "Modifies config or environment variables",
        "no_tests_touched": "No test files in this PR",
        "large_diff": "Large diff with high surface area",
        "many_files": "Many files modified",
        "has_cve_refs": "Contains CVE references",
        "security_patterns": "Security patterns detected in diff",
        "floor_high": "Pre-analysis flagged high risk",
        "floor_medium": "Pre-analysis flagged medium risk",
        "vulnerabilities_found": "LLM found concrete vulnerabilities",
        "attack_path_present": "A realistic attack path was identified",
        "ci_cd_risk_present": "CI/CD risk surface is present",
        "additions_large": "More than 500 lines added",
        "many_changed_files": "More than 10 files modified",
    }

    scored: list[tuple[str, float]] = []
    for key, val in p_signals.items():
        if val > 0:
            scored.append((key, val))
    for key, val in i_signals.items():
        if val > 0:
            scored.append((key, val))

    priority = {
        "floor_high": 100,
        "attack_path_present": 95,
        "vulnerabilities_found": 90,
        "ci_cd_risk_present": 80,
        "tag_auth": 75,
        "tag_security": 74,
        "tag_infra": 72,
        "tag_payments": 72,
        "has_cve_refs": 65,
        "security_patterns": 64,
        "large_diff": 40,
        "many_files": 35,
        "no_tests_touched": 30,
    }

    scored.sort(key=lambda kv: (priority.get(kv[0], 0), kv[1]), reverse=True)

    out = []
    for key, _ in scored:
        label = labels.get(key)
        if label and label not in out:
            out.append(label)
        if len(out) == 5:
            break
    return out


def compute_risk_score(pre: PreAnalysis, summary: dict, ev: Evaluation, pr_data: dict) -> RiskSignals:
    p_signals = _extract_p_signals(pre, pr_data)
    i_signals = _extract_i_signals(pre, summary, pr_data)
    c_signals = _extract_c_signals(pre, ev, pr_data)

    p_score = _weighted_sum(p_signals, _P_WEIGHTS)
    i_score = _weighted_sum(i_signals, _I_WEIGHTS)
    c_score = _weighted_sum(c_signals, _C_WEIGHTS)

    risk_score = _combine_risk_components(p_score, i_score, c_score, summary, ev)
    risk_band, risk_label = _score_to_band(risk_score)
    top_factors = _build_top_factors(p_signals, i_signals)

    signals = RiskSignals(
        p_signals=p_signals,
        p_score=round(p_score, 3),
        i_signals=i_signals,
        i_score=round(i_score, 3),
        c_signals=c_signals,
        c_score=round(c_score, 3),
        risk_score=risk_score,
        risk_band=risk_band,
        risk_label=risk_label,
        top_factors=top_factors,
        triage="P3",
        merge_blocker=False,
    )

    triage, merge_blocker = _build_triage(summary, signals, ev)
    signals.triage = triage
    signals.merge_blocker = merge_blocker

    return signals


# -----------------------------------------------------------------------------
# Regexes for usefulness check
# -----------------------------------------------------------------------------
_FILENAME_RE = re.compile(r"\b[\w/-]+\.(?:py|js|ts|tsx|jsx|go|rb|java|rs|sql|yaml|yml|json|toml|sh|cfg|ini|env|md)\b")
_FUNCTION_RE = re.compile(r"\b(\w+)\((?:[\w,\s*]*)\)|`(\w+)`|\b(?:def|function|func|fn)\s+(\w+)")
_CHANGE_RE = re.compile(
    r"\b(?:add(?:s|ed)?|remov(?:e[sd]?)|replac(?:e[sd]?)|renam(?:e[sd]?)|"
    r"mov(?:e[sd]?)|fix(?:es|ed)?|introduc(?:e[sd]?)|deprecat(?:e[sd]?)|"
    r"migrat(?:e[sd]?)|extract(?:s|ed)?|split[s]?|merges?)\b"
)
