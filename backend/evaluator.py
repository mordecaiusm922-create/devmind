"""
evaluator.py -- DevMind deterministic risk engine

Three-phase pipeline:
  1. pre_analyse(pr_data)       -> PreAnalysis   (before LLM, structural signals)
  2. evaluate(summary, pr_data) -> dict          (after LLM, quality + risk scoring)
  3. enforce_risk_floor(summary, pre)            (never let LLM undercut structural floor)

Design principles:
  - Zero LLM calls -- every score is explainable from the PR data alone.
  - Immutable dataclasses. No mutation after construction.
  - Single definition per type -- no duplicate dataclasses.
  - All magic numbers are named constants.
  - Pure functions throughout; side effects only at the module boundary.
  - All string literals are ASCII-safe (no Unicode em-dashes or special chars).
"""

from __future__ import annotations
import json

import re
from dataclasses import asdict, dataclass
from typing import Final

# =============================================================================
# 1. CONSTANTS
# =============================================================================

TRIVIAL_CHURN_THRESHOLD: Final[int] = 8

ADDITIONS_LARGE: Final[int] = 500
ADDITIONS_MEDIUM: Final[int] = 100
DELETIONS_LARGE: Final[int] = 200
FILES_MANY: Final[int] = 15
FILES_SEVERAL: Final[int] = 7
FILES_CRITICAL: Final[int] = 10

# Confidence score thresholds
# Lowered from 0.55/0.30 - YAML/infra PRs score lower on code-specific patterns.
CONFIDENCE_HIGH: Final[float] = 0.45
CONFIDENCE_MED: Final[float] = 0.20
SPECIFICITY_NONE: Final[float] = 0.08

# Confidence bonus when LLM produced structured findings.
# Each bonus is capped independently so they cannot trivially reach 1.0.
CONFIDENCE_VULN_BONUS: Final[float] = 0.12
CONFIDENCE_CICD_BONUS: Final[float] = 0.08
CONFIDENCE_EVIDENCE_BONUS: Final[float] = 0.05

BAND_CRITICAL: Final[int] = 80
BAND_HIGH: Final[int] = 60
BAND_MEDIUM: Final[int] = 40
BAND_LOW: Final[int] = 20

P0_THRESHOLD: Final[int] = 85
P1_THRESHOLD: Final[int] = 65
P2_THRESHOLD: Final[int] = 40

GENERIC_PENALTY_THRESHOLD: Final[int] = 4
SUMMARY_MIN_CHARS: Final[int] = 150
SUMMARY_SHORT_CHARS: Final[int] = 200
SUMMARY_MEDIUM_CHARS: Final[int] = 400

COVERAGE_FULL: Final[float] = 0.95
COVERAGE_PARTIAL: Final[float] = 0.70

CVE_HIGH_COUNT: Final[int] = 3
CVE_HIGH_IN_DIFF: Final[int] = 2

# =============================================================================
# 2. PATTERN TABLES  (compiled once at import time)
# =============================================================================

_GENERIC_PHRASES: Final[tuple[tuple[str, int], ...]] = (
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
)

_SPECIFICITY_PATTERNS: Final[tuple[tuple[str, int], ...]] = (
    # Code identifiers
    (r"\b\w+\.(?:py|js|ts|tsx|jsx|go|rb|java|rs|sql|yaml|yml|json|toml|sh|env)\b", 3),
    (r"\b\w+\((?:\w+)?\)", 2),
    (r"\b[A-Z][a-z]+[A-Z][a-zA-Z]+\b", 2),
    (r"\b[A-Z][A-Z_]{3,}\b", 2),
    (r"\b(?:src|api|db|auth|routes?|models?|services?|utils?|handlers?|middleware)/\w+", 2),
    (r"\b(?:SELECT|INSERT|UPDATE|DELETE|CREATE TABLE|ALTER TABLE|INDEX ON)\b", 3),
    (r"\b(?:GET|POST|PUT|PATCH|DELETE)\s+/\w+", 2),
    (r"\bv?\d+\.\d+(?:\.\d+)?\b", 1),
    (r"\b\d{2,} (?:lines?|files?|tests?|cases?)\b", 1),
    # CI/CD and infra identifiers
    (r"\b[\w-]+/[\w.-]+@(?:v\d+|\w{40})\b", 3),
    (r"\b(?:pull_request_target|workflow_run|workflow_dispatch|schedule)\b", 3),
    (r"\.github/workflows/[\w.-]+", 3),
    (r"\b(?:aws|google|azurerm|kubernetes|helm|random)_[a-z_]{4,}\b", 2),
    (r"\b[\w.-]+/[\w.-]+:[\w.-]{2,}\b", 2),
    (r"\$\{\{\s*(?:secrets|env|github|inputs|needs)\.[A-Z_a-z]\w*\s*\}\}", 3),
)

_RISK_FILE_RULES: Final[tuple[tuple[str, str, str], ...]] = (
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
)

_SECURITY_PATTERNS: Final[tuple[tuple[str, str], ...]] = (
    (r"password|passwd|pwd", "sensitive_data"),
    (r"token|api_key|secret|jwt", "sensitive_data"),
    (r"except\s+Exception", "broad_exception"),
    (r"verify\s*=\s*False", "tls_disabled"),
    (r"charge|payment|transfer", "financial_logic"),
    (r"eval\(|exec\(|__import__", "code_injection"),
    (r"request\.(get|post|data|form)", "input_handling"),
    (r"CVE-\d{4}-\d+", "known_cve"),
)

_RISK_ORD: Final[dict[str, int]] = {"low": 0, "medium": 1, "high": 2}
_ORD_RISK: Final[dict[int, str]] = {v: k for k, v in _RISK_ORD.items()}

_RE_FILENAME = re.compile(
    r"\b[\w/-]+\.(?:py|js|ts|tsx|jsx|go|rb|java|rs|sql|yaml|yml|json|toml|sh|cfg|ini|env|md)\b"
)
_RE_FUNCTION = re.compile(
    r"\b(\w+)\((?:[\w,\s*]*)\)|`(\w+)`|\b(?:def|function|func|fn)\s+(\w+)"
)
_RE_CHANGE_VERB = re.compile(
    r"\b(?:add(?:s|ed)?|remov(?:e[sd]?)|replac(?:e[sd]?)|renam(?:e[sd]?)|"
    r"mov(?:e[sd]?)|fix(?:es|ed)?|introduc(?:e[sd]?)|deprecat(?:e[sd]?)|"
    r"migrat(?:e[sd]?)|extract(?:s|ed)?|split[s]?|merges?)\b"
)
_RE_TEST_FILE = re.compile(r"test[s]?/|spec[s]?/|__test__|\.(test|spec)\.", re.IGNORECASE)
_RE_CVE = re.compile(r"CVE-\d{4}-\d+")

_COMPILED_GENERIC = [(re.compile(p, re.IGNORECASE), s) for p, s in _GENERIC_PHRASES]
_COMPILED_SPECIFICITY = [(re.compile(p), w) for p, w in _SPECIFICITY_PATTERNS]
_COMPILED_SECURITY = [(re.compile(p, re.IGNORECASE), f) for p, f in _SECURITY_PATTERNS]
_COMPILED_RISK_RULES = [(re.compile(p, re.IGNORECASE), floor, tag) for p, floor, tag in _RISK_FILE_RULES]

# =============================================================================
# 3. RISK ENGINE WEIGHT TABLES
# =============================================================================

_P_WEIGHTS: Final[dict[str, float]] = {
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
    "security_improvement": -0.80,
}

_I_WEIGHTS: Final[dict[str, float]] = {
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
    "security_improvement": -0.60,
}

_C_WEIGHTS: Final[dict[str, float]] = {
    "specificity_high": 1.00,
    "specificity_med": 0.65,
    "specificity_low": 0.25,
    "not_flagged": 0.20,
    "diff_coverage_full": 0.15,
    "diff_coverage_partial": -0.20,
    "large_pr_chunked": -0.10,
    "no_diff_available": -0.30,
}

_TOP_FACTOR_LABELS: Final[dict[str, str]] = {
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
    "large_diff": "Large diff -- high surface area",
    "many_files": "Many files modified",
    "has_cve_refs": "Contains CVE references",
    "security_patterns": "Security patterns detected in diff",
    "security_improvement": "Looks like a security improvement, not a vuln",
    "floor_high": "Pre-analysis flagged high risk",
    "floor_medium": "Pre-analysis flagged medium risk",
    "vulnerabilities_found": "LLM found concrete vulnerabilities",
    "attack_path_present": "A realistic attack path was identified",
    "ci_cd_risk_present": "CI/CD risk surface is present",
    "additions_large": "More than 500 lines added",
    "many_changed_files": "More than 10 files modified",
}

_FACTOR_PRIORITY: Final[dict[str, int]] = {
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
    "security_improvement": 110,
}

# =============================================================================
# 4. DATACLASSES
# =============================================================================

@dataclass(frozen=True)
class PreAnalysis:
    risk_floor: str
    risk_tags: tuple[str, ...]
    flagged_files: tuple[str, ...]
    trivially_touched: tuple[str, ...]
    total_diff_chars: int
    files_with_diff: int
    files_skipped_noise: int
    files_skipped_budget: int

    def to_prompt_context(self) -> str:
        lines = [
            "## DevMind pre-analysis",
            f"Risk floor (minimum): {self.risk_floor.upper()}",
        ]
        if self.risk_tags:
            lines.append(f"Sensitive areas detected: {', '.join(self.risk_tags)}")
        if self.flagged_files:
            lines.append("Flagged files:")
            lines.extend(f"  - {f}" for f in self.flagged_files[:8])
        if self.trivially_touched:
            lines.append("Sensitive files with trivial churn:")
            lines.extend(f"  - {f}" for f in self.trivially_touched[:8])
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


@dataclass(frozen=True)
class Evaluation:
    confidence: str
    confidence_score: float
    specificity_score: float
    generic_phrases_found: tuple[str, ...]
    generic_penalty: int
    is_flagged: bool
    flag_reason: str | None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["generic_phrases_found"] = list(d["generic_phrases_found"])
        return d


@dataclass(frozen=True)
class UsefulnessCheck:
    is_useful: bool
    usefulness_level: str
    has_filenames: bool
    has_functions: bool
    has_specific_changes: bool
    missing: tuple[str, ...]
    evidence: dict[str, list[str]]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["missing"] = list(d["missing"])
        return d


@dataclass(frozen=True)
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
    top_factors: tuple[str, ...]
    triage: str
    merge_blocker: bool

    def to_dict(self) -> dict:
        d = asdict(self)
        d["top_factors"] = list(d["top_factors"])
        return d


# =============================================================================
# 5. PUBLIC API
# =============================================================================

def pre_analyse(pr_data: dict) -> PreAnalysis:
    """
    Deterministic structural analysis -- runs before the LLM call.
    Establishes risk floor, tags, and flagged files from file paths alone.
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

        for rule_re, floor, tag in _COMPILED_RISK_RULES:
            if rule_re.search(filename):
                floor_ord = _RISK_ORD.get(floor, 0)
                churn = f.get("additions", 0) + f.get("deletions", 0)

                if churn < TRIVIAL_CHURN_THRESHOLD and floor_ord > 0:
                    floor_ord -= 1
                    fname = f.get("filename", "")
                    if fname not in trivially_touched:
                        trivially_touched.append(fname)

                risk_level = max(risk_level, floor_ord)

                if tag not in risk_tags:
                    risk_tags.append(tag)
                fname = f.get("filename", "")
                if fname not in flagged_files:
                    flagged_files.append(fname)
                break

    full_diff = _build_full_diff_text(pr_data)
    diff_only = " ".join(f.get("diff") or "" for f in files)

    security_flags = {
        flag
        for sec_re, flag in _COMPILED_SECURITY
        if sec_re.search(full_diff)
    }
    if security_flags and "security" not in risk_tags:
        risk_tags.append("security")

    if {"known_cve", "tls_disabled"} & security_flags:
        risk_level = max(risk_level, _RISK_ORD["medium"])

    cve_count = len(set(_RE_CVE.findall(full_diff)))
    cve_in_diff = len(set(_RE_CVE.findall(diff_only)))
    if cve_count >= CVE_HIGH_COUNT or cve_in_diff >= CVE_HIGH_IN_DIFF:
        risk_level = max(risk_level, _RISK_ORD["high"])

    total_diff_chars = sum(len(f.get("diff") or "") for f in files)

    return PreAnalysis(
        risk_floor=_ORD_RISK[risk_level],
        risk_tags=tuple(risk_tags),
        flagged_files=tuple(flagged_files),
        trivially_touched=tuple(trivially_touched),
        total_diff_chars=total_diff_chars,
        files_with_diff=files_with_diff,
        files_skipped_noise=files_skipped_noise,
        files_skipped_budget=files_skipped_budget,
    )


def evaluate(summary: dict, pr_data: dict) -> dict:
    """
    Deterministic post-LLM evaluation.

    Returns a flat dict with:
      scores        -- numeric breakdown
      triage        -- P0 / P1 / P2 / P3
      merge_blocker -- bool
      risk_signals  -- full RiskSignals serialized
      evaluation    -- Evaluation quality scores
      usefulness    -- UsefulnessCheck
    """
    pre = pre_analyse(pr_data)
    ev = _evaluate_summary_quality(summary, pr_data)
    signals = compute_risk_score(pre, summary, ev, pr_data)
    usefulness = _usefulness_check(summary)

    return {
        "scores": {
            "risk_score": signals.risk_score,
            "risk_band": signals.risk_band,
            "risk_label": signals.risk_label,
            "exploitability_score": round(signals.p_score, 3),
            "impact_score": round(signals.i_score, 3),
            "confidence_score": round(signals.c_score, 3),
            "top_factors": list(signals.top_factors),
        },
        "triage": signals.triage,
        "merge_blocker": signals.merge_blocker,
       
        "evaluation": ev.to_dict(),
        "usefulness": usefulness.to_dict(),
    }


def enforce_risk_floor(summary: dict, pre: PreAnalysis) -> dict:
    """
    Never allow the LLM to report a risk level below the structural floor.
    Returns the (possibly mutated) summary dict.
    """
    risk = summary.get("risk", {})
    if not isinstance(risk, dict):
        return summary

    model_ord = _RISK_ORD.get(str(risk.get("level", "low")).lower(), 0)
    floor_ord = _RISK_ORD.get(pre.risk_floor, 0)

    if floor_ord > model_ord:
        old_level = risk.get("level", "low")
        reason = str(risk.get("reason", "")).strip()
        prefix = (
            f"[Escalated from {old_level} to {pre.risk_floor} -- "
            f"sensitive areas: {', '.join(pre.risk_tags)}] "
        )
        summary["risk"] = {
            "level": pre.risk_floor,
            "reason": (prefix + reason) if reason else prefix.rstrip(),
        }

    return summary


def infer_risk_floor(files: list[dict]) -> PreAnalysis:
    """Compatibility helper: build PreAnalysis from a file list only."""
    return pre_analyse({
        "files": files,
        "changed_files": len(files),
        "additions": 0,
        "deletions": 0,
    })


def compute_risk_score(
    pre: PreAnalysis,
    summary: dict,
    ev: Evaluation,
    pr_data: dict,
) -> RiskSignals:
    """
    Core risk engine.
    Combines P=probability, I=impact, C=confidence into a deterministic 0-100 score.
    """
    p_signals = _extract_p_signals(pre, pr_data)
    i_signals = _extract_i_signals(pre, summary, pr_data)
    c_signals = _extract_c_signals(pre, ev, pr_data)

    p_score = _weighted_sum(p_signals, _P_WEIGHTS)
    i_score = _weighted_sum(i_signals, _I_WEIGHTS)
    c_score = _weighted_sum(c_signals, _C_WEIGHTS)

    risk_score = _combine_scores(p_score, i_score, c_score, summary, ev)
    risk_band, risk_label = _score_to_band(risk_score)
    top_factors = _build_top_factors(p_signals, i_signals)
    triage, merge_block = _build_triage(summary, risk_score, ev)

    return RiskSignals(
        p_signals=p_signals,
        p_score=round(p_score, 3),
        i_signals=i_signals,
        i_score=round(i_score, 3),
        c_signals=c_signals,
        c_score=round(c_score, 3),
        risk_score=risk_score,
        risk_band=risk_band,
        risk_label=risk_label,
        top_factors=tuple(top_factors),
        triage=triage,
        merge_blocker=merge_block,
    )


# =============================================================================
# 6. SIGNAL EXTRACTORS
# =============================================================================

def _is_security_improvement(summary: dict, pr_data: dict) -> bool:
    text = " ".join([
        pr_data.get("title", "") or "",
        pr_data.get("body", "") or "",
        " ".join(pr_data.get("commit_messages", [])),
        summary.get("what", "") or "",
        summary.get("why", "") or "",
        summary.get("impact", "") or "",
        summary.get("review_focus", "") or "",
        json.dumps(summary.get("vulnerabilities", []), ensure_ascii=False),
        json.dumps(summary.get("ci_cd_risks", []), ensure_ascii=False),
    ]).lower()

    has_marker = any(marker in text for marker in (
        "trivy",
        "snyk",
        "grype",
        "scanner",
        "vulnerability scanner",
        "latest version",
        "pin",
        "security improvement",
        "reduce risk",
        "security patch",
        "dependency update",
    ))
    has_specific_cve = bool(re.search(r"CVE-\d{4}-\d+", text))
    has_real_finding = bool(summary.get("attack_path")) or bool(summary.get("vulnerabilities")) or bool(summary.get("ci_cd_risks"))

    return has_marker and not has_specific_cve and not has_real_finding


def _extract_p_signals(pre: PreAnalysis, pr_data: dict) -> dict[str, float]:
    """Probability axis -- how likely is this to be exploitable."""
    signals: dict[str, float] = {}

    tag_to_signal = {
        "auth": "tag_auth",
        "payments": "tag_payments",
        "infra": "tag_infra",
        "security": "tag_security",
        "db-migration": "tag_db_migration",
        "concurrency": "tag_concurrency",
        "db-query": "tag_db_query",
        "api": "tag_api",
        "config": "tag_config",
    }
    for tag, key in tag_to_signal.items():
        if tag in pre.risk_tags:
            signals[key] = 1.0

    files = pr_data.get("files", [])
    has_tests = any(_RE_TEST_FILE.search(f.get("filename", "")) for f in files)
    if not has_tests:
        signals["no_tests_touched"] = 1.0

    additions = pr_data.get("additions", 0)
    changed_files = pr_data.get("changed_files", 0)

    if additions > ADDITIONS_LARGE:
        signals["large_diff"] = 1.0
    elif additions > ADDITIONS_MEDIUM:
        signals["large_diff"] = 0.5

    if changed_files > FILES_MANY:
        signals["many_files"] = 1.0
    elif changed_files > FILES_SEVERAL:
        signals["many_files"] = 0.5

    full_diff = " ".join(f.get("diff") or "" for f in files)
    cve_count = len(set(_RE_CVE.findall(full_diff)))
    if cve_count > 0:
        signals["has_cve_refs"] = min(1.0, cve_count / 3)

    sec_hits = sum(1 for sec_re, _ in _COMPILED_SECURITY if sec_re.search(full_diff))
    if sec_hits > 0:
        signals["security_patterns"] = min(1.0, sec_hits / 4)

    if _is_security_improvement({}, pr_data):
        signals["security_improvement"] = 1.0

    return signals


def _extract_i_signals(pre: PreAnalysis, summary: dict, pr_data: dict) -> dict[str, float]:
    """Impact axis -- how severe if exploited."""
    signals: dict[str, float] = {}

    floor_key = {"high": "floor_high", "medium": "floor_medium"}.get(pre.risk_floor, "floor_low")
    signals[floor_key] = 1.0

    llm_level = str((summary.get("risk") or {}).get("level", "low")).lower()
    llm_key = {"high": "llm_high", "medium": "llm_medium"}.get(llm_level, "llm_low")
    signals[llm_key] = 1.0

    additions = pr_data.get("additions", 0)
    deletions = pr_data.get("deletions", 0)
    changed_files = pr_data.get("changed_files", 0)

    if additions > ADDITIONS_LARGE:
        signals["additions_large"] = 1.0
    elif additions > ADDITIONS_MEDIUM:
        signals["additions_medium"] = 1.0

    if deletions > DELETIONS_LARGE:
        signals["deletions_large"] = 1.0

    if changed_files > FILES_CRITICAL:
        signals["many_changed_files"] = 1.0

    vulns = summary.get("vulnerabilities", [])
    if vulns:
        signals["vulnerabilities_found"] = min(1.0, len(vulns) / 3)

    if summary.get("attack_path"):
        signals["attack_path_present"] = 1.0

    if summary.get("ci_cd_risks"):
        signals["ci_cd_risk_present"] = 1.0

    if _is_security_improvement(summary, pr_data):
        signals["security_improvement"] = 1.0

    return signals


def _extract_c_signals(pre: PreAnalysis, ev: Evaluation, pr_data: dict) -> dict[str, float]:
    """Confidence axis -- how trustworthy is the analysis."""
    signals: dict[str, float] = {}

    cs = ev.confidence_score
    if cs >= CONFIDENCE_HIGH:
        signals["specificity_high"] = 1.0
    elif cs >= CONFIDENCE_MED:
        signals["specificity_med"] = 1.0
    else:
        signals["specificity_low"] = 1.0

    if not ev.is_flagged:
        signals["not_flagged"] = 1.0

    total = pre.files_with_diff + pre.files_skipped_budget
    if total > 0:
        coverage = pre.files_with_diff / total
        if coverage >= COVERAGE_FULL:
            signals["diff_coverage_full"] = 1.0
        elif coverage < COVERAGE_PARTIAL:
            signals["diff_coverage_partial"] = 1.0

    if pr_data.get("is_large_pr"):
        signals["large_pr_chunked"] = 1.0

    if pre.files_with_diff == 0:
        signals["no_diff_available"] = 1.0

    return signals


# =============================================================================
# 7. SCORING HELPERS
# =============================================================================

def _weighted_sum(signals: dict[str, float], weights: dict[str, float]) -> float:
    """Normalized weighted sum -- always returns [0.0, 1.0]."""
    if not signals:
        return 0.0
    active = [(max(0.0, min(1.0, v)), weights.get(k, 0.0)) for k, v in signals.items()]
    denom = sum(abs(w) for _, w in active if w != 0)
    if denom <= 0:
        return 0.0
    return max(0.0, min(1.0, sum(v * w for v, w in active) / denom))


def _combine_scores(
    p_score: float,
    i_score: float,
    c_score: float,
    summary: dict,
    ev: Evaluation,
) -> int:
    base = 0.50 * p_score + 0.35 * i_score + 0.15 * c_score

    if summary.get("attack_path"):
        base += 0.05
    if summary.get("vulnerabilities"):
        base += 0.05
    if ev.is_flagged:
        base -= 0.05

    vulns = summary.get("vulnerabilities") or []
    attack = summary.get("attack_path")
    ci_cd = summary.get("ci_cd_risks") or []
    evidence = summary.get("evidence") or []
    llm_level = str((summary.get("risk") or {}).get("level", "low")).lower()

    # No evidence supplied for any finding -- penalize confidence in the score.
    if not evidence and (vulns or ci_cd):
        base -= 0.08

    # No actionable findings at all -- hard cap at top of "high" band.
    if not vulns and not attack and not ci_cd:
        base = min(base, 0.69)

    # Security improvement with no real finding should not inflate risk.
    if _is_security_improvement(summary, {}) and not vulns and not attack and not ci_cd:
        base = min(base, 0.19)

    # LLM assessed low risk with zero vuln findings -- cap at "medium".
    if llm_level == "low" and not vulns:
        base = min(base, 0.49)

    # Single ci_cd_risk with no evidence and no vulns -- cap at "high".
    if ci_cd and not vulns and not attack and not evidence:
        base = min(base, 0.74)

    return int(round(max(0.0, min(1.0, base)) * 100))


def _score_to_band(score: int) -> tuple[str, str]:
    """
    Map numeric score to (band, label).
    All labels are ASCII-only -- no Unicode dashes that corrupt in Latin-1
    environments or JSON serializers without ensure_ascii=False.
    """
    if score >= BAND_CRITICAL:
        return "critical", "Critical -- immediate review required"
    if score >= BAND_HIGH:
        return "high", "High -- review before merging"
    if score >= BAND_MEDIUM:
        return "medium", "Medium -- review specific areas"
    if score >= BAND_LOW:
        return "low", "Low -- low risk changes"
    return "minimal", "Minimal -- low impact PR"


def _build_triage(summary: dict, risk_score: int, ev: Evaluation) -> tuple[str, bool]:
    vulns = summary.get("vulnerabilities", [])
    ci_cd = summary.get("ci_cd_risks", [])
    attack_path = summary.get("attack_path")

    severities = {str(v.get("severity", "low")).lower() for v in vulns}

    if not attack_path and not vulns and not ci_cd:
        return "P3", False

    if "critical" in severities or risk_score >= P0_THRESHOLD:
        return "P0", True
    if "high" in severities or risk_score >= P1_THRESHOLD:
        return "P1", True
    if risk_score >= P2_THRESHOLD:
        return "P2", False
    return "P3", False


def _build_top_factors(
    p_signals: dict[str, float],
    i_signals: dict[str, float],
) -> list[str]:
    combined = {**p_signals, **i_signals}
    ranked = sorted(
        [(k, v) for k, v in combined.items() if v > 0],
        key=lambda kv: (_FACTOR_PRIORITY.get(kv[0], 0), kv[1]),
        reverse=True,
    )
    out: list[str] = []
    for key, _ in ranked:
        label = _TOP_FACTOR_LABELS.get(key)
        if label and label not in out:
            out.append(label)
        if len(out) == 5:
            break
    return out


# =============================================================================
# 8. QUALITY EVALUATORS
# =============================================================================

def _evaluate_summary_quality(summary: dict, pr_data: dict) -> Evaluation:
    """
    Score the specificity and quality of an LLM-generated summary.

    Scoring pipeline:
      1. Raw specificity from regex pattern hits (code + CI/CD patterns).
      2. Structural bonus: non-empty vulnerabilities / ci_cd_risks / evidence
         prove the LLM cited real findings.
      3. Generic-phrase deduction.
      4. Length penalty.
      5. Clamp to [0.0, 1.0].
    """
    full_text = " ".join([
        summary.get("what", ""),
        summary.get("why", ""),
        summary.get("impact", ""),
        summary.get("review_focus", ""),
        (summary.get("risk") or {}).get("reason", ""),
        " ".join(summary.get("key_changes") or []),
        " ".join(
            f"{v.get('location', '')} {v.get('description', '')} {v.get('exploit_path', '')}"
            for v in (summary.get("vulnerabilities") or [])
        ),
        " ".join(
            f"{r.get('trigger', '')} {r.get('risk', '')} {r.get('line', '')}"
            for r in (summary.get("ci_cd_risks") or [])
        ),
    ])
    lower = full_text.lower()

    found_phrases: list[str] = []
    total_penalty = 0
    for compiled_re, severity in _COMPILED_GENERIC:
        matches = compiled_re.findall(lower)
        if matches:
            found_phrases.append(matches[0])
            total_penalty += severity * len(matches)

    specificity_max = sum(w * 3 for _, w in _COMPILED_SPECIFICITY)
    specificity_hits = sum(
        min(len(r.findall(full_text)), 3) * w
        for r, w in _COMPILED_SPECIFICITY
    )
    specificity_score = round(min(specificity_hits / specificity_max, 1.0), 3) if specificity_max else 0.0

    structural_bonus = 0.0
    if summary.get("vulnerabilities"):
        structural_bonus += CONFIDENCE_VULN_BONUS
    if summary.get("ci_cd_risks"):
        structural_bonus += CONFIDENCE_CICD_BONUS
    if summary.get("evidence"):
        structural_bonus += CONFIDENCE_EVIDENCE_BONUS
    structural_bonus = min(structural_bonus, CONFIDENCE_HIGH - 0.01)

    chars = len(full_text)
    length_penalty = 0.30 if chars < SUMMARY_SHORT_CHARS else (0.10 if chars < SUMMARY_MEDIUM_CHARS else 0.0)

    generic_deduction = sum(
        0.15 if sev == 2 else 0.07
        for r, sev in _COMPILED_GENERIC
        if r.search(lower)
    )

    specificity_ceiling = min(1.0, specificity_score + 0.25)

    confidence_score = round(
        max(0.0, min(specificity_ceiling, specificity_score + structural_bonus - generic_deduction - length_penalty)),
        3,
    )
    confidence = (
        "high" if confidence_score >= CONFIDENCE_HIGH else
        "medium" if confidence_score >= CONFIDENCE_MED else
        "low"
    )

    is_flagged = False
    flag_reason = None

    if total_penalty >= GENERIC_PENALTY_THRESHOLD:
        is_flagged = True
        flag_reason = (
            f"Summary contains {len(found_phrases)} generic phrase(s): "
            f"{', '.join(repr(p) for p in found_phrases[:3])}."
        )
    elif specificity_score < SPECIFICITY_NONE and pr_data.get("changed_files", 0) > 2:
        is_flagged = True
        flag_reason = (
            f"No specific identifiers found despite "
            f"{pr_data.get('changed_files', 0)} files changed."
        )
    elif chars < SUMMARY_MIN_CHARS:
        is_flagged = True
        flag_reason = "Summary is unusually short and likely incomplete."

    return Evaluation(
        confidence=confidence,
        confidence_score=confidence_score,
        specificity_score=specificity_score,
        generic_phrases_found=tuple(dict.fromkeys(found_phrases)),
        generic_penalty=total_penalty,
        is_flagged=is_flagged,
        flag_reason=flag_reason,
    )


def _usefulness_check(summary: dict) -> UsefulnessCheck:
    full_text = " ".join([
        summary.get("what", ""),
        summary.get("why", ""),
        summary.get("impact", ""),
        summary.get("review_focus", ""),
        (summary.get("risk") or {}).get("reason", ""),
        " ".join(summary.get("key_changes") or []),
    ])

    filenames_found = _RE_FILENAME.findall(full_text)
    func_matches = _RE_FUNCTION.findall(full_text)
    functions_found = [next((g for g in m if g), "") for m in func_matches if any(m)]
    functions_found = [f for f in functions_found if f]
    change_matches = _RE_CHANGE_VERB.findall(full_text.lower())

    has_filenames = bool(filenames_found)
    has_functions = bool(functions_found)
    has_specific_changes = len(change_matches) >= 2

    missing: list[str] = []
    if not has_filenames:
        missing.append("file names")
    if not has_functions:
        missing.append("function or identifier names")
    if not has_specific_changes:
        missing.append("concrete change verbs")

    present = sum([has_filenames, has_functions, has_specific_changes])
    level, useful = (
        ("high", True) if present == 3 else
        ("medium", True) if present == 2 else
        ("low", False)
    )

    return UsefulnessCheck(
        is_useful=useful,
        usefulness_level=level,
        has_filenames=has_filenames,
        has_functions=has_functions,
        has_specific_changes=has_specific_changes,
        missing=tuple(missing),
        evidence={
            "filenames": filenames_found[:5],
            "functions": functions_found[:5],
            "change_verbs": list(dict.fromkeys(change_matches))[:8],
        },
    )


# =============================================================================
# 9. INTERNAL UTILITIES
# =============================================================================

def _build_full_diff_text(pr_data: dict) -> str:
    files = pr_data.get("files", [])
    return " ".join([
        pr_data.get("title", "") or "",
        pr_data.get("body", "") or "",
        " ".join(pr_data.get("commit_messages", [])),
        " ".join(f.get("diff") or "" for f in files),
    ])


