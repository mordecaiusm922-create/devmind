"""
summarizer.py -- DevMind LLM summarization pipeline

Responsibility: transform raw PR data into a structured security summary
via one LLM call (or chunked calls for large PRs), then hand off to the
deterministic risk engine in evaluator.py.

Design principles:
  - Single LLM model, single temperature, declared as module constants.
  - All JSON produced with ensure_ascii=False -- prevents UTF-8 corruption
    of non-ASCII chars (em-dashes, arrows) in label strings.
  - attack_path is REQUIRED when risk >= medium and vulnerabilities exist;
    the schema instruction enforces this at the prompt level.
  - Pure functions throughout; the only stateful object is `debug_capture`
    which is an opt-in side channel for test harnesses.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Optional

from dotenv import load_dotenv
from openai import OpenAI

from evaluator import pre_analyse, evaluate, enforce_risk_floor

load_dotenv()

# =============================================================================
# MODULE CONSTANTS
# =============================================================================

_GROQ_BASE_URL: str    = "https://api.groq.com/openai/v1"
MODEL:          str    = "llama-3.3-70b-versatile"
MAX_TOKENS:     int    = 4096
TEMPERATURE:    float  = 0.2
CHUNK_FILE_THRESHOLD: int = 12

client = OpenAI(
    api_key=os.getenv("GROQ_API_KEY"),
    base_url=_GROQ_BASE_URL,
)

# =============================================================================
# SYSTEM PROMPT
# =============================================================================

SYSTEM_PROMPT = (
    "You are DevMind, a security analysis engine for pull requests. "
    "Your job is to identify REAL, EXPLOITABLE security issues grounded "
    "exclusively in the diff provided. You do not speculate.\n\n"

    "FALSIFIABILITY RULE — before making any claim, ask:\n"
    "  (a) Is attacker control of this input demonstrated in the diff?\n"
    "  (b) Is there a concrete, reproducible path from input to sensitive resource?\n"
    "  (c) Does the diff introduce the flaw, or does it fix/detect it?\n"
    "If any answer is NO, do not claim a vulnerability. Set risk to low.\n\n"

    "SECURITY IMPROVEMENT RULE:\n"
    "  - Adding a vulnerability scanner (Trivy, Snyk, Grype, etc.) REDUCES risk.\n"
    "  - Pinning action versions REDUCES supply chain risk.\n"
    "  - Updating actions to latest stable versions is NOT a vulnerability unless "
    "    a specific CVE or breaking change is present in the diff.\n"
    "  - Never classify a security improvement as a vulnerability.\n\n"

    "CI/CD THREAT MODEL — only flag if ALL conditions are true:\n"
    "  1. The trigger is pull_request_target or workflow_run.\n"
    "  2. The workflow explicitly accesses ${{ secrets.* }} or runs untrusted code.\n"
    "  3. The permissions: block is absent or grants write scope unnecessarily.\n"
    "  4. An external attacker can reach this trigger without repo write access.\n\n"

    "PERMISSIONS ANALYSIS — always check the diff for:\n"
    "  - permissions: blocks (presence/absence, scopes granted).\n"
    "  - secrets accessed before input validation.\n"
    "  - GITHUB_TOKEN scope relative to the trigger.\n\n"

    "ATTACK PATH RULES:\n"
    "  - entry_point must be a specific file:line in the diff.\n"
    "  - exploit_steps must list >= 3 concrete, reproducible steps.\n"
    "  - attacker_control_verified must be true — if you cannot confirm "
    "    the attacker controls the entry point, set attack_path to null.\n"
    "  - sink must be a real resource proven reachable in the diff.\n"
    "  - If risk >= medium but no realistic attack path exists, "
    "    lower risk to low rather than invent a path.\n\n"

    "BLAST RADIUS — for every vulnerability estimate:\n"
    "  - Scope: repo-only | org-wide | cross-account | public.\n"
    "  - Data at risk: secrets | artifacts | source | prod-infra | none.\n\n"

    "Internal reasoning (do not output):\n"
    "  1. What changed in the diff?\n"
    "  2. Does this add security (scanner, pin, permission scope reduction)?\n"
    "  3. Can an external attacker control the entry point?\n"
    "  4. What are the exact exploit steps? Are they reproducible?\n"
    "  5. What is the blast radius if exploited?\n\n"

    "Output only valid JSON. No markdown. No code fences. No explanations."
)

# Opt-in side channel for test harnesses -- set to a list before calling
# summarize_pr() to capture raw LLM I/O.
debug_capture: list[dict] | None = None


# =============================================================================
# PUBLIC API
# =============================================================================

def summarize_pr(pr_data: dict) -> tuple[dict, object, object]:
    """
    Entry point.  Returns (summary, pre_analysis, evaluation).

    The returned summary contains all LLM fields plus the deterministic
    scores, triage, and merge_blocker written back by the risk engine.
    """
    pre = pre_analyse(pr_data)
    files_with_diff = [f for f in pr_data.get("files", []) if f.get("diff")]

    if pr_data.get("is_large_pr") or len(files_with_diff) > CHUNK_FILE_THRESHOLD:
        summary = _summarize_large_pr(pr_data, files_with_diff, pre)
    else:
        summary = _summarize_single_pass(pr_data, files_with_diff, pre)

    summary = _normalize_summary(summary)
    summary = enforce_risk_floor(summary, pre)

    hallucinations = _check_hallucinations(summary, pr_data)
    if hallucinations:
        summary["hallucination_warning"] = hallucinations

    ev = evaluate(summary, pr_data)

    summary["scores"]        = ev.get("scores", {})
    summary["triage"]        = ev.get("triage")
    summary["merge_blocker"] = ev.get("merge_blocker", False)

    return summary, pre, ev


# =============================================================================
# INTERNAL PIPELINE
# =============================================================================

def _summarize_single_pass(pr_data: dict, files_with_diff: list, pre) -> dict:
    prompt = _build_full_prompt(pr_data, files_with_diff, pre)
    return _call_llm(prompt)


def _summarize_large_pr(pr_data: dict, files_with_diff: list, pre) -> dict:
    chunk_size = 6
    chunks = [
        files_with_diff[i : i + chunk_size]
        for i in range(0, len(files_with_diff), chunk_size)
    ]

    partial_summaries = []
    for i, chunk in enumerate(chunks, start=1):
        prompt = _build_chunk_prompt(pr_data, chunk, i, len(chunks), pre)
        partial_summaries.append(_call_llm(prompt))

    return _synthesise(pr_data, partial_summaries, pre)


def _synthesise(pr_data: dict, partials: list, pre) -> dict:
    prompt = (
        f"SYNTHESIS PHASE\n\n"
        f"PR Title: {pr_data.get('title', '')}\n"
        f"Author: @{pr_data.get('author', '')}\n"
        f"Total files: {pr_data.get('changed_files', 0)}\n"
        f"Total additions: {pr_data.get('additions', 0)}\n"
        f"Total deletions: {pr_data.get('deletions', 0)}\n\n"
        f"{pre.to_prompt_context()}\n\n"
        f"Partial analyses:\n{json.dumps(partials, indent=2, ensure_ascii=False)}\n\n"
        f"Combine the partial analyses into one final security assessment.\n"
        f"Keep only findings that are grounded in the PR data.\n\n"
        f"{_output_schema_instruction()}"
    )
    result = _call_llm(prompt)
    result["analysed_in_chunks"] = len(partials)
    return result


def _call_llm(user_prompt: str) -> dict:
    response = client.chat.completions.create(
        model=MODEL,
        max_tokens=MAX_TOKENS,
        temperature=TEMPERATURE,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_prompt},
        ],
    )

    choice = response.choices[0]
    raw    = choice.message.content or ""

    if choice.finish_reason == "length":
        raise ValueError(
            f"LLM response truncated (finish_reason=length). "
            f"Prompt length: {len(user_prompt)} chars."
        )

    parsed = _parse_and_validate(raw)

    if debug_capture is not None:
        debug_capture.append({
            "prompt_chars":  len(user_prompt),
            "raw":           raw,
            "finish_reason": choice.finish_reason,
            "parsed":        parsed,
        })

    return parsed


# =============================================================================
# PROMPT BUILDERS
# =============================================================================

def _build_full_prompt(pr_data: dict, files_with_diff: list, pre) -> str:
    return (
        f"PR ANALYSIS\n\n"
        f"Title: {pr_data.get('title', '')}\n"
        f"Author: @{pr_data.get('author', '')}\n"
        f"Repository: {pr_data.get('repo', '')}\n"
        f"Files changed: {pr_data.get('changed_files', 0)} "
        f"(+{pr_data.get('additions', 0)} / -{pr_data.get('deletions', 0)})\n\n"
        f"{pre.to_prompt_context()}\n\n"
        f"Commit messages:\n{_format_commits(pr_data.get('commit_messages', []))}\n\n"
        f"Review comments:\n{_format_review_comments(pr_data.get('review_comments', []))}\n\n"
        f"Issue comments:\n{_format_issue_comments(pr_data.get('issue_comments', []))}\n\n"
        f"Changed files:\n{_format_file_list(pr_data.get('files', []))}\n\n"
        f"Diffs:\n{_format_diffs(files_with_diff)}\n\n"
        f"{_output_schema_instruction()}"
    )


def _build_chunk_prompt(pr_data: dict, chunk: list, chunk_num: int, total: int, pre) -> str:
  return (
        "Return ONLY a JSON object with these exact top-level keys:\n"
        "{\n"
        '  "what": "Precise 1-2 sentence description of what changed.",\n'
        '  "why": "Technical reason for this change.",\n'
        '  "impact": "Which systems, workflows, or behaviors are affected.",\n'
        '  "risk": {\n'
        '    "level": "low | medium | high | critical",\n'
        '    "reason": "Exact failure mechanism with file:line reference. '
        'If the change adds security tooling, level must be low."\n'
        "  },\n"
        '  "permissions_analysis": {\n'
        '    "permissions_block_present": true,\n'
        '    "scopes_granted": ["contents: read"],\n'
        '    "secrets_accessed_before_validation": false,\n'
        '    "github_token_scope": "read | write | none | not_applicable",\n'
        '    "trust_boundary_respected": true\n'
        "  },\n"
        '  "attack_path": {\n'
        '    "entry_point": "Specific file:line in this diff the attacker targets.",\n'
        '    "attacker_control_verified": true,\n'
        '    "exploit_steps": [\n'
        '      "Step 1: attacker forks the repo and opens a PR.",\n'
        '      "Step 2: pull_request_target trigger fires with write permissions.",\n'
        '      "Step 3: workflow accesses ${{ secrets.AWS_KEY }} at line 82."\n'
        "    ],\n"
        '    "sink": "The exact resource compromised (e.g. secrets.AWS_KEY at line 82).",\n'
        '    "blast_radius": "repo-only | org-wide | cross-account | public",\n'
        '    "impact": "account_takeover | data_exfiltration | privilege_escalation '
        '| rce | supply_chain | other"\n'
        "  },\n"
        "  // attack_path MUST be populated when risk >= medium AND attacker_control_verified is true.\n"
        "  // attack_path MUST be null when attacker_control cannot be confirmed in the diff.\n"
        '  "vulnerabilities": [\n'
        "    {\n"
        '      "type": "credential_exposure | sql_injection | xss | auth_bypass | '
        'privilege_escalation | ci_cd_misconfig | supply_chain | other",\n'
        '      "severity": "low | medium | high | critical",\n'
        '      "location": "filename:L12-18",\n'
        '      "description": "Exact flaw with file:line reference. '
        'Do NOT list security improvements as vulnerabilities.",\n'
        '      "fix": "Concrete, actionable fix.",\n'
        '      "exploit_path": "Minimum 3 reproducible steps referencing exact diff lines.",\n'
        '      "blast_radius": "repo-only | org-wide | cross-account | public"\n'
        "    }\n"
        "  ],\n"
        '  "ci_cd_risks": [\n'
        "    {\n"
        '      "trigger": "pull_request_target | workflow_run | push | other",\n'
        '      "risk": "Exact risk with workflow file:line reference.",\n'
        '      "severity": "low | medium | high | critical",\n'
        '      "permissions_block_missing": false,\n'
        '      "secrets_exposed": false,\n'
        '      "line": "filename:Lx"\n'
        "    }\n"
        "  ],\n"
        '  "key_changes": ["filename:L12-18 -- what changed and security impact"],\n'
        '  "review_focus": "Single most critical concern with exact file:line.",\n'
        '  "evidence": [\n'
        "    {\n"
        '      "claim": "Short falsifiable claim.",\n'
        '      "location": "filename:L12-18",\n'
        '      "snippet": "exact code from diff"\n'
        "    }\n"
        "  ]\n"
        "}\n\n"
        "Hard rules:\n"
        "- Adding Trivy, Snyk, or any scanner = security improvement, NOT a vulnerability.\n"
        "- attack_path requires attacker_control_verified: true and >= 3 exploit_steps.\n"
        "- If attacker_control_verified is false, attack_path MUST be null.\n"
        "- vulnerabilities must not include security improvements or version updates "
        "without a specific CVE.\n"
        "- if workflow files are present, populate permissions_analysis.\n"
        "- evidence is mandatory for every vulnerability entry.\n"
        "- all strings must use ASCII-safe characters only.\n"
    )
        '      "trigger": "pull_request_target | workflow_run | push | other",\n'
        '      "risk": "Exact CI/CD risk description referencing the workflow file and trigger.",\n'
        '      "severity": "low | medium | high | critical",\n'
        '      "line": "filename:Lx"\n'
        "    }\n"
        "  ],\n"
        '  "key_changes": ["filename:L12-18 -- what changed and why it matters"],\n'
        '  "review_focus": "Single most critical security concern and exact code path.",\n'
        '  "evidence": [\n'
        "    {\n"
        '      "claim": "short claim",\n'
        '      "location": "filename:L12-18",\n'
        '      "snippet": "exact code from diff"\n'
        "    }\n"
        "  ]\n"
        "}\n\n"
        "Hard rules:\n"
        "- vulnerabilities must be grounded in the diff -- no invented CVEs.\n"
        "- attack_path MUST be populated (not null) when risk >= medium and vulnerabilities is non-empty.\n"
        "- if risk is high or critical, vulnerabilities must contain at least one entry.\n"
        "- if workflow files are present, ci_cd_risks must contain at least one entry.\n"
        "- evidence is mandatory for every vulnerability.\n"
        "- all string values must use ASCII-safe characters only -- no Unicode em-dashes or arrows.\n"
    )


# =============================================================================
# NORMALIZATION AND VALIDATION
# =============================================================================

def _normalize_summary(data: dict) -> dict:
    """
    Coerce LLM output into the canonical summary shape.
    All setdefault calls are safe because the field is only set when absent.
    """
    if not isinstance(data, dict):
        raise ValueError("LLM output did not parse into an object.")

    data.setdefault("what", "")
    data.setdefault("why", "")
    data.setdefault("impact", "")
    data.setdefault("risk", {})
    data.setdefault("attack_path", None)
    data.setdefault("vulnerabilities", [])
    data.setdefault("ci_cd_risks", [])
    data.setdefault("key_changes", [])
    data.setdefault("review_focus", "")
    data.setdefault("evidence", [])

    # Normalize risk field -- accept string "level -- reason" or dict
    risk = data.get("risk", {})
    if isinstance(risk, str):
        parts  = risk.split("--", 1)
        level  = parts[0].strip().lower()
        reason = parts[1].strip() if len(parts) > 1 else risk.strip()
        data["risk"] = {"level": level, "reason": reason}
    elif isinstance(risk, dict):
        data["risk"]["level"]  = str(risk.get("level", "low")).lower()
        data["risk"]["reason"] = str(risk.get("reason", "")).strip()
    else:
        data["risk"] = {"level": "low", "reason": ""}

    if not isinstance(data["vulnerabilities"], list):
        data["vulnerabilities"] = []

    if not isinstance(data["ci_cd_risks"], list):
        data["ci_cd_risks"] = []

    if not isinstance(data["key_changes"], list):
        data["key_changes"] = [str(data["key_changes"])]

    if not isinstance(data["evidence"], list):
        data["evidence"] = []

    if data["attack_path"] is not None and not isinstance(data["attack_path"], dict):
        data["attack_path"] = None

    # Sanitize all string values: replace common multi-byte punctuation with
    # ASCII equivalents so downstream JSON serialization is always clean.
    _sanitize_strings(data)

    return data


def _sanitize_strings(obj: Any) -> None:
    """
    Walk the summary tree and replace problematic multi-byte chars in-place.

    This is a belt-and-suspenders measure on top of ensure_ascii=False in
    json.dumps: it ensures that if any consumer serializes with the default
    ensure_ascii=True they still get readable output rather than \\uXXXX escapes
    or, worse, garbled Latin-1 bytes.
    """
    _REPLACEMENTS: dict[str, str] = {
        "\u2014": "--",   # em dash
        "\u2013": "-",    # en dash
        "\u2012": "-",    # figure dash
        "\u2192": "->",   # rightwards arrow
        "\u2190": "<-",   # leftwards arrow
        "\u2018": "'",    # left single quotation mark
        "\u2019": "'",    # right single quotation mark
        "\u201c": '"',    # left double quotation mark
        "\u201d": '"',    # right double quotation mark
        "\u2026": "...",  # horizontal ellipsis
    }

    def _clean(s: str) -> str:
        for char, replacement in _REPLACEMENTS.items():
            s = s.replace(char, replacement)
        return s

    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str):
                obj[k] = _clean(v)
            else:
                _sanitize_strings(v)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            if isinstance(item, str):
                obj[i] = _clean(item)
            else:
                _sanitize_strings(item)


def _check_hallucinations(summary: dict, pr_data: dict) -> list:
    corpus_parts = [
        pr_data.get("title", ""),
        pr_data.get("body", ""),
        " ".join(pr_data.get("commit_messages", [])),
    ]

    for f in pr_data.get("files", []):
        corpus_parts.append(f.get("diff") or "")
        corpus_parts.append(f.get("filename", ""))

    corpus = " ".join(corpus_parts)

    summary_text = " ".join([
        summary.get("what", ""),
        summary.get("why", ""),
        summary.get("impact", ""),
        summary.get("review_focus", ""),
        " ".join(summary.get("key_changes") or []),
        json.dumps(summary.get("vulnerabilities", []), ensure_ascii=False),
        json.dumps(summary.get("ci_cd_risks", []),     ensure_ascii=False),
    ])

    _COMMON_VERBS = frozenset({
        "make", "take", "have", "give", "find", "call", "send",
        "read", "load", "save", "open", "close", "init", "test",
        "check", "raise", "catch", "throw", "wrap", "list",
    })

    hallucinated = []
    for m in re.finditer(r"\b([a-z][a-z0-9_]{3,})\(\)", summary_text):
        fn = m.group(1)
        if fn in _COMMON_VERBS:
            continue
        if fn not in corpus:
            hallucinated.append(fn + "()")

    return list(dict.fromkeys(hallucinated))


# =============================================================================
# JSON PARSING
# =============================================================================

def _extract_json_object(raw: str) -> str:
    """
    Extract the first complete JSON object from raw LLM output.
    Handles models that prefix/suffix the JSON with prose or code fences.
    """
    start = raw.find("{")
    if start == -1:
        raise ValueError("No JSON object found in model output.")

    depth     = 0
    in_string = False
    escape    = False

    for i in range(start, len(raw)):
        ch = raw[i]

        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue

        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return raw[start : i + 1]

    raise ValueError("Unbalanced JSON object in model output.")


def _parse_and_validate(raw: str) -> dict:
    try:
        extracted = _extract_json_object(raw)
    except ValueError:
        extracted = raw.strip()

    try:
        return json.loads(extracted)
    except json.JSONDecodeError:
        cleaned = re.sub(r",\s*}", "}", extracted)
        cleaned = re.sub(r",\s*]", "]", cleaned)
        return json.loads(cleaned)


# =============================================================================
# FORMATTING HELPERS  (pure, stateless)
# =============================================================================

def _format_file_list(files: list) -> str:
    if not files:
        return "None"

    icons = {"added": "+", "removed": "-", "renamed": "->", "modified": "~"}
    lines = []

    for f in files:
        icon = icons.get(f.get("status", "modified"), "~")
        skip = f" [skipped: {f['skipped_reason']}]" if f.get("skipped_reason") else ""
        lines.append(
            f"  {icon} {f.get('filename', '')}  "
            f"+{f.get('additions', 0)}/-{f.get('deletions', 0)}{skip}"
        )

    return "\n".join(lines)


def _format_diffs(files: list) -> str:
    parts = []

    for f in files:
        diff = f.get("diff", "")
        if not diff:
            continue

        note = "  [truncated]" if f.get("truncated") else ""
        parts.append(
            f"### {f.get('filename', '')}  "
            f"(+{f.get('additions', 0)}/-{f.get('deletions', 0)}){note}\n"
            f"```diff\n{diff}\n```"
        )

    return "\n\n".join(parts) if parts else "No diffs available."


def _format_commits(messages: list) -> str:
    return "\n".join(f"  - {m}" for m in messages) if messages else "No commits."


def _format_review_comments(comments: list) -> str:
    if not comments:
        return "No inline review comments."
    return "\n".join(
        f"  [{c['path']}] @{c['user']}: {c['body']}" for c in comments
    )


def _format_issue_comments(comments: list) -> str:
    if not comments:
        return "No discussion."
    return "\n".join(f"  @{c['user']}: {c['body']}" for c in comments)