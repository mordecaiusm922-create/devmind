import json
import os
import re
from openai import OpenAI
from dotenv import load_dotenv
from evaluator import pre_analyse, evaluate, enforce_risk_floor

load_dotenv()

client = OpenAI(
    api_key=os.getenv("GROQ_API_KEY"),
    base_url="https://api.groq.com/openai/v1",
)

# Model to use for all LLM calls
MODEL = "llama-3.3-70b-versatile"

# A PR is split into chunks if it exceeds this many files with actual diffs
CHUNK_FILE_THRESHOLD = 15

# ── System prompt ─────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """\
You are DevMind, a senior software engineer with 15 years of experience doing \
code review across backend, frontend, infrastructure, and data systems.

Your job is to produce PR analysis that a developer can act on immediately. \
You write like a principal engineer talking to a peer — specific, direct, \
no filler.

STRICT RULES:
- Never write generic phrases like "improves code quality", "refactors code", \
"updates logic", "makes changes to", "this PR modifies", "adds functionality".
- Every claim must be grounded in specific files, function names, class names, \
config keys, or line changes visible in the diff.
- If you cannot determine something from the diff, say "unclear from diff" — \
do not invent.
- Risk assessment must name the exact mechanism of failure, not just say \
"may cause issues".
- The pre-analysis block in the prompt is computed from file paths by a \
deterministic system. It is authoritative — do not contradict it.
- For every risk claim and key change, include an evidence field with \
the exact filename and line numbers from the diff. Format: filename:L12-18.\
"""


def summarize_pr(pr_data: dict) -> tuple[dict, object, object]:
    """
    Entry point. Returns (summary, pre_analysis, evaluation).
    Callers (main.py) unpack all three so they can log and attach to response.
    """
    pre = pre_analyse(pr_data)
    files_with_diff = [f for f in pr_data.get("files", []) if f.get("diff")]

    if pr_data.get("is_large_pr") or len(files_with_diff) > CHUNK_FILE_THRESHOLD:
        summary = _summarize_large_pr(pr_data, files_with_diff, pre)
    else:
        summary = _summarize_single_pass(pr_data, files_with_diff, pre)

    # Post-processing: enforce risk floor, then evaluate
    summary = enforce_risk_floor(summary, pre)

    # Hallucination check: flag identifiers in summary not found in any source.
    # Stored in summary so it flows through to the API response and the logger.
    hallucinations = _check_hallucinations(summary, pr_data)
    if hallucinations:
        summary["hallucination_warning"] = hallucinations

    ev = evaluate(summary, pr_data)

    return summary, pre, ev


# ── Single-pass path ──────────────────────────────────────────────────────────

def _summarize_single_pass(pr_data: dict, files_with_diff: list, pre) -> dict:
    prompt = _build_full_prompt(pr_data, files_with_diff, pre)
    return _call_claude(prompt)


# ── Chunked path (large PRs) ──────────────────────────────────────────────────

def _summarize_large_pr(pr_data: dict, files_with_diff: list, pre) -> dict:
    chunk_size = 8
    chunks = [
        files_with_diff[i:i + chunk_size]
        for i in range(0, len(files_with_diff), chunk_size)
    ]
    partial_summaries = []
    for i, chunk in enumerate(chunks):
        prompt = _build_chunk_prompt(pr_data, chunk, i + 1, len(chunks), pre)
        partial_summaries.append(_call_claude(prompt))

    return _synthesise(pr_data, partial_summaries, pre)


def _synthesise(pr_data: dict, partials: list[dict], pre) -> dict:
    synthesis_prompt = f"""\
You have analysed a large PR in {len(partials)} chunks. \
Below are the partial analyses.

PR: {pr_data['title']}
Author: @{pr_data['author']}
Total: {pr_data['changed_files']} files, \
+{pr_data['additions']}/-{pr_data['deletions']} lines

{pre.to_prompt_context()}

Partial analyses:
{json.dumps(partials, indent=2)}

Synthesise into ONE final analysis. Merge duplicates, resolve contradictions. \
Same strict rules: specific, no filler.

{_output_schema_instruction()}"""

    result = _call_claude(synthesis_prompt)
    result["analysed_in_chunks"] = len(partials)
    return result


# ── Claude API wrapper ───────────────────────────────────────────────────────

# When debug_capture is set to a list, _call_claude appends raw responses to it.
# Used by the eval suite's --debug mode. Never set in production.
debug_capture: list[dict] | None = None


def _call_claude(user_prompt: str) -> dict:
    """
    Single point of contact with the Groq API (OpenAI-compatible).
    Model: llama-3.3-70b-versatile — free tier, 6000 req/day.
    Groq uses finish_reason instead of stop_reason.
    """
    response = client.chat.completions.create(
        model=MODEL,
        max_tokens=4096,
        temperature=0.2,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_prompt},
        ],
    )

    choice = response.choices[0]

    # Detect truncation — Groq sets finish_reason="length" when cut off
    if choice.finish_reason == "length":
        raise ValueError(
            f"LLM response truncated (finish_reason=length). "
            f"Prompt was {len(user_prompt)} chars. "
            f"Consider reducing diff budget or splitting into smaller chunks."
        )

    raw    = choice.message.content
    parsed = _parse_and_validate(raw)

    if debug_capture is not None:
        debug_capture.append({
            "prompt_chars":  len(user_prompt),
            "prompt_tail":   user_prompt[-600:],
            "raw":           raw,
            "finish_reason": choice.finish_reason,
            "parsed":        parsed,
        })

    return parsed


# ── Prompt builders ───────────────────────────────────────────────────────────

def _build_full_prompt(pr_data: dict, files_with_diff: list, pre) -> str:
    return f"""\
Analyse this Pull Request. Every claim must reference specific files or code.

## PR Metadata
Title: {pr_data['title']}
Author: @{pr_data['author']}
Branch: `{pr_data['head_branch']}` → `{pr_data['base_branch']}`
Files changed: {pr_data['changed_files']} \
(+{pr_data['additions']} / -{pr_data['deletions']} lines)

## PR Description
{pr_data['body'][:1200] or 'No description provided.'}

## Commit messages
{_format_commits(pr_data.get('commit_messages', []))}

## All changed files
{_format_file_list(pr_data.get('files', []))}

{pre.to_prompt_context()}

## Diffs (cleaned, grouped by file)
{_format_diffs(files_with_diff)}

## Review comments (inline)
{_format_review_comments(pr_data.get('review_comments', []))}

## Discussion
{_format_issue_comments(pr_data.get('issue_comments', []))}

{_output_schema_instruction()}"""


def _build_chunk_prompt(pr_data: dict, chunk: list, chunk_num: int, total: int, pre) -> str:
    return f"""\
Analysing chunk {chunk_num} of {total} of a large PR. Be specific.

## PR Metadata
Title: {pr_data['title']}
Author: @{pr_data['author']}
Total: {pr_data['changed_files']} files \
(+{pr_data['additions']} / -{pr_data['deletions']})

{pre.to_prompt_context()}

## Files in this chunk
{_format_diffs(chunk)}

{_output_schema_instruction()}"""


def _check_hallucinations(summary: dict, pr_data: dict) -> list[str]:
    """
    Compares identifiers mentioned in the summary against the source material
    (diff text, PR title, body, commit messages).
    Returns a list of identifiers that appear in the summary but NOT in any
    source — these are likely hallucinated by the model to satisfy the
    specificity rules.

    Only flags lowercase_with_underscores() style function calls (Python/JS
    naming convention) — CamelCase class names are excluded because they're
    commonly inferred from import paths not shown in the diff.
    """
    # Build corpus of all known real text
    corpus_parts = [
        pr_data.get("title", ""),
        pr_data.get("body", ""),
        " ".join(pr_data.get("commit_messages", [])),
    ]
    for f in pr_data.get("files", []):
        corpus_parts.append(f.get("diff") or "")
        corpus_parts.append(f.get("filename", ""))
    corpus = " ".join(corpus_parts)

    # Extract lowercase_snake_case() identifiers from summary text
    summary_text = " ".join([
        summary.get("what", ""),
        summary.get("why", ""),
        summary.get("impact", ""),
        summary.get("review_focus", ""),
        " ".join(summary.get("key_changes") or []),
    ])

    hallucinated = []
    for m in re.finditer(r'\b([a-z][a-z0-9_]{3,})\(\)', summary_text):
        fn = m.group(1)
        # Skip very common English words that look like function calls
        if fn in {"make", "take", "have", "give", "find", "call", "send",
                   "read", "load", "save", "open", "close", "init", "test",
                   "check", "raise", "catch", "throw", "wrap", "list"}:
            continue
        if fn not in corpus:
            hallucinated.append(fn + "()")

    return list(dict.fromkeys(hallucinated))  # deduplicated, order preserved


def _output_schema_instruction() -> str:
    return """\
Return ONLY a JSON object with these exact keys — no markdown, no extra text:

{
  "what": "Precise 1-2 sentence description. Name specific functions, modules, or config keys.",
  "why": "Technical reason this change was necessary. Reference the actual problem.",
  "impact": "Which subsystems, APIs, DB tables, or runtime behaviours are affected. Be concrete.",
  "risk": {
    "level": "low | medium | high",
    "reason": "Name the exact failure mechanism. E.g.: 'The new index on users.email runs synchronously — will lock the table on large datasets.'"
  },
  "key_changes": [
    "filename.py:L12-18 — what changed and why it matters",
    "filename.py:L45 — what changed and why it matters"
  ],
 "review_focus": "Single most important thing to verify. Name the exact code path, edge case, or assumption.",
  "evidence": [
    {"claim": "brief claim being supported", "location": "filename.py:L12-18", "snippet": "exact_code_here()"}
  ]
}

CRITICAL: The evidence array is MANDATORY. Every entry in key_changes must have a corresponding evidence entry with exact filename and line numbers."""


# ── Formatters ────────────────────────────────────────────────────────────────

def _format_file_list(files: list) -> str:
    if not files:
        return "None"
    icons = {"added": "+", "removed": "-", "renamed": "→", "modified": "~"}
    lines = []
    for f in files:
        icon = icons.get(f["status"], "~")
        skip = f" [skipped: {f['skipped_reason']}]" if f.get("skipped_reason") else ""
        lines.append(f"  {icon} {f['filename']}  +{f['additions']}/-{f['deletions']}{skip}")
    return "\n".join(lines)


def _format_diffs(files: list) -> str:
    parts = []
    for f in files:
        diff = f.get("diff", "")
        if not diff:
            continue
        note = "  [truncated]" if f.get("truncated") else ""
        parts.append(
            f"### {f['filename']}  (+{f['additions']}/-{f['deletions']}){note}\n"
            f"```diff\n{diff}\n```"
        )
    return "\n\n".join(parts) if parts else "No diffs available."


def _format_commits(messages: list) -> str:
    return "\n".join(f"  - {m}" for m in messages) if messages else "No commits."


def _format_review_comments(comments: list) -> str:
    if not comments:
        return "No inline review comments."
    return "\n".join(f"  [{c['path']}] @{c['user']}: {c['body']}" for c in comments)


def _format_issue_comments(comments: list) -> str:
    if not comments:
        return "No discussion."
    return "\n".join(f"  @{c['user']}: {c['body']}" for c in comments)


# ── Output validation ─────────────────────────────────────────────────────────

def _parse_and_validate(raw: str) -> dict:
    """
    Extracts and validates the JSON object from Claude's response text.
    Claude may wrap the JSON in prose or markdown fences — we strip those first.
    Falls back to parsing the full string if no fence is found.
    """
    # Strip markdown code fences (```json ... ``` or ``` ... ```)
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    if fence:
        raw = fence.group(1)
    else:
        # Find the outermost { ... } block in case there's surrounding prose
        brace_start = raw.find("{")
        brace_end   = raw.rfind("}")
        if brace_start != -1 and brace_end != -1 and brace_end > brace_start:
            raw = raw[brace_start:brace_end + 1]

    data = json.loads(raw)

    risk = data.get("risk", {})
    if isinstance(risk, str):
        parts = risk.split("—", 1)
        level = parts[0].strip().lower()
        reason = parts[1].strip() if len(parts) > 1 else risk
        data["risk"] = {"level": level, "reason": reason}
    elif isinstance(risk, dict):
        data["risk"]["level"] = risk.get("level", "low").lower()

    if not isinstance(data.get("key_changes"), list):
        data["key_changes"] = [str(data.get("key_changes", ""))]

    return data
