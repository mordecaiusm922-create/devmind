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

MODEL = "llama-3.3-70b-versatile"
CHUNK_FILE_THRESHOLD = 15

SYSTEM_PROMPT = (
    "You are DevMind, a security-focused code analysis engine. "
    "You think like an attacker, not a reviewer. "
    "Your job is to find security vulnerabilities in pull requests before they reach production. "
    "WHAT YOU HUNT: "
    "Credential exposure: hardcoded API keys, passwords, tokens, secrets. "
    "Injection vectors: SQL injection, XSS, command injection, path traversal. "
    "Authentication flaws: missing auth checks, broken session management, JWT issues. "
    "Privilege escalation: improper role checks, insecure direct object references. "
    "Insecure AI-generated patterns: Math.random() for tokens, CORS wildcard, CSRF disabled. "
    "Dependency vulnerabilities: outdated packages with known CVEs. "
    "STRICT RULES: "
    "Think like an attacker. Ask: how would I exploit this? "
    "Every risk claim must reference specific files, line numbers, or code patterns. "
    "If you find a critical vulnerability, name the exact attack vector. "
    "Never say may cause issues -- say exactly what breaks and how. "
    "The pre-analysis block is authoritative -- do not contradict it. "
    "For every finding include: what it is, how its exploited, what the fix is."
)

debug_capture = None


def summarize_pr(pr_data: dict) -> tuple[dict, object, object]:
    pre = pre_analyse(pr_data)
    files_with_diff = [f for f in pr_data.get("files", []) if f.get("diff")]

    if pr_data.get("is_large_pr") or len(files_with_diff) > CHUNK_FILE_THRESHOLD:
        summary = _summarize_large_pr(pr_data, files_with_diff, pre)
    else:
        summary = _summarize_single_pass(pr_data, files_with_diff, pre)

    summary = enforce_risk_floor(summary, pre)

    hallucinations = _check_hallucinations(summary, pr_data)
    if hallucinations:
        summary["hallucination_warning"] = hallucinations

    ev = evaluate(summary, pr_data)
    return summary, pre, ev


def _summarize_single_pass(pr_data: dict, files_with_diff: list, pre) -> dict:
    prompt = _build_full_prompt(pr_data, files_with_diff, pre)
    return _call_claude(prompt)


def _summarize_large_pr(pr_data: dict, files_with_diff: list, pre) -> dict:
    chunk_size = 8
    chunks = [files_with_diff[i:i + chunk_size] for i in range(0, len(files_with_diff), chunk_size)]
    partial_summaries = []
    for i, chunk in enumerate(chunks):
        prompt = _build_chunk_prompt(pr_data, chunk, i + 1, len(chunks), pre)
        partial_summaries.append(_call_claude(prompt))
    return _synthesise(pr_data, partial_summaries, pre)


def _synthesise(pr_data: dict, partials: list, pre) -> dict:
    synthesis_prompt = (
        f"You have analysed a large PR in {len(partials)} chunks. "
        f"PR: {pr_data['title']} Author: @{pr_data['author']} "
        f"Total: {pr_data['changed_files']} files "
        f"+{pr_data['additions']}/-{pr_data['deletions']} lines\n"
        f"{pre.to_prompt_context()}\n"
        f"Partial analyses:\n{json.dumps(partials, indent=2)}\n"
        f"Synthesise into ONE final analysis. Same strict rules: specific, no filler.\n"
        f"{_output_schema_instruction()}"
    )
    result = _call_claude(synthesis_prompt)
    result["analysed_in_chunks"] = len(partials)
    return result


def _call_claude(user_prompt: str) -> dict:
    response = client.chat.completions.create(
        model=MODEL,
        max_tokens=4096,
        temperature=0.2,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
    )
    choice = response.choices[0]
    if choice.finish_reason == "length":
        raise ValueError(f"LLM response truncated. Prompt was {len(user_prompt)} chars.")
    raw = choice.message.content
    parsed = _parse_and_validate(raw)
    if debug_capture is not None:
        debug_capture.append({
            "prompt_chars": len(user_prompt),
            "raw": raw,
            "finish_reason": choice.finish_reason,
            "parsed": parsed,
        })
    return parsed


def _build_full_prompt(pr_data: dict, files_with_diff: list, pre) -> str:
    return (
        f"Analyse this Pull Request for security vulnerabilities. Every claim must reference specific files or code.\n\n"
        f"## PR Metadata\n"
        f"Title: {pr_data['title']}\n"
        f"Author: @{pr_data['author']}\n"
        f"Branch: {pr_data['head_branch']} -> {pr_data['base_branch']}\n"
        f"Files changed: {pr_data['changed_files']} (+{pr_data['additions']} / -{pr_data['deletions']} lines)\n\n"
        f"## PR Description\n{pr_data['body'][:1200] or 'No description provided.'}\n\n"
        f"## Commit messages\n{_format_commits(pr_data.get('commit_messages', []))}\n\n"
        f"## All changed files\n{_format_file_list(pr_data.get('files', []))}\n\n"
        f"{pre.to_prompt_context()}\n\n"
        f"## Diffs (cleaned, grouped by file)\n{_format_diffs(files_with_diff)}\n\n"
        f"## Review comments (inline)\n{_format_review_comments(pr_data.get('review_comments', []))}\n\n"
        f"## Discussion\n{_format_issue_comments(pr_data.get('issue_comments', []))}\n\n"
        f"{_output_schema_instruction()}"
    )


def _build_chunk_prompt(pr_data: dict, chunk: list, chunk_num: int, total: int, pre) -> str:
    return (
        f"Analysing chunk {chunk_num} of {total} of a large PR. Be specific.\n\n"
        f"## PR Metadata\n"
        f"Title: {pr_data['title']}\n"
        f"Author: @{pr_data['author']}\n"
        f"Total: {pr_data['changed_files']} files (+{pr_data['additions']} / -{pr_data['deletions']})\n\n"
        f"{pre.to_prompt_context()}\n\n"
        f"## Files in this chunk\n{_format_diffs(chunk)}\n\n"
        f"{_output_schema_instruction()}"
    )


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
    ])

    hallucinated = []
    for m in re.finditer(r'\b([a-z][a-z0-9_]{3,})\(\)', summary_text):
        fn = m.group(1)
        if fn in {"make", "take", "have", "give", "find", "call", "send",
                  "read", "load", "save", "open", "close", "init", "test",
                  "check", "raise", "catch", "throw", "wrap", "list"}:
            continue
        if fn not in corpus:
            hallucinated.append(fn + "()")
    return list(dict.fromkeys(hallucinated))


def _output_schema_instruction() -> str:
    return (
        'Return ONLY a JSON object with these exact keys -- no markdown, no extra text:\n\n'
        '{\n'
        '  "what": "Precise 1-2 sentence description. Name specific functions, modules, or config keys.",\n'
        '  "why": "Technical reason this change was necessary. Reference the actual problem.",\n'
        '  "impact": "Which subsystems, APIs, DB tables, or runtime behaviours are affected. Be concrete.",\n'
        '  "risk": {\n'
        '    "level": "low | medium | high | critical",\n'
        '    "reason": "Name the exact failure mechanism and attack vector."\n'
        '  },\n'
        '  "vulnerabilities": [\n'
        '    {\n'
        '      "type": "credential_exposure | sql_injection | xss | auth_bypass | privilege_escalation | insecure_ai_pattern | cve_dependency | path_traversal | other",\n'
        '      "severity": "low | medium | high | critical",\n'
        '      "location": "filename:L12-18",\n'
        '      "description": "Exact vulnerability description with attack vector",\n'
        '      "fix": "Concrete fix recommendation"\n'
        '    }\n'
        '  ],\n'
        '  "key_changes": ["filename.py:L12-18 -- what changed and why it matters"],\n'
        '  "review_focus": "Single most critical security concern. Name the exact code path.",\n'
        '  "evidence": [{"claim": "brief claim", "location": "filename.py:L12-18", "snippet": "code"}]\n'
        '}\n\n'
        'CRITICAL: vulnerabilities array is MANDATORY. If no vulnerabilities found, return empty array.\n'
        'If risk level is high or critical, populate vulnerabilities with at least one entry.'
    )


def _format_file_list(files: list) -> str:
    if not files:
        return "None"
    icons = {"added": "+", "removed": "-", "renamed": "->", "modified": "~"}
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
        parts.append(f"### {f['filename']}  (+{f['additions']}/-{f['deletions']}){note}\n```diff\n{diff}\n```")
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


def _parse_and_validate(raw: str) -> dict:
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    if fence:
        raw = fence.group(1)
    else:
        brace_start = raw.find("{")
        brace_end = raw.rfind("}")
        if brace_start != -1 and brace_end != -1 and brace_end > brace_start:
            raw = raw[brace_start:brace_end + 1]

    data = json.loads(raw)

    risk = data.get("risk", {})
    if isinstance(risk, str):
        parts = risk.split("--", 1)
        level = parts[0].strip().lower()
        reason = parts[1].strip() if len(parts) > 1 else risk
        data["risk"] = {"level": level, "reason": reason}
    elif isinstance(risk, dict):
        data["risk"]["level"] = risk.get("level", "low").lower()

    if not isinstance(data.get("key_changes"), list):
        data["key_changes"] = [str(data.get("key_changes", ""))]

    if not isinstance(data.get("vulnerabilities"), list):
        data["vulnerabilities"] = []

    return data
