import json
import os
import re
from typing import Any, Optional

from dotenv import load_dotenv
from openai import OpenAI

from evaluator import pre_analyse, evaluate, enforce_risk_floor

load_dotenv()

client = OpenAI(
    api_key=os.getenv("GROQ_API_KEY"),
    base_url="https://api.groq.com/openai/v1",
)

MODEL = "llama-3.3-70b-versatile"
CHUNK_FILE_THRESHOLD = 12

SYSTEM_PROMPT = (
    "You are DevMind, an offensive security analysis engine for pull requests. "
    "You think like an attacker, not a reviewer. "
    "Your job is to identify real exploitable security issues before merge.\n\n"
    "Focus on: credential exposure, auth flaws, privilege escalation, injection, "
    "supply chain risk, unsafe CI/CD workflows, and risky dependency changes.\n\n"
    "CI/CD threats have high priority. Pay special attention to: "
    "pull_request_target with untrusted code, missing permissions blocks, "
    "mutable action tags, secrets accessed before validation, workflow_run with "
    "untrusted artifacts, and unsafe registry or image handling.\n\n"
    "Rules:\n"
    "- Every claim must be grounded in the diff.\n"
    "- Always cite a real file, line, and code snippet.\n"
    "- Do not invent vulnerabilities.\n"
    "- If there is no realistic attack path, set attack_path to null.\n"
    "- Be precise. Avoid vague wording like may, could, might, probably.\n"
    "- Prefer concrete exploit paths and concrete fixes.\n"
    "- The pre-analysis block is authoritative.\n\n"
    "Internal reasoning only:\n"
    "1) What changed?\n"
    "2) Can attacker control it?\n"
    "3) What resource is at risk?\n"
    "4) Is there a realistic attack path?\n\n"
    "Output only valid JSON. No markdown. No code fences. No explanations."
)

debug_capture = None


def summarize_pr(pr_data: dict) -> tuple[dict, object, object]:
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

    summary["scores"] = ev.get("scores", {})
    summary["triage"] = ev.get("triage")
    summary["merge_blocker"] = ev.get("merge_blocker", False)

    return summary, pre, ev


def _summarize_single_pass(pr_data: dict, files_with_diff: list, pre) -> dict:
    prompt = _build_full_prompt(pr_data, files_with_diff, pre)
    return _call_llm(prompt)


def _summarize_large_pr(pr_data: dict, files_with_diff: list, pre) -> dict:
    chunk_size = 6
    chunks = [
        files_with_diff[i:i + chunk_size]
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
        f"Partial analyses:\n{json.dumps(partials, indent=2)}\n\n"
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
        max_tokens=4096,
        temperature=0.2,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
    )

    choice = response.choices[0]
    raw = choice.message.content or ""

    if choice.finish_reason == "length":
        raise ValueError(f"LLM response truncated. Prompt length: {len(user_prompt)} chars.")

    parsed = _parse_and_validate(raw)

    if debug_capture is not None:
        debug_capture.append(
            {
                "prompt_chars": len(user_prompt),
                "raw": raw,
                "finish_reason": choice.finish_reason,
                "parsed": parsed,
            }
        )

    return parsed


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
        f"CHUNK ANALYSIS {chunk_num}/{total}\n\n"
        f"PR Title: {pr_data.get('title', '')}\n"
        f"Author: @{pr_data.get('author', '')}\n"
        f"Repository: {pr_data.get('repo', '')}\n\n"
        f"{pre.to_prompt_context()}\n\n"
        f"Files in this chunk:\n{_format_file_list(chunk)}\n\n"
        f"Diffs:\n{_format_diffs(chunk)}\n\n"
        f"Only report findings grounded in these diffs.\n\n"
        f"{_output_schema_instruction()}"
    )


def _output_schema_instruction() -> str:
    return (
        "Return ONLY a JSON object with these exact top-level keys:\n"
        "{\n"
        '  "what": "Precise 1 to 2 sentence description of what changed.",\n'
        '  "why": "Technical reason this change was necessary.",\n'
        '  "impact": "Which systems, workflows, APIs, or runtime behaviors are affected.",\n'
        '  "risk": {\n'
        '    "level": "low | medium | high | critical",\n'
        '    "reason": "Exact failure mechanism and attack vector."\n'
        "  },\n"
        '  "attack_path": {\n'
        '    "entry_point": "specific change in the PR that introduces risk",\n'
        '    "vector": "how an attacker would exploit this exact change",\n'
        '    "sink": "what resource is impacted",\n'
        '    "impact": "account takeover | data exfiltration | privilege escalation | RCE | other"\n'
        "  } | null,\n"
        '  "vulnerabilities": [\n'
        "    {\n"
        '      "type": "credential_exposure | sql_injection | xss | auth_bypass | privilege_escalation | insecure_ai_pattern | cve_dependency | path_traversal | ci_cd_misconfig | other",\n'
        '      "severity": "low | medium | high | critical",\n'
        '      "location": "filename:L12-18",\n'
        '      "description": "Exact vulnerability description with attack vector.",\n'
        '      "fix": "Concrete fix recommendation.",\n'
        '      "exploit_path": "Step by step attack path."\n'
        "    }\n"
        "  ],\n"
        '  "ci_cd_risks": [\n'
        "    {\n"
        '      "trigger": "pull_request_target | workflow_run | push | other",\n'
        '      "risk": "Exact CI/CD risk description.",\n'
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
        "Rules:\n"
        "- vulnerabilities must be grounded in the diff.\n"
        "- attack_path must be null if no realistic attacker-controlled path exists.\n"
        "- if risk is high or critical, vulnerabilities must contain at least one entry.\n"
        "- if workflow files are present, ci_cd_risks must contain at least one entry.\n"
        "- evidence is mandatory for every vulnerability.\n"
    )


def _normalize_summary(data: dict) -> dict:
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

    risk = data.get("risk", {})
    if isinstance(risk, str):
        parts = risk.split("--", 1)
        level = parts[0].strip().lower()
        reason = parts[1].strip() if len(parts) > 1 else risk.strip()
        data["risk"] = {"level": level, "reason": reason}
    elif isinstance(risk, dict):
        data["risk"]["level"] = str(risk.get("level", "low")).lower()
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

    return data


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

    summary_text = " ".join(
        [
            summary.get("what", ""),
            summary.get("why", ""),
            summary.get("impact", ""),
            summary.get("review_focus", ""),
            " ".join(summary.get("key_changes") or []),
            json.dumps(summary.get("vulnerabilities", [])),
            json.dumps(summary.get("ci_cd_risks", [])),
        ]
    )

    hallucinated = []
    for m in re.finditer(r"\b([a-z][a-z0-9_]{3,})\(\)", summary_text):
        fn = m.group(1)
        if fn in {
            "make", "take", "have", "give", "find", "call", "send",
            "read", "load", "save", "open", "close", "init", "test",
            "check", "raise", "catch", "throw", "wrap", "list"
        }:
            continue
        if fn not in corpus:
            hallucinated.append(fn + "()")

    return list(dict.fromkeys(hallucinated))


def _extract_json_object(raw: str) -> str:
    start = raw.find("{")
    if start == -1:
        raise ValueError("No JSON object found in model output.")

    depth = 0
    in_string = False
    escape = False

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
                return raw[start:i + 1]

    raise ValueError("Unbalanced JSON object in model output.")


def _parse_and_validate(raw: str) -> dict:
    try:
        extracted = _extract_json_object(raw)
    except ValueError:
        extracted = raw.strip()

    try:
        data = json.loads(extracted)
    except json.JSONDecodeError:
        cleaned = re.sub(r",\s*}", "}", extracted)
        cleaned = re.sub(r",\s*]", "]", cleaned)
        data = json.loads(cleaned)

    return data


def _format_file_list(files: list) -> str:
    if not files:
        return "None"

    icons = {"added": "+", "removed": "-", "renamed": "->", "modified": "~"}
    lines = []

    for f in files:
        icon = icons.get(f.get("status", "modified"), "~")
        skip = f" [skipped: {f['skipped_reason']}]" if f.get("skipped_reason") else ""
        lines.append(
            f"  {icon} {f.get('filename', '')}  +{f.get('additions', 0)}/-{f.get('deletions', 0)}{skip}"
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
            f"### {f.get('filename', '')}  (+{f.get('additions', 0)}/-{f.get('deletions', 0)}){note}\n"
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