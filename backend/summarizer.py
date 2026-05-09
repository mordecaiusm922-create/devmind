from __future__ import annotations

import json
import os
import re
from typing import Any, Optional

from dotenv import load_dotenv
from openai import OpenAI

from evaluator import enforce_risk_floor, evaluate, pre_analyse

load_dotenv()

client = OpenAI(
    api_key=os.getenv("GROQ_API_KEY"),
    base_url="https://api.groq.com/openai/v1",
)

MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
MAX_TOKENS = int(os.getenv("GROQ_MAX_TOKENS", "4096"))
TEMPERATURE = float(os.getenv("GROQ_TEMPERATURE", "0.2"))
CHUNK_FILE_THRESHOLD = int(os.getenv("DEVMD_CHUNK_FILE_THRESHOLD", "12"))
CHUNK_SIZE = int(os.getenv("DEVMD_CHUNK_SIZE", "6"))

SYSTEM_PROMPT = (
    "You are DevMind, a security analysis engine for pull requests. "
    "Your job is to identify real, exploitable security issues grounded only in the diff.\n\n"
    "Rules:\n"
    "- Every claim must be grounded in the diff.\n"
    "- Always cite a real file, line, and code snippet when possible.\n"
    "- Do not invent vulnerabilities.\n"
    "- If there is no realistic attack path, set attack_path to null.\n"
    "- Be precise. Avoid vague wording.\n"
    "- The pre-analysis block is authoritative.\n\n"
    "Security improvements are not vulnerabilities.\n"
    "Adding scanners, pinning safer versions, or reducing permissions should not be classified as vulnerabilities unless the diff proves a specific exploitable flaw.\n\n"
    "CI/CD threat model:\n"
    "- Only flag a CI/CD issue if the workflow exposes a real attack surface.\n"
    "- Check for pull_request_target, workflow_run, secrets access, permissions blocks, and trust boundary violations.\n\n"
    "Attack path rules:\n"
    "- entry_point must be a specific file:line from the diff.\n"
    "- exploit_steps must contain concrete steps.\n"
    "- attacker_control_verified must be true, otherwise set attack_path to null.\n"
    "- sink must be a real resource proven reachable in the diff.\n\n"
    "Output only valid JSON. No markdown. No code fences. No explanations."
)

debug_capture: list[dict] | None = None


def summarize_pr(pr_data: dict, model: Any | None = None, retriever_ctx: dict | None = None) -> tuple[dict, object, object]:
    """
    Main entrypoint.

    Flow:
    1. Pre-analyze PR
    2. Summarize with LLM (single-pass or chunked)
    3. Normalize + validate + enforce risk floor
    4. Evaluate with hybrid evaluator
    5. Attach scores and probabilistic signal
    """
    pre = pre_analyse(pr_data)
    files_with_diff = [f for f in pr_data.get("files", []) if f.get("diff")]

    if pr_data.get("is_large_pr") or len(files_with_diff) > CHUNK_FILE_THRESHOLD:
        summary = _summarize_large_pr(pr_data, files_with_diff, pre)
    else:
        summary = _summarize_single_pass(pr_data, files_with_diff, pre)

    summary = _normalize_summary(summary)
    summary = enforce_risk_floor(summary, pre)
    summary = _post_validate_summary(summary, pr_data)

    hallucinations = _check_hallucinations(summary, pr_data)
    if hallucinations:
        summary["hallucination_warning"] = hallucinations

    ev = evaluate(summary, pr_data, model=model)
    summary["scores"] = ev.get("scores", {})
    summary["triage"] = ev.get("triage")
    summary["merge_blocker"] = ev.get("merge_blocker", False)
    summary["probabilistic"] = ev.get("probabilistic", {})
    summary["risk_signals"] = ev.get("risk_signals", {})
    summary["usefulness"] = ev.get("usefulness", {})
    summary["evaluation"] = ev.get("evaluation", {})
    summary["features"] = ev.get("features", {})
    summary["feature_vector"] = ev.get("feature_vector", [])

    return summary, pre, ev


def _summarize_single_pass(pr_data: dict, files_with_diff: list, pre) -> dict:
    prompt = _build_full_prompt(pr_data, files_with_diff, pre)
    return _call_llm(prompt)


def _summarize_large_pr(pr_data: dict, files_with_diff: list, pre) -> dict:
    chunks = [
        files_with_diff[i : i + CHUNK_SIZE]
        for i in range(0, len(files_with_diff), CHUNK_SIZE)
    ]

    partial_summaries = []
    for i, chunk in enumerate(chunks, start=1):
        prompt = _build_chunk_prompt(pr_data, chunk, i, len(chunks), pre)
        partial_summaries.append(_call_llm(prompt))

    return _synthesise(pr_data, partial_summaries, pre)


def _synthesise(pr_data: dict, partials: list[dict], pre) -> dict:
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
        f"Keep only findings grounded in the PR data.\n\n"
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
            {"role": "user", "content": user_prompt},
        ],
    )

    choice = response.choices[0]
    raw = choice.message.content or ""

    if choice.finish_reason == "length":
        raise ValueError(
            f"LLM response truncated (finish_reason=length). Prompt length: {len(user_prompt)} chars."
        )

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
        f"PR ANALYSIS -- chunk {chunk_num}/{total}\n\n"
        f"Title: {pr_data.get('title', '')}\n"
        f"Author: @{pr_data.get('author', '')}\n"
        f"Repository: {pr_data.get('repo', '')}\n"
        f"Files changed: {pr_data.get('changed_files', 0)} "
        f"(+{pr_data.get('additions', 0)} / -{pr_data.get('deletions', 0)})\n\n"
        f"{pre.to_prompt_context()}\n\n"
        f"Commit messages:\n{_format_commits(pr_data.get('commit_messages', []))}\n\n"
        f"Changed files (this chunk):\n{_format_file_list(chunk)}\n\n"
        f"Diffs:\n{_format_diffs(chunk)}\n\n"
        f"{_output_schema_instruction()}"
    )


def _output_schema_instruction() -> str:
    return (
        "Return ONLY a JSON object with these exact top-level keys:\n"
        "{\n"
        '  "what": "Precise 1 to 2 sentence description of what changed.",\n'
        '  "why": "Technical reason for this change.",\n'
        '  "impact": "Which systems, workflows, or behaviors are affected.",\n'
        '  "risk_note": {\n'
        '    "level": "low | medium | high | critical",\n'
        '    "reason": "Exact failure mechanism with file:line reference."\n'
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
        '      "Step 2: workflow trigger fires with unsafe trust boundary.",\n'
        '      "Step 3: secrets or privileged token are exposed."\n'
        "    ],\n"
        '    "sink": "The exact resource compromised.",\n'
        '    "blast_radius": "repo-only | org-wide | cross-account | public",\n'
        '    "impact": "account_takeover | data_exfiltration | privilege_escalation | rce | supply_chain | other"\n'
        "  },\n"
        '  "vulnerabilities": [\n'
        "    {\n"
        '      "type": "credential_exposure | sql_injection | xss | auth_bypass | privilege_escalation | ci_cd_misconfig | supply_chain | other",\n'
        '      "severity": "low | medium | high | critical",\n'
        '      "location": "filename:L12-18",\n'
        '      "description": "Exact flaw with file:line reference.",\n'
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
        '      "line": "filename:Lx",\n'
        '      "evidence_snippet": "exact line(s) from diff that prove this risk"\n'
        "    }\n"
        "  ],\n"
        '  "key_changes": ["filename:L12-18 -- what changed and why it matters"],\n'
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
        "- Security improvements are not vulnerabilities.\n"
        "- attack_path must be null if no attacker-controlled path exists.\n"
        "- evidence is mandatory for every vulnerability entry.\n"
        "- all strings must be ASCII-safe.\n"
    )


def _normalize_summary(data: dict) -> dict:
    if not isinstance(data, dict):
        raise ValueError("LLM output did not parse into an object.")

    data.setdefault("what", "")
    data.setdefault("why", "")
    data.setdefault("impact", "")
    data.setdefault("risk_note", {})
    data.setdefault("permissions_analysis", None)
    data.setdefault("attack_path", None)
    data.setdefault("vulnerabilities", [])
    data.setdefault("ci_cd_risks", [])
    data.setdefault("key_changes", [])
    data.setdefault("review_focus", "")
    data.setdefault("evidence", [])

    risk = data.get("risk_note", {})
    if isinstance(risk, str):
        parts = risk.split("--", 1)
        level = parts[0].strip().lower()
        reason = parts[1].strip() if len(parts) > 1 else risk.strip()
        data["risk_note"] = {"level": level, "reason": reason}
    elif isinstance(risk, dict):
        data["risk_note"]["level"] = str(risk.get("level", "low")).lower()
        data["risk_note"]["reason"] = str(risk.get("reason", "")).strip()
    else:
        data["risk_note"] = {"level": "low", "reason": ""}

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

    _sanitize_strings(data)
    return data


def _post_validate_summary(summary: dict, pr_data: dict) -> dict:
    risk_level = str((summary.get("risk_note") or {}).get("level", "low")).lower()
    title_body = " ".join(
        [
            pr_data.get("title", "") or "",
            pr_data.get("body", "") or "",
            " ".join(pr_data.get("commit_messages", [])),
            json.dumps(summary.get("vulnerabilities", []), ensure_ascii=False),
            json.dumps(summary.get("ci_cd_risks", []), ensure_ascii=False),
        ]
    ).lower()

    security_improvement_markers = [
        "trivy",
        "snyk",
        "grype",
        "scanner",
        "vulnerability scanner",
        "pin",
        "latest version",
        "security improvement",
        "reduce risk",
    ]

    if any(marker in title_body for marker in security_improvement_markers):
        specific_cve = bool(re.search(r"CVE-\d{4}-\d+", title_body))
        if not specific_cve:
            summary["risk_note"] = {
                "level": "low",
                "reason": "Security improvement or dependency maintenance change without a proven exploit path.",
            }
            summary["attack_path"] = None
            summary["vulnerabilities"] = []
            if not summary.get("ci_cd_risks"):
                summary["ci_cd_risks"] = []

    attack_path = summary.get("attack_path")
    if attack_path and isinstance(attack_path, dict):
        attacker_verified = bool(attack_path.get("attacker_control_verified", False))
        exploit_steps = attack_path.get("exploit_steps", [])
        if not attacker_verified or not isinstance(exploit_steps, list) or len(exploit_steps) < 3:
            summary["attack_path"] = None

    if risk_level in {"medium", "high", "critical"} and summary.get("attack_path") is None:
        summary["risk_note"] = {
            "level": "low",
            "reason": "No confirmed attacker-controlled exploit path in the diff.",
        }

    if summary.get("risk_note", {}).get("level") in {"high", "critical"}:
        if not summary.get("vulnerabilities") and not summary.get("ci_cd_risks"):
            summary["risk_note"] = {
                "level": "low",
                "reason": "No concrete vulnerability or CI/CD risk was proven in the diff.",
            }

    return summary


def _sanitize_strings(obj: Any) -> None:
    replacements = {
        "\u2014": "--",
        "\u2013": "-",
        "\u2012": "-",
        "\u2192": "->",
        "\u2190": "<-",
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2026": "...",
    }

    def clean(s: str) -> str:
        for ch, repl in replacements.items():
            s = s.replace(ch, repl)
        return s

    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str):
                obj[k] = clean(v)
            else:
                _sanitize_strings(v)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            if isinstance(item, str):
                obj[i] = clean(item)
            else:
                _sanitize_strings(item)


def _check_hallucinations(summary: dict, pr_data: dict) -> list[str]:
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
            json.dumps(summary.get("vulnerabilities", []), ensure_ascii=False),
            json.dumps(summary.get("ci_cd_risks", []), ensure_ascii=False),
        ]
    )

    common = frozenset(
        {
            "make",
            "take",
            "have",
            "give",
            "find",
            "call",
            "send",
            "read",
            "load",
            "save",
            "open",
            "close",
            "init",
            "test",
            "check",
            "raise",
            "catch",
            "throw",
            "wrap",
            "list",
        }
    )

    hallucinated = []
    for m in re.finditer(r"\b([a-z][a-z0-9_]{3,})\(\)", summary_text):
        fn = m.group(1)
        if fn in common:
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