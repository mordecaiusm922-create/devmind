import json
import os
import re
from typing import Any

from dotenv import load_dotenv
from openai import OpenAI

from evaluator import pre_analyse, evaluate, enforce_risk_floor

load_dotenv()

client = OpenAI(
    api_key=os.getenv("GROQ_API_KEY"),
    base_url="https://api.groq.com/openai/v1",
)

MODEL = "llama-3.3-70b-versatile"
MAX_TOKENS = 4096
TEMPERATURE = 0.2
CHUNK_FILE_THRESHOLD = 12

SYSTEM_PROMPT = (
    "You are DevMind, a security analysis engine for pull requests. "
    "Your job is to identify real, exploitable security issues grounded only in the diff.\n\n"

    "FALSIFIABILITY RULE:\n"
    "Before claiming a vulnerability, verify all of the following:\n"
    "1. The attacker can control the entry point.\n"
    "2. There is a concrete path from entry point to sensitive resource.\n"
    "3. The diff introduces the flaw, not a mitigation or detection.\n"
    "If any answer is no, do not claim a vulnerability.\n\n"

    "SECURITY IMPROVEMENT RULE:\n"
    "Adding a scanner (Trivy, Snyk, Grype, etc.) reduces risk. "
    "Pinning actions or updating to a safer version is usually a security improvement, not a vulnerability. "
    "Do not classify security improvements as vulnerabilities unless the diff proves a specific exploitable flaw.\n\n"

    "CI/CD THREAT MODEL:\n"
    "Only flag a CI/CD issue if all of the following are true:\n"
    "1. The trigger is pull_request_target, workflow_run, or another externally reachable trigger.\n"
    "2. The workflow runs untrusted code or accesses secrets before validation.\n"
    "3. The permissions block is missing or overly broad.\n"
    "4. The attacker can reach the trigger without repo write access.\n\n"

    "ATTACK PATH RULES:\n"
    "- entry_point must be a specific file:line from the diff.\n"
    "- exploit_steps must contain at least 3 concrete steps.\n"
    "- attacker_control_verified must be true, otherwise set attack_path to null.\n"
    "- sink must be a real resource proven reachable in the diff.\n"
    "- If risk is medium or higher but no realistic attack path exists, lower risk to low.\n\n"

    "BLAST RADIUS:\n"
    "For each vulnerability, estimate scope as one of: repo-only, org-wide, cross-account, public.\n"
    "Also estimate data at risk as one of: secrets, artifacts, source, prod-infra, none.\n\n"

    "Internal reasoning only, do not output:\n"
    "1. What changed?\n"
    "2. Is it a security improvement or a risk?\n"
    "3. Can an external attacker control the entry point?\n"
    "4. What are the exact exploit steps?\n"
    "5. What is the blast radius?\n\n"

    "Output only valid JSON. No markdown. No code fences. No explanations."
)

debug_capture: list[dict] | None = None

_SECURITY_IMPROVEMENT_MARKERS = (
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
)

_CI_CD_MARKERS = (
    "pull_request_target",
    "workflow_run",
    ".github/workflows/",
    "permissions:",
    "secrets.",
    "${{ secrets.",
    "configure-aws-credentials",
    "github-token",
)


def summarize_pr(pr_data: dict) -> tuple[dict, object, object]:
    pre = pre_analyse(pr_data)
    files_with_diff = [f for f in pr_data.get("files", []) if f.get("diff")]

    if pr_data.get("is_large_pr") or len(files_with_diff) > CHUNK_FILE_THRESHOLD:
        summary = _summarize_large_pr(pr_data, files_with_diff, pre)
    else:
        summary = _summarize_single_pass(pr_data, files_with_diff, pre)

    summary = _normalize_summary(summary)
    summary = _post_validate_summary(summary, pr_data)
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
            {"role": "user", "content": user_prompt},
        ],
    )

    choice = response.choices[0]
    raw = choice.message.content or ""

    if choice.finish_reason == "length":
        raise ValueError(
            f"LLM response truncated (finish_reason=length). "
            f"Prompt length: {len(user_prompt)} chars."
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
        '  "risk": {\n'
        '    "level": "low | medium | high | critical",\n'
        '    "reason": "Exact failure mechanism with file:line reference. If the change adds security tooling, level must be low."\n'
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
        '      "description": "Exact flaw with file:line reference. Do NOT list security improvements as vulnerabilities.",\n'
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
        "- Adding Trivy, Snyk, or any scanner is a security improvement, not a vulnerability.\n"
        "- Attack path requires attacker_control_verified to be true and at least 3 exploit_steps.\n"
        "- If attacker_control_verified is false, attack_path must be null.\n"
        "- Vulnerabilities must not include security improvements or version updates without a specific CVE.\n"
        "- If workflow files are present, populate permissions_analysis.\n"
        "- Evidence is mandatory for every vulnerability entry.\n"
        "- All strings must use ASCII-safe characters only.\n"
    )


def _normalize_summary(data: dict) -> dict:
    if not isinstance(data, dict):
        raise ValueError("LLM output did not parse into an object.")

    data.setdefault("what", "")
    data.setdefault("why", "")
    data.setdefault("impact", "")
    data.setdefault("risk", {})
    data.setdefault("permissions_analysis", None)
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

    data["ci_cd_risks"] = [
        r for r in data["ci_cd_risks"]
        if isinstance(r, dict) and r.get("evidence_snippet", "").strip()
    ]

    _sanitize_strings(data)
    return data


def _post_validate_summary(summary: dict, pr_data: dict) -> dict:
    """
    Consistency gate:
    - Security improvements cannot be vulnerabilities.
    - Attack path must be supported by proof.
    - Medium+ risk without proof is lowered.
    """
    risk_level = str((summary.get("risk") or {}).get("level", "low")).lower()
    vulnerabilities = summary.get("vulnerabilities", [])
    attack_path = summary.get("attack_path")

    title_body = " ".join([
        pr_data.get("title", "") or "",
        pr_data.get("body", "") or "",
        " ".join(pr_data.get("commit_messages", [])),
        json.dumps(vulnerabilities, ensure_ascii=False),
        json.dumps(summary.get("ci_cd_risks", []), ensure_ascii=False),
    ]).lower()

    if any(marker in title_body for marker in _SECURITY_IMPROVEMENT_MARKERS):
        specific_cve = bool(re.search(r"CVE-\d{4}-\d+", title_body))
        if not specific_cve:
            summary["risk"] = {
                "level": "low",
                "reason": "Security improvement or dependency maintenance change without a proven exploit path.",
            }
            summary["attack_path"] = None
            summary["vulnerabilities"] = []

    if summary.get("attack_path") and isinstance(summary["attack_path"], dict):
        attacker_verified = bool(summary["attack_path"].get("attacker_control_verified", False))
        exploit_steps = summary["attack_path"].get("exploit_steps", [])
        if not attacker_verified or not isinstance(exploit_steps, list) or len(exploit_steps) < 3:
            summary["attack_path"] = None

    if risk_level in {"medium", "high", "critical"} and summary.get("attack_path") is None:
        summary["risk"] = {
            "level": "low",
            "reason": "No confirmed attacker-controlled exploit path in the diff.",
        }

    if summary.get("risk", {}).get("level") in {"high", "critical"}:
        if not summary.get("vulnerabilities") and not summary.get("ci_cd_risks"):
            summary["risk"] = {
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
        json.dumps(summary.get("ci_cd_risks", []), ensure_ascii=False),
    ])

    common = frozenset({
        "make", "take", "have", "give", "find", "call", "send",
        "read", "load", "save", "open", "close", "init", "test",
        "check", "raise", "catch", "throw", "wrap", "list",
    })

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