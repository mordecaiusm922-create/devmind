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


# =========================
# SYSTEM PROMPT (CLEAN)
# =========================
SYSTEM_PROMPT = (
    "You are DevMind, a security-focused code analysis engine. "
    "You think like an attacker, not a reviewer. "

    "Your job is to detect real exploitable vulnerabilities in pull requests. "

    "FOCUS AREAS: "
    "credential exposure, injection vectors, auth flaws, privilege escalation, "
    "CI/CD misconfigurations, supply chain risks, insecure dependencies. "

    "CI/CD PRIORITY: "
    "pull_request_target risks, missing permissions block, mutable action versions, "
    "unsafe artifact usage, secrets exposed before validation. "

    "STRICT RULES: "
    "Every claim MUST include filename, line, and code snippet. "
    "No vague language. Be deterministic. "
    "If no real exploit path exists, do not invent one. "
    "Think: can attacker control input -> reach sensitive resource -> impact. "

    "Before answering, internally reason: "
    "1) what changed "
    "2) attacker control "
    "3) sensitive resource "
    "4) realistic exploit path "

    "Output ONLY valid JSON. No explanations."
)


# =========================
# MAIN ENTRY
# =========================
def summarize_pr(pr_data: dict):
    pre = pre_analyse(pr_data)
    files_with_diff = [f for f in pr_data.get("files", []) if f.get("diff")]

    if pr_data.get("is_large_pr") or len(files_with_diff) > CHUNK_FILE_THRESHOLD:
        summary = _summarize_large(pr_data, files_with_diff, pre)
    else:
        summary = _summarize_single(pr_data, files_with_diff, pre)

    summary = _normalize(summary)
    summary = enforce_risk_floor(summary, pre)

    hallucinations = _check_hallucinations(summary, pr_data)
    if hallucinations:
        summary["hallucination_warning"] = hallucinations

    ev = evaluate(summary, pr_data)

    return summary, pre, ev


# =========================
# SINGLE PASS
# =========================
def _summarize_single(pr_data, files, pre):
    prompt = _build_prompt(pr_data, files, pre)
    return _call_llm(prompt)


# =========================
# CHUNKING
# =========================
def _summarize_large(pr_data, files, pre):
    chunk_size = 8
    chunks = [files[i:i + chunk_size] for i in range(0, len(files), chunk_size)]

    partials = []
    for i, chunk in enumerate(chunks):
        prompt = _build_prompt(pr_data, chunk, pre, chunk_info=(i+1, len(chunks)))
        partials.append(_call_llm(prompt))

    return _synthesise(pr_data, partials, pre)


def _synthesise(pr_data, partials, pre):
    prompt = (
        f"Combine multiple analyses into one final result.\n"
        f"PR: {pr_data['title']}\n"
        f"{json.dumps(partials)}\n"
        f"{_schema()}"
    )
    return _call_llm(prompt)


# =========================
# PROMPT BUILDER
# =========================
def _build_prompt(pr_data, files, pre, chunk_info=None):
    chunk_text = ""
    if chunk_info:
        chunk_text = f"Chunk {chunk_info[0]} of {chunk_info[1]}\n"

    return (
        f"{chunk_text}"
        f"PR: {pr_data['title']}\n"
        f"Author: @{pr_data['author']}\n"
        f"Files changed: {pr_data['changed_files']}\n\n"
        f"{pre.to_prompt_context()}\n\n"
        f"{_format_diffs(files)}\n\n"
        f"{_schema()}"
    )


# =========================
# SCHEMA (CORE)
# =========================
def _schema():
    return (
        'Return ONLY JSON:\n'
        '{\n'
        '  "what": "precise change summary",\n'
        '  "why": "technical reason",\n'
        '  "impact": "affected systems",\n'

        '  "risk": {\n'
        '    "level": "low | medium | high | critical",\n'
        '    "reason": "exact failure mechanism"\n'
        '  },\n'

        '  "scores": {\n'
        '    "exploitability": 0-10,\n'
        '    "impact": 0-10,\n'
        '    "confidence": 0-10\n'
        '  },\n'

        '  "merge_blocker": true | false,\n'

        '  "attack_path": {\n'
        '    "entry_point": "exact change",\n'
        '    "vector": "how exploited",\n'
        '    "sink": "target resource",\n'
        '    "impact": "data exfiltration | RCE | etc"\n'
        '  } | null,\n'

        '  "vulnerabilities": [\n'
        '    {\n'
        '      "type": "string",\n'
        '      "severity": "low | medium | high | critical",\n'
        '      "location": "file:Lx",\n'
        '      "description": "exact issue",\n'
        '      "fix": "specific fix",\n'
        '      "exploit_path": "step-by-step exploit"\n'
        '    }\n'
        '  ],\n'

        '  "key_changes": ["file:Lx what changed"],\n'
        '  "review_focus": "most critical issue",\n'
        '  "evidence": [\n'
        '    {\n'
        '      "claim": "finding",\n'
        '      "location": "file:Lx",\n'
        '      "snippet": "code"\n'
        '    }\n'
        '  ]\n'
        '}'
    )


# =========================
# LLM CALL
# =========================
def _call_llm(prompt):
    response = client.chat.completions.create(
        model=MODEL,
        temperature=0.2,
        max_tokens=4096,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
    )

    raw = response.choices[0].message.content
    return _parse(raw)


# =========================
# PARSER (ROBUST)
# =========================
def _parse(raw: str):
    match = re.search(r"\{.*\}", raw, re.DOTALL)
    if not match:
        raise ValueError("No JSON found")

    return json.loads(match.group(0))


# =========================
# NORMALIZER (CRUCIAL)
# =========================
def _normalize(data):
    data.setdefault("vulnerabilities", [])
    data.setdefault("evidence", [])
    data.setdefault("attack_path", None)

    if "scores" not in data:
        data["scores"] = {"exploitability": 0, "impact": 0, "confidence": 0}

    if "merge_blocker" not in data:
        data["merge_blocker"] = data.get("risk", {}).get("level") in ["high", "critical"]

    return data


# =========================
# HALLUCINATION CHECK
# =========================
def _check_hallucinations(summary, pr_data):
    corpus = " ".join([
        pr_data.get("title", ""),
        pr_data.get("body", ""),
        *[f.get("diff", "") for f in pr_data.get("files", [])]
    ])

    hallucinated = []
    for word in re.findall(r"\b[a-zA-Z_]{6,}\(\)", json.dumps(summary)):
        if word not in corpus:
            hallucinated.append(word)

    return list(set(hallucinated))


# =========================
# FORMAT DIFFS
# =========================
def _format_diffs(files):
    out = []
    for f in files:
        if f.get("diff"):
            out.append(f"### {f['filename']}\n{f['diff']}")
    return "\n\n".join(out)