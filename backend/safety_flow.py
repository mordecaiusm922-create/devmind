from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field

from evaluate import evaluate_payload


class CandidatePayload(BaseModel):
    id: str | None = None
    diff: str = ""
    strategy: str = ""
    explanation: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class SafetyFlowRequest(BaseModel):
    prompt: str
    candidates: list[CandidatePayload] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)
    mode: str = "secure"
    intent: dict[str, Any] = Field(default_factory=dict)
    evidence: dict[str, Any] = Field(default_factory=dict)
    history: list[dict[str, Any]] = Field(default_factory=list)
    files: list[dict[str, Any]] = Field(default_factory=list)
    repo: str | None = None
    properties: list[str] = Field(default_factory=list)
    n_candidates: int = 3


_SECRET_ASSIGN_RE = re.compile(
    r"(?im)^\+?\s*(SECRET_KEY|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY)\s*=\s*['\"][^'\"]{8,}['\"]"
)
_ENV_READ_RE = re.compile(r"\b(os\.environ(?:\.get)?|os\.getenv|environ\.get)\b")
_FAIL_FAST_RE = re.compile(r"\braise\s+\w*error\b|\bassert\s+", re.IGNORECASE)
_PARAM_SQL_RE = re.compile(r"execute\s*\([^,\n]+,\s*(\[|\(|\{)", re.IGNORECASE)
_UNSAFE_SQL_RE = re.compile(r"execute\s*\([^,\n]*(\+|%|\.format\(|f['\"])", re.IGNORECASE)
_AUTH_GUARD_RE = re.compile(
    r"(?im)^\+\s*(if\s+not\s+.*?(policy\.|can_|authorize|has_permission|is_admin)|@\w*permission\w*|@\w*login_required)"
)
_REMOVED_AUTH_RE = re.compile(
    r"(?im)^-\s*(if|raise|return).*?(is_admin|permission|authorize|can_|policy|rbac)"
)


def run_safety_flow(req: SafetyFlowRequest) -> dict[str, Any]:
    candidates = [_candidate_to_dict(c, i) for i, c in enumerate(req.candidates)]
    prior_data: dict[str, Any] = {}
    if req.repo:
        try:
            from memory import get_prior_for_prompt
            prior_data = get_prior_for_prompt(req.repo, req.prompt)
        except Exception:
            pass
    if not candidates:
        candidates = _generate_candidates(req.prompt, req.context, req.n_candidates)
        

    payload = {
        "prompt": req.prompt,
        "candidates": candidates,
        "context": req.context,
        "mode": req.mode,
        "intent": req.intent or _infer_intent(req.prompt, req.context),
        "evidence": req.evidence,
        "history": req.history,
        "files": req.files,
        "repo": req.repo,
    }
    evaluation = evaluate_payload(payload)["evaluation"]
    properties = _infer_properties(req.prompt, req.context, req.properties)

    verifications = {
        candidate["id"]: _verify_candidate(candidate, properties)
        for candidate in candidates
    }
    ranking = _rank_candidates(evaluation["scores"], verifications)
    selected = ranking[0] if ranking else None
    decision = _final_decision(req.mode, selected, evaluation)

    return {
        "flow": [
            "generate",
            "score",
            "verify",
            "risk_adjust",
            "rank",
            "decide",
        ],
        "policy": {
            "objective": "maximize risk_adjusted_utility",
            "formula": "utility - 0.14*violations - 0.25*critical_violations - 0.08*uncertainty + 0.04*verified",
            "security_gate": "critical violations cannot be approved",
        },
        "generated": len(req.candidates) == 0,
        "properties": properties,
        "candidates": candidates,
        "evaluation": evaluation,
        "verification": verifications,
        "ranking": ranking,
        "selected": selected,
        "decision": decision,
        "prior": prior_data,
    }


def _candidate_to_dict(candidate: CandidatePayload, idx: int) -> dict[str, Any]:
    data = candidate.model_dump()
    data["id"] = data["id"] or f"c{idx + 1}"
    return data


def _infer_intent(prompt: str, context: dict[str, Any]) -> dict[str, Any]:
    text = f"{prompt} {context}".lower()
    if any(k in text for k in ("secret", "sql", "injection", "auth", "permission", "token")):
        return {"label": "secure_fix", "confidence": 0.78}
    if any(k in text for k in ("latency", "performance", "slow", "throughput")):
        return {"label": "performance_fix", "confidence": 0.68}
    return {"label": "general_fix", "confidence": 0.55}


def _infer_properties(prompt: str, context: dict[str, Any], explicit: list[str]) -> list[str]:
    props = list(dict.fromkeys(explicit))
    text = f"{prompt} {context}".lower()

    if any(k in text for k in ("secret", "token", "api_key", "password")):
        props.extend(["no_hardcoded_secret", "secret_from_environment", "fail_fast"])
    if any(k in text for k in ("sql", "query", "injection", "cursor.execute")):
        props.extend(["no_raw_sql", "parameterized_sql"])
    if any(k in text for k in ("auth", "authorization", "permission", "rbac", "is_admin")):
        props.extend(["auth_guard_present", "no_auth_guard_removal", "fail_closed"])

    return list(dict.fromkeys(props))


def _generate_candidates(prompt: str, context: dict[str, Any], n: int) -> list[dict[str, Any]]:
    text = f"{prompt} {context}".lower()
    filename = str(context.get("filename") or context.get("file") or "app.py")

    if any(k in text for k in ("sql", "query", "injection")):
        templates = [
            (
                "parameterized-sql",
                f"+cursor.execute(\"SELECT * FROM users WHERE email = %s\", [email])",
                "Use bound parameters so user input is never concatenated into SQL.",
            ),
            (
                "orm-filter",
                "+user = User.objects.filter(email=email).first()",
                "Use ORM query construction to avoid raw SQL interpolation.",
            ),
            (
                "validate-and-parameterize",
                "+validate_email(email)\n+cursor.execute(\"SELECT * FROM users WHERE email = %s\", [email])",
                "Validate input shape and use parameterized SQL.",
            ),
        ]
    elif any(k in text for k in ("auth", "authorization", "permission", "rbac", "is_admin")):
        templates = [
            (
                "policy-check",
                "+if not policy.can_perform(user, resource):\n+    raise PermissionError(\"not authorized\")\n+return perform_action(resource)",
                "Fail closed through a centralized authorization policy.",
            ),
            (
                "explicit-admin-guard",
                "+if not user.is_admin:\n+    raise PermissionError(\"admin required\")\n+return perform_action(resource)",
                "Add an explicit permission guard before the sensitive action.",
            ),
            (
                "decorator-guard",
                "+@requires_permission(\"resource:write\")\n+def handler(request):\n+    return perform_action(resource)",
                "Protect the entrypoint with a permission decorator.",
            ),
        ]
    elif any(k in text for k in ("secret", "token", "api_key", "password")):
        templates = [
            (
                "env-fail-fast",
                "+import os\n+SECRET_KEY = os.environ.get(\"SECRET_KEY\")\n+if not SECRET_KEY:\n+    raise RuntimeError(\"SECRET_KEY environment variable is not set\")",
                "Read secret from the environment and fail closed if it is missing.",
            ),
            (
                "env-only",
                "+import os\n+SECRET_KEY = os.environ.get(\"SECRET_KEY\")",
                "Read secret from the environment with a minimal change.",
            ),
            (
                "config-loader",
                "+SECRET_KEY = config.require_secret(\"SECRET_KEY\")",
                "Use a config helper that requires secret material at runtime.",
            ),
        ]
    else:
        templates = [
            ("minimal-patch", "+# minimal fix placeholder", "Small patch with minimal blast radius."),
            ("robust-guard", "+assert invariant_holds()", "Add an invariant guard before changing behavior."),
            ("test-backed", "+# add regression test for the changed behavior", "Prefer a test-backed fix."),
        ]

    candidates = []
    for idx, (strategy, body, explanation) in enumerate(templates[: max(1, n)]):
        candidates.append(
            {
                "id": f"g{idx + 1}",
                "diff": (
                    f"diff --git a/{filename} b/{filename}\n"
                    f"--- a/{filename}\n"
                    f"+++ b/{filename}\n"
                    f"@@\n"
                    f"{body}\n"
                ),
                "strategy": strategy,
                "explanation": explanation,
                "metadata": {"generated_by": "safety_flow", "rank": idx + 1},
            }
        )
    return candidates


def _verify_candidate(candidate: dict[str, Any], properties: list[str]) -> dict[str, Any]:
    diff = str(candidate.get("diff") or "")
    violations: list[str] = []
    critical: list[str] = []
    evidence: list[str] = []

    for prop in properties:
        if prop == "no_hardcoded_secret":
            if _SECRET_ASSIGN_RE.search(diff):
                violations.append(prop)
                critical.append(prop)
            else:
                evidence.append(prop)
        elif prop == "secret_from_environment":
            if not _ENV_READ_RE.search(diff) and "require_secret" not in diff:
                violations.append(prop)
            else:
                evidence.append(prop)
        elif prop in {"fail_fast", "fail_closed"}:
            if not _FAIL_FAST_RE.search(diff):
                violations.append(prop)
            else:
                evidence.append(prop)
        elif prop == "no_raw_sql":
            if _UNSAFE_SQL_RE.search(diff) and not _PARAM_SQL_RE.search(diff):
                violations.append(prop)
                critical.append(prop)
            else:
                evidence.append(prop)
        elif prop == "parameterized_sql":
            if not _PARAM_SQL_RE.search(diff) and "objects.filter" not in diff:
                violations.append(prop)
            else:
                evidence.append(prop)
        elif prop == "auth_guard_present":
            if not _AUTH_GUARD_RE.search(diff):
                violations.append(prop)
            else:
                evidence.append(prop)
        elif prop == "no_auth_guard_removal":
            if _REMOVED_AUTH_RE.search(diff):
                violations.append(prop)
                critical.append(prop)
            else:
                evidence.append(prop)

    score = max(0.0, 1.0 - 0.14 * len(violations) - 0.20 * len(critical))
    return {
        "verified": not violations,
        "score": round(score, 4),
        "violations": violations,
        "critical_violations": critical,
        "evidence": evidence,
    }


def _rank_candidates(scores: dict[str, Any], verifications: dict[str, Any]) -> list[dict[str, Any]]:
    ranking: list[dict[str, Any]] = []
    for cid, score in scores.items():
        verification = verifications.get(cid, {})
        utility = float(score.get("utility", 0.0))
        uncertainty = float(score.get("uncertainty", 0.0))
        violations = len(verification.get("violations", []))
        critical = len(verification.get("critical_violations", []))
        verified_bonus = 0.04 if verification.get("verified") else 0.0
        adjusted = utility - 0.14 * violations - 0.25 * critical - 0.08 * uncertainty + verified_bonus
        ranking.append(
            {
                "candidate": cid,
                "utility": round(utility, 4),
                "risk_adjusted_utility": round(max(0.0, adjusted), 4),
                "security": score.get("security"),
                "correctness": score.get("correctness"),
                "uncertainty": score.get("uncertainty"),
                "verified": verification.get("verified", False),
                "violations": verification.get("violations", []),
                "critical_violations": verification.get("critical_violations", []),
                "rationale": score.get("rationale", []),
            }
        )

    return sorted(
        ranking,
        key=lambda item: (
            not item["critical_violations"],
            item["verified"],
            item["risk_adjusted_utility"],
            item["security"] or 0,
        ),
        reverse=True,
    )


def _final_decision(mode: str, selected: dict[str, Any] | None, evaluation: dict[str, Any]) -> dict[str, Any]:
    if selected is None:
        return {"action": "abstain", "reason": "No candidate available."}

    if selected["critical_violations"]:
        return {
            "action": "reject",
            "reason": "Best candidate still has critical safety violations.",
            "candidate": selected["candidate"],
        }

    if selected["violations"]:
        return {
            "action": "revise",
            "reason": "Best candidate has unresolved verification violations.",
            "candidate": selected["candidate"],
        }

    if mode.lower() in {"secure", "robust", "critical"} or evaluation.get("requires_verification"):
        return {
            "action": "needs_verification",
            "reason": "Candidate passes policy checks but safety-sensitive mode requires human or test verification.",
            "candidate": selected["candidate"],
        }

    return {
        "action": "approve",
        "reason": "Candidate has the best risk-adjusted utility and passes policy checks.",
        "candidate": selected["candidate"],
    }
