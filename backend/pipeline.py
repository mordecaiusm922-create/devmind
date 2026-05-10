# backend/pipeline.py
from __future__ import annotations

import asyncio
import json
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Protocol, Tuple


# ============================================================
# Core types
# ============================================================

class Decision(str, Enum):
    APPROVE = "approve"
    REVISE = "revise"
    REJECT = "reject"
    NEEDS_VERIFICATION = "needs_verification"
    NEEDS_REPAIR = "needs_repair"
    ABSTAIN = "abstain"


class Mode(str, Enum):
    FAST = "fast"
    BALANCED = "balanced"
    SECURE = "secure"
    ROBUST = "robust"
    CRITICAL = "critical"


@dataclass
class TaskInput:
    prompt: str
    context: Dict[str, Any] = field(default_factory=dict)
    history: List[Dict[str, Any]] = field(default_factory=list)
    files: List[Dict[str, Any]] = field(default_factory=list)
    mode: Mode = Mode.BALANCED
    repo: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IntentHypothesis:
    label: str
    confidence: float
    alternatives: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


@dataclass
class RetrievedEvidence:
    docs: List[Dict[str, Any]] = field(default_factory=list)
    code: List[Dict[str, Any]] = field(default_factory=list)
    tests: List[Dict[str, Any]] = field(default_factory=list)
    history: List[Dict[str, Any]] = field(default_factory=list)
    policy: List[Dict[str, Any]] = field(default_factory=list)
    graph: Dict[str, Any] = field(default_factory=dict)
    memory: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Candidate:
    id: str
    diff: str
    strategy: str = ""
    explanation: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CandidateScore:
    correctness: float
    correctness_uncertainty: float
    security: float
    security_uncertainty: float
    robustness: float
    performance: float
    maintainability: float
    alignment: float
    catastrophic_risk: float
    regression_risk: float
    uncertainty: float
    utility: float
    confidence: float
    risk_tags: List[str] = field(default_factory=list)
    rationale: List[str] = field(default_factory=list)


@dataclass
class EvaluationResult:
    decision: Decision
    chosen_candidate: Optional[str]
    scores: Dict[str, CandidateScore]
    risk_summary: Dict[str, float]
    best_rationale: List[str] = field(default_factory=list)
    requires_verification: bool = False
    requires_repair: bool = False
    threshold_hit: bool = False


@dataclass
class VerificationResult:
    verified: bool
    confidence: float
    violations: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


@dataclass
class RepairResult:
    candidate: Candidate
    iterations: int
    converged: bool
    history: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class PipelineResult:
    run_id: str
    prompt: str
    mode: str
    intent: IntentHypothesis
    evidence: RetrievedEvidence
    candidates: List[Candidate]
    evaluation: EvaluationResult
    verification: Optional[VerificationResult] = None
    repair: Optional[RepairResult] = None
    final_candidate: Optional[Candidate] = None
    applied: bool = False
    decision: Decision = Decision.ABSTAIN
    summary: Dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "prompt": self.prompt,
            "mode": self.mode,
            "intent": asdict(self.intent),
            "evidence": asdict(self.evidence),
            "candidates": [asdict(c) for c in self.candidates],
            "evaluation": {
                "decision": self.evaluation.decision.value,
                "chosen_candidate": self.evaluation.chosen_candidate,
                "scores": {cid: asdict(score) for cid, score in self.evaluation.scores.items()},
                "risk_summary": self.evaluation.risk_summary,
                "best_rationale": self.evaluation.best_rationale,
                "requires_verification": self.evaluation.requires_verification,
                "requires_repair": self.evaluation.requires_repair,
                "threshold_hit": self.evaluation.threshold_hit,
            },
            "verification": asdict(self.verification) if self.verification else None,
            "repair": asdict(self.repair) if self.repair else None,
            "final_candidate": asdict(self.final_candidate) if self.final_candidate else None,
            "applied": self.applied,
            "decision": self.decision.value,
            "summary": self.summary,
            "duration_ms": self.duration_ms,
        }


# ============================================================
# Engine protocols
# ============================================================

class IntentEngine(Protocol):
    async def infer(self, task: TaskInput) -> IntentHypothesis: ...


class RetrieverEngine(Protocol):
    async def retrieve(self, task: TaskInput, intent: IntentHypothesis) -> RetrievedEvidence: ...


class GeneratorEngine(Protocol):
    async def generate(
        self,
        task: TaskInput,
        intent: IntentHypothesis,
        evidence: RetrievedEvidence,
        strategy: Optional[str] = None,
        max_candidates: int = 3,
    ) -> List[Candidate]: ...


class EvaluatorEngine(Protocol):
    async def evaluate(
        self,
        task: TaskInput,
        intent: IntentHypothesis,
        evidence: RetrievedEvidence,
        candidate: Candidate,
    ) -> CandidateScore: ...


class RepairerEngine(Protocol):
    async def repair(
        self,
        task: TaskInput,
        intent: IntentHypothesis,
        evidence: RetrievedEvidence,
        candidate: Candidate,
        score: CandidateScore,
    ) -> Candidate: ...


class VerifierEngine(Protocol):
    async def verify(
        self,
        task: TaskInput,
        intent: IntentHypothesis,
        evidence: RetrievedEvidence,
        candidate: Candidate,
    ) -> VerificationResult: ...


class MemoryEngine(Protocol):
    async def read(self, task: TaskInput) -> Dict[str, Any]: ...
    async def write(self, task: TaskInput, result: PipelineResult) -> None: ...


class GraphEngine(Protocol):
    async def inspect(self, task: TaskInput) -> Dict[str, Any]: ...


class ApplierEngine(Protocol):
    async def apply(self, task: TaskInput, candidate: Candidate) -> Dict[str, Any]: ...


# ============================================================
# Imports from your other modules when available
# ============================================================

try:
    from .policy import PolicyEngine, Action
except Exception:  # pragma: no cover
    from policy import PolicyEngine, Action  # type: ignore

try:
    from .repair import repair_candidate
except Exception:  # pragma: no cover
    from repair import repair_candidate  # type: ignore

try:
    from .memory import (
        record_analysis_result,
        record_outcome,
        record_strategy_result,
        summarize_repo_memory,
        get_prior_for_prompt,
    )
except Exception:  # pragma: no cover
    record_analysis_result = None
    record_outcome = None
    record_strategy_result = None

    def summarize_repo_memory(repo: str) -> Dict[str, Any]:
        return {"repo": repo, "n_events": 0, "by_label": {}, "by_event_type": {}, "risk_profile": {}, "dev_profile": {}}

    def get_prior_for_prompt(repo: str, prompt: str) -> Dict[str, Any]:
        return {"intent": "general_fix", "priors": {}, "n_observations": 0}


# ============================================================
# Helpers
# ============================================================

def _clip01(x: float) -> float:
    return max(0.0, min(1.0, float(x)))


def _memory_key(task: TaskInput) -> str:
    repo = task.repo or task.context.get("repo") or "default"
    prompt_sig = re.sub(r"\s+", " ", task.prompt.strip().lower())[:96]
    return f"{repo}::{prompt_sig}"


def _safe_float(v: Any, default: float = 0.0) -> float:
    try:
        if v is None:
            return default
        return float(v)
    except Exception:
        return default


def _candidate_to_dict(c: Candidate) -> Dict[str, Any]:
    return {"id": c.id, "diff": c.diff, "strategy": c.strategy, "explanation": c.explanation, "metadata": dict(c.metadata)}


def _dict_to_candidate(d: Mapping[str, Any], fallback_id: str = "candidate") -> Candidate:
    return Candidate(
        id=str(d.get("id", fallback_id)),
        diff=str(d.get("diff", "")),
        strategy=str(d.get("strategy", "")),
        explanation=str(d.get("explanation", "")),
        metadata=dict(d.get("metadata", {}) or {}),
    )


def task_from_json(data: Mapping[str, Any]) -> TaskInput:
    mode = data.get("mode", Mode.BALANCED.value)
    if isinstance(mode, str):
        try:
            mode = Mode(mode.lower())
        except Exception:
            mode = Mode.BALANCED

    return TaskInput(
        prompt=str(data.get("prompt", "")),
        context=dict(data.get("context", {}) or {}),
        history=list(data.get("history", []) or []),
        files=list(data.get("files", []) or []),
        mode=mode,
        repo=data.get("repo"),
        metadata=dict(data.get("metadata", {}) or {}),
    )


# ============================================================
# Default engines
# ============================================================

class DefaultIntentEngine:
    SIGNALS: Tuple[Tuple[str, str, float], ...] = (
        (r"\b(sql injection|sqli|parameterized sql|unsafe query)\b", "sql_injection_fix", 0.42),
        (r"\b(xss|cross[- ]site scripting)\b", "xss_fix", 0.40),
        (r"\b(csrf|cross[- ]site request forgery)\b", "csrf_fix", 0.38),
        (r"\b(ssrf|server[- ]side request forgery)\b", "ssrf_fix", 0.42),
        (r"\b(rce|remote code execution|command injection)\b", "rce_fix", 0.48),
        (r"\b(auth bypass|authorization bypass|privilege escalation)\b", "auth_bypass_fix", 0.45),
        (r"\b(secret|secret_key|api[_-]?key|token|password|credential)\b", "secret_fix", 0.36),
        (r"\b(auth|authentication|authorization|rbac|permission)\b", "auth_fix", 0.28),
        (r"\b(race condition|deadlock|mutex|lock contention|thread safety)\b", "concurrency_fix", 0.40),
        (r"\b(timeout|retry|backoff|idempotency|circuit breaker)\b", "reliability_fix", 0.24),
        (r"\b(performance|latency|throughput|optimi[sz]e|slow query)\b", "performance_fix", 0.26),
        (r"\b(n\+1|cache miss|memory leak)\b", "performance_fix", 0.32),
        (r"\b(terraform|helm|kubernetes|k8s|docker|ci/cd|pipeline)\b", "infra_fix", 0.30),
        (r"\b(refactor|cleanup|maintainability|simplify)\b", "refactor", 0.18),
        (r"\b(test|unit test|integration test|coverage)\b", "testing", 0.16),
    )

    async def infer(self, task: TaskInput) -> IntentHypothesis:
        text = (task.prompt or "").lower()
        scores: Dict[str, float] = {}
        evidence: Dict[str, List[str]] = {}
        notes: List[str] = []

        for pattern, label, weight in self.SIGNALS:
            match = re.search(pattern, text)
            if match:
                scores[label] = scores.get(label, 0.0) + weight
                evidence.setdefault(label, []).append(match.group(0))
                notes.append(f"matched:{label}")

        filename = str(task.context.get("filename", "")).lower()
        if any(x in filename for x in ("auth", "login", "session", "rbac")):
            scores["auth_fix"] = scores.get("auth_fix", 0.0) + 0.12
        if any(x in filename for x in ("payment", "billing", "checkout")):
            scores["critical_payment_fix"] = scores.get("critical_payment_fix", 0.0) + 0.18
        if any(x in filename for x in ("terraform", "helm", "docker", "k8s")):
            scores["infra_fix"] = scores.get("infra_fix", 0.0) + 0.15

        if not scores:
            return IntentHypothesis(
                label="general_fix",
                confidence=0.41,
                alternatives=[],
                notes=["fallback:no_strong_signal"],
            )

        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        best_label, best_score = ranked[0]
        second_score = ranked[1][1] if len(ranked) > 1 else 0.0
        margin = best_score - second_score

        confidence = min(
            0.98,
            max(
                0.45,
                0.58 + (best_score * 0.55) + (margin * 0.18),
            ),
        )

        if task.mode in {Mode.SECURE, Mode.CRITICAL}:
            confidence = min(0.99, confidence + 0.03)
            notes.append("mode_bias:security_sensitive")
        if task.mode == Mode.FAST:
            confidence = max(0.35, confidence - 0.06)
            notes.append("mode_bias:fast")

        alternatives = [
            {"label": label, "score": round(score, 4), "evidence": evidence.get(label, [])}
            for label, score in ranked[1:4]
        ]

        return IntentHypothesis(
            label=best_label,
            confidence=round(confidence, 4),
            alternatives=alternatives,
            notes=notes[:12],
        )


class DefaultRetrieverEngine:
    async def retrieve(self, task: TaskInput, intent: IntentHypothesis) -> RetrievedEvidence:
        graph = task.context.get("graph", {})
        memory = task.context.get("memory", {})
        docs = task.context.get("docs", [])
        tests = task.context.get("tests", [])
        history = task.history or []
        policy = task.context.get("policy", [])
        code = task.files or []

        return RetrievedEvidence(
            docs=docs if isinstance(docs, list) else [docs],
            code=code if isinstance(code, list) else [code],
            tests=tests if isinstance(tests, list) else [tests],
            history=history,
            policy=policy if isinstance(policy, list) else [policy],
            graph=graph if isinstance(graph, dict) else {"raw": graph},
            memory=memory if isinstance(memory, dict) else {"raw": memory},
        )


class DefaultGeneratorEngine:
    async def generate(
        self,
        task: TaskInput,
        intent: IntentHypothesis,
        evidence: RetrievedEvidence,
        strategy: Optional[str] = None,
        max_candidates: int = 3,
    ) -> List[Candidate]:
        prompt = task.prompt.lower()
        candidates: List[Candidate] = []

        # Security: secrets
        if any(k in prompt for k in ("secret_key", "hardcoded secret", "hardcoded secret_key")):
            candidates.extend([
                Candidate(
                    id="c1",
                    diff='''import os
SECRET_KEY = os.environ.get("SECRET_KEY")
''',
                    strategy="minimal-patch",
                    explanation="Small patch sourced from environment.",
                    metadata={"mode": task.mode.value, "rank": 1, "intent": "secret_fix"},
                ),
                Candidate(
                    id="c2",
                    diff='''import os
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY not set")
''',
                    strategy="balanced-fix" if task.mode != Mode.FAST else "minimal-patch",
                    explanation="Robust fix with fail-fast.",
                    metadata={"mode": task.mode.value, "rank": 2, "intent": "secret_fix"},
                ),
            ])
            if task.mode in {Mode.SECURE, Mode.CRITICAL, Mode.ROBUST}:
                candidates.append(
                    Candidate(
                        id="c3",
                        diff='''import os
from pathlib import Path

SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("Missing SECRET_KEY")
''',
                        strategy="secure-defense",
                        explanation="Security-first candidate with explicit runtime failure.",
                        metadata={"mode": task.mode.value, "rank": 3, "intent": "secret_fix"},
                    )
                )
            return candidates[:max_candidates]

        # Security: SQL injection
        if re.search(r"\b(sql injection|sqli|sql)\b", prompt):
            candidates.extend([
                Candidate(
                    id="c1",
                    diff='''cursor.execute(
    "SELECT * FROM users WHERE email = '" + email + "'"
)
''',
                    strategy="unsafe-raw-sql",
                    explanation="Raw SQL with string concatenation — vulnerable to injection.",
                    metadata={"mode": task.mode.value, "rank": 1, "intent": "sql_injection_fix"},
                ),
                Candidate(
                    id="c2",
                    diff='''cursor.execute(
    "SELECT * FROM users WHERE email = %s",
    [email],
)
''',
                    strategy="parameterized-query",
                    explanation="Parameterized query eliminates SQL injection surface.",
                    metadata={"mode": task.mode.value, "rank": 2, "intent": "sql_injection_fix"},
                ),
                Candidate(
                    id="c3",
                    diff='''email = validate_email(email)

cursor.execute(
    "SELECT * FROM users WHERE email = %s",
    [email],
)
''',
                    strategy="validated-parameterized-query",
                    explanation="Validation plus parameterization for stronger posture.",
                    metadata={"mode": task.mode.value, "rank": 3, "intent": "sql_injection_fix"},
                ),
            ])
            if task.mode in {Mode.SECURE, Mode.CRITICAL, Mode.ROBUST}:
                candidates.append(
                    Candidate(
                        id="c4",
                        diff='''user = User.objects.filter(
    email=email
).first()
''',
                        strategy="orm-safe-query",
                        explanation="Move query handling into ORM abstraction.",
                        metadata={"mode": task.mode.value, "rank": 4, "intent": "sql_injection_fix"},
                    )
                )
            return candidates[:max_candidates]

        # Auth
        if any(k in prompt for k in ("auth", "authorization", "permission", "rbac")):
            candidates.extend([
                Candidate(
                    id="c1",
                    diff='''@login_required
def handler(request):
    return handler_impl(request)
''',
                    strategy="auth-guard",
                    explanation="Add explicit authentication guard.",
                    metadata={"mode": task.mode.value, "rank": 1, "intent": "auth_fix"},
                ),
                Candidate(
                    id="c2",
                    diff='''@login_required
def handler(request):
    if not policy.can_perform(request.user, "requested_action"):
        raise PermissionError("unauthorized")
    return handler_impl(request)
''',
                    strategy="policy-check",
                    explanation="Auth guard plus policy gate.",
                    metadata={"mode": task.mode.value, "rank": 2, "intent": "auth_fix"},
                ),
            ])
            return candidates[:max_candidates]

        # Concurrency
        if any(k in prompt for k in ("race condition", "concurrency", "deadlock", "mutex", "lock")):
            candidates.extend([
                Candidate(
                    id="c1",
                    diff="# add lock around critical section\n",
                    strategy="lock-guard",
                    explanation="Protect the critical section with synchronization.",
                    metadata={"mode": task.mode.value, "rank": 1, "intent": "concurrency_fix"},
                ),
                Candidate(
                    id="c2",
                    diff="# enforce idempotency and retry-safe behavior\n",
                    strategy="idempotent-fix",
                    explanation="Idempotency-first concurrency repair.",
                    metadata={"mode": task.mode.value, "rank": 2, "intent": "concurrency_fix"},
                ),
            ])
            return candidates[:max_candidates]

        # Generic generation path
        base_strategy = strategy or task.mode.value
        candidates.append(
            Candidate(
                id="c1",
                diff=f"# strategy: {base_strategy}\n# variant: minimal\n",
                strategy="minimal-patch",
                explanation="Minimal change candidate.",
                metadata={"mode": task.mode.value, "rank": 1, "intent": intent.label},
            )
        )
        if task.mode != Mode.FAST:
            candidates.append(
                Candidate(
                    id="c2",
                    diff=f"# strategy: {base_strategy}\n# variant: balanced\n",
                    strategy="balanced-fix",
                    explanation="Balanced candidate with safer defaults.",
                    metadata={"mode": task.mode.value, "rank": 2, "intent": intent.label},
                )
            )
        if task.mode in {Mode.SECURE, Mode.CRITICAL, Mode.ROBUST}:
            candidates.append(
                Candidate(
                    id="c3",
                    diff=f"# strategy: {base_strategy}\n# variant: secure\n",
                    strategy="secure-defense",
                    explanation="Security-first candidate.",
                    metadata={"mode": task.mode.value, "rank": 3, "intent": intent.label},
                )
            )

        return candidates[:max_candidates]


class DefaultEvaluatorEngine:
    def __init__(
        self,
        weights: Optional[Dict[str, float]] = None,
        beta: float = 1.0,
        approval_threshold: float = 0.72,
        verify_threshold: float = 0.60,
        uncertainty_threshold: float = 0.35,
    ) -> None:
        self.weights = weights or {
            "correctness": 0.30,
            "security": 0.30,
            "robustness": 0.15,
            "performance": 0.08,
            "maintainability": 0.09,
            "alignment": 0.08,
        }
        self.beta = beta
        self.approval_threshold = approval_threshold
        self.verify_threshold = verify_threshold
        self.uncertainty_threshold = uncertainty_threshold

    def _mode_adjustments(self, task: TaskInput) -> Dict[str, float]:
        if task.mode == Mode.FAST:
            return {"performance": 0.06, "maintainability": -0.02, "security": -0.02}
        if task.mode == Mode.SECURE:
            return {"security": 0.08, "correctness": 0.03, "performance": -0.03}
        if task.mode == Mode.CRITICAL:
            return {"security": 0.10, "correctness": 0.05, "robustness": 0.05, "performance": -0.05}
        if task.mode == Mode.ROBUST:
            return {"robustness": 0.08, "correctness": 0.03}
        return {}

    def _baseline_scores(self, task: TaskInput, candidate: Candidate) -> Tuple[float, float, float, float, float, float, float, float, float, float]:
        text = (candidate.diff.lower() + " " + candidate.explanation.lower())
        prompt = task.prompt.lower()

        correctness = 0.55
        security = 0.55
        robustness = 0.50
        performance = 0.70
        maintainability = 0.70
        alignment = 0.60
        catastrophic_risk = 0.20
        regression_risk = 0.22
        uncertainty = 0.28
        confidence = 0.72

        # SQL-specific
        if "sql_injection_fix" in str(candidate.metadata.get("intent", "")) or "sql" in prompt:
            if " + " in text or "\" + " in text or "' + " in text:
                correctness -= 0.02
                security -= 0.28
                catastrophic_risk += 0.12
                regression_risk += 0.02
                uncertainty += 0.06
            if "execute(" in text and "%s" in text:
                correctness += 0.14
                security += 0.25
                robustness += 0.08
                alignment += 0.10
                catastrophic_risk -= 0.10
                regression_risk -= 0.06
                uncertainty -= 0.06
            if "validate_email" in text:
                correctness += 0.03
                security += 0.05
                robustness += 0.06
                uncertainty -= 0.02
            if "objects.filter" in text or ".filter(" in text:
                maintainability += 0.08
                security += 0.10
                correctness += 0.04
                regression_risk += 0.02

        # Secrets
        if "secret_fix" in str(candidate.metadata.get("intent", "")) or "secret" in prompt:
            if "os.environ.get" in text or "os.getenv" in text:
                correctness += 0.18
                security += 0.22
                alignment += 0.08
                catastrophic_risk -= 0.08
                regression_risk -= 0.06
            if "raise valueerror" in text or "raise runtimeerror" in text:
                correctness += 0.08
                security += 0.05
                robustness += 0.10
                uncertainty -= 0.04
            if "hardcoded_secret_key" in text:
                security -= 0.35
                catastrophic_risk += 0.20

        # Auth
        if "auth" in str(candidate.metadata.get("intent", "")) or any(k in prompt for k in ("auth", "authorization", "permission", "rbac")):
            if "login_required" in text or "policy.can_perform" in text:
                correctness += 0.12
                security += 0.18
                robustness += 0.08
                catastrophic_risk -= 0.08
            else:
                security -= 0.12
                catastrophic_risk += 0.08

        # Generic heuristics
        if "minimal" in candidate.strategy.lower():
            maintainability += 0.04
            confidence -= 0.02
        if "balanced" in candidate.strategy.lower():
            correctness += 0.03
            security += 0.03
            robustness += 0.04
        if "secure" in candidate.strategy.lower() or "defense" in candidate.strategy.lower():
            security += 0.06
            robustness += 0.05
            catastrophic_risk -= 0.04

        if task.mode in {Mode.SECURE, Mode.CRITICAL}:
            security += 0.04
            catastrophic_risk -= 0.02
        if task.mode == Mode.FAST:
            performance += 0.03
            uncertainty += 0.03

        if ("secret" in prompt or "auth" in prompt or "token" in prompt) and "os.environ.get" not in text and "login_required" not in text:
            security -= 0.05
            robustness -= 0.05
            uncertainty += 0.02

        correctness = _clip01(correctness)
        security = _clip01(security)
        robustness = _clip01(robustness)
        performance = _clip01(performance)
        maintainability = _clip01(maintainability)
        alignment = _clip01(alignment)
        catastrophic_risk = _clip01(catastrophic_risk)
        regression_risk = _clip01(regression_risk)
        uncertainty = _clip01(uncertainty)
        confidence = _clip01(max(confidence, 1.0 - uncertainty * 0.8))

        return (
            correctness,
            security,
            robustness,
            performance,
            maintainability,
            alignment,
            catastrophic_risk,
            regression_risk,
            uncertainty,
            confidence,
        )

    async def evaluate(
        self,
        task: TaskInput,
        intent: IntentHypothesis,
        evidence: RetrievedEvidence,
        candidate: Candidate,
    ) -> CandidateScore:
        (
            correctness,
            security,
            robustness,
            performance,
            maintainability,
            alignment,
            catastrophic_risk,
            regression_risk,
            uncertainty,
            confidence,
        ) = self._baseline_scores(task, candidate)

        adjustments = self._mode_adjustments(task)
        performance = _clip01(performance + adjustments.get("performance", 0.0))
        maintainability = _clip01(maintainability + adjustments.get("maintainability", 0.0))
        security = _clip01(security + adjustments.get("security", 0.0))
        correctness = _clip01(correctness + adjustments.get("correctness", 0.0))
        robustness = _clip01(robustness + adjustments.get("robustness", 0.0))

        rationale: List[str] = []
        risk_tags: List[str] = []
        text = candidate.diff.lower()

        intent_label = str(candidate.metadata.get("intent", intent.label))
        if intent_label == "sql_injection_fix":
            if "%s" in text:
                rationale.append("uses parameterized SQL")
                security = _clip01(security + 0.08)
                robustness = _clip01(robustness + 0.04)
                catastrophic_risk = _clip01(catastrophic_risk - 0.05)
                regression_risk = _clip01(regression_risk - 0.03)
            if "validate_email" in text:
                rationale.append("validates input before query")
                security = _clip01(security + 0.03)
                uncertainty = _clip01(uncertainty - 0.02)
            if " + " in text and "execute(" in text:
                rationale.append("unsafe string concatenation detected")
                security = _clip01(security - 0.30)
                catastrophic_risk = _clip01(catastrophic_risk + 0.15)
                uncertainty = _clip01(uncertainty + 0.05)
                risk_tags.append("sqli")

        if intent_label == "secret_fix":
            risk_tags.append("secret")
            rationale.append("security-sensitive secret handling")
            if "os.environ.get" in text:
                rationale.append("reads secret from environment")
            if "raise valueerror" in text or "raise runtimeerror" in text:
                rationale.append("fails fast on missing secret")
            if "hardcoded_secret_key" in text:
                security = _clip01(security - 0.35)
                catastrophic_risk = _clip01(catastrophic_risk + 0.20)

        if intent_label == "auth_fix":
            risk_tags.append("auth")
            if "login_required" in text or "policy.can_perform" in text:
                rationale.append("auth guard present")
                security = _clip01(security + 0.10)
                catastrophic_risk = _clip01(catastrophic_risk - 0.06)
            else:
                rationale.append("missing auth guard")
                security = _clip01(security - 0.12)
                catastrophic_risk = _clip01(catastrophic_risk + 0.08)

        if security >= 0.85:
            rationale.append("strong security posture")
        if robustness >= 0.75:
            rationale.append("robust runtime behavior")
        if correctness >= 0.80:
            rationale.append("high semantic correctness")

        weights = self.weights
        utility = (
            weights["correctness"] * correctness
            + weights["security"] * security
            + weights["robustness"] * robustness
            + weights["performance"] * performance
            + weights["maintainability"] * maintainability
            + weights["alignment"] * alignment
        )

        utility = utility - self.beta * (0.65 * catastrophic_risk + 0.35 * regression_risk)
        confidence = _clip01(0.55 * confidence + 0.45 * (1.0 - uncertainty))

        return CandidateScore(
            correctness=round(correctness, 4),
            correctness_uncertainty=round(min(0.25, 0.08 + uncertainty * 0.18), 4),
            security=round(security, 4),
            security_uncertainty=round(min(0.20, 0.05 + uncertainty * 0.12), 4),
            robustness=round(robustness, 4),
            performance=round(performance, 4),
            maintainability=round(maintainability, 4),
            alignment=round(alignment, 4),
            catastrophic_risk=round(catastrophic_risk, 4),
            regression_risk=round(regression_risk, 4),
            uncertainty=round(uncertainty, 4),
            utility=round(_clip01(utility), 4),
            confidence=round(confidence, 4),
            risk_tags=risk_tags,
            rationale=rationale,
        )


class DefaultRepairerEngine:
    async def repair(
        self,
        task: TaskInput,
        intent: IntentHypothesis,
        evidence: RetrievedEvidence,
        candidate: Candidate,
        score: CandidateScore,
    ) -> Candidate:
        # Uses your real repair.py if available.
        result = repair_candidate(
            prompt=task.prompt,
            candidate=_candidate_to_dict(candidate) | {
                "utility": score.utility,
                "security": score.security,
                "correctness": score.correctness,
                "uncertainty": score.uncertainty,
            },
            evaluation={
                "intent": intent.label,
                "utility": score.utility,
                "security": score.security,
                "correctness": score.correctness,
                "uncertainty": score.uncertainty,
                "risk_summary": {
                    "catastrophic": score.catastrophic_risk,
                    "regression": score.regression_risk,
                    "uncertainty": score.uncertainty,
                },
            },
            max_iters=1,
        )
        repaired = result.candidate
        return _dict_to_candidate(repaired, fallback_id=f"{candidate.id}-r1")


class DefaultVerifierEngine:
    async def verify(
        self,
        task: TaskInput,
        intent: IntentHypothesis,
        evidence: RetrievedEvidence,
        candidate: Candidate,
    ) -> VerificationResult:
        # Uses your real verify.py if available.
        try:
            from .verify import verify_candidate as runtime_verify
        except Exception:  # pragma: no cover
            from verify import verify_candidate as runtime_verify  # type: ignore

        raw = runtime_verify(
            {
                "prompt": task.prompt,
                "mode": task.mode.value,
                "properties": [],
            },
            {
                "id": candidate.id,
                "diff": candidate.diff,
                "strategy": candidate.strategy,
                "explanation": candidate.explanation,
                "metadata": candidate.metadata,
                "properties": [],
            },
        )

        if isinstance(raw, dict):
            return VerificationResult(
                verified=bool(raw.get("verified", False)),
                confidence=_safe_float(raw.get("confidence", 0.0), 0.0),
                violations=list(raw.get("violations", []) or []),
                notes=list(raw.get("notes", []) or []),
            )

        return VerificationResult(
            verified=False,
            confidence=0.0,
            violations=[{"message": "invalid verifier response"}],
            notes=[],
        )


class InMemoryMemoryEngine:
    def __init__(self) -> None:
        self._store: Dict[str, Any] = {}

    async def read(self, task: TaskInput) -> Dict[str, Any]:
        return self._store.get(_memory_key(task), {})

    async def write(self, task: TaskInput, result: PipelineResult) -> None:
        self._store[_memory_key(task)] = {
            "last_run_id": result.run_id,
            "last_decision": result.decision.value,
            "last_candidate": asdict(result.final_candidate) if result.final_candidate else None,
            "last_evaluation": {
                "decision": result.evaluation.decision.value,
                "chosen_candidate": result.evaluation.chosen_candidate,
                "risk_summary": result.evaluation.risk_summary,
            },
            "updated_at": time.time(),
        }


class DefaultGraphEngine:
    async def inspect(self, task: TaskInput) -> Dict[str, Any]:
        files_blob = json.dumps(task.files or [])
        return {
            "files": [f.get("path") for f in task.files if isinstance(f, dict) and f.get("path")],
            "risk_nodes": ["auth"] if "secret" in task.prompt.lower() else [],
            "critical_paths": ["settings"] if "settings.py" in files_blob else [],
        }


class DefaultApplierEngine:
    async def apply(self, task: TaskInput, candidate: Candidate) -> Dict[str, Any]:
        return {
            "applied": False,
            "message": "No applier configured. Returning candidate only.",
            "candidate_id": candidate.id,
        }


# ============================================================
# Pipeline
# ============================================================

class DevMindPipeline:
    def __init__(
        self,
        intent_engine: Optional[IntentEngine] = None,
        retriever_engine: Optional[RetrieverEngine] = None,
        generator_engine: Optional[GeneratorEngine] = None,
        evaluator_engine: Optional[EvaluatorEngine] = None,
        repairer_engine: Optional[RepairerEngine] = None,
        verifier_engine: Optional[VerifierEngine] = None,
        memory_engine: Optional[MemoryEngine] = None,
        graph_engine: Optional[GraphEngine] = None,
        applier_engine: Optional[ApplierEngine] = None,
        *,
        max_candidates: int = 3,
        max_repair_iters: int = 3,
        approval_threshold: float = 0.72,
        verification_threshold: float = 0.60,
        uncertainty_threshold: float = 0.35,
        apply_on_approve: bool = False,
    ) -> None:
        self.intent_engine = intent_engine or DefaultIntentEngine()
        self.retriever_engine = retriever_engine or DefaultRetrieverEngine()
        self.generator_engine = generator_engine or DefaultGeneratorEngine()
        self.evaluator_engine = evaluator_engine or DefaultEvaluatorEngine(
            approval_threshold=approval_threshold,
            verify_threshold=verification_threshold,
            uncertainty_threshold=uncertainty_threshold,
        )
        self.repairer_engine = repairer_engine or DefaultRepairerEngine()
        self.verifier_engine = verifier_engine or DefaultVerifierEngine()
        self.memory_engine = memory_engine or InMemoryMemoryEngine()
        self.graph_engine = graph_engine or DefaultGraphEngine()
        self.applier_engine = applier_engine or DefaultApplierEngine()
        self.policy_engine = PolicyEngine()

        self.max_candidates = max_candidates
        self.max_repair_iters = max_repair_iters
        self.approval_threshold = approval_threshold
        self.verification_threshold = verification_threshold
        self.uncertainty_threshold = uncertainty_threshold
        self.apply_on_approve = apply_on_approve

    async def run(self, task: TaskInput) -> PipelineResult:
        started = time.perf_counter()
        run_id = str(uuid.uuid4())
        task = self._normalize_task(task)

        memory_snapshot = await self.memory_engine.read(task)
        graph_snapshot = await self.graph_engine.inspect(task)
        task.context.setdefault("memory", memory_snapshot)
        task.context.setdefault("graph", graph_snapshot)

        intent = await self.intent_engine.infer(task)

        evidence = await self.retriever_engine.retrieve(task, intent)
        evidence.memory = memory_snapshot
        evidence.graph = graph_snapshot

        candidates = await self.generator_engine.generate(
            task=task,
            intent=intent,
            evidence=evidence,
            strategy=task.mode.value,
            max_candidates=self.max_candidates,
        )
        if not candidates:
            candidates = [
                Candidate(
                    id="fallback-1",
                    diff="# no candidate generated\n",
                    strategy="fallback",
                    explanation="Fallback candidate because generation returned nothing.",
                    metadata={"fallback": True},
                )
            ]

        evaluation = await self._evaluate_candidates(task, intent, evidence, candidates)
        best_candidate = self._pick_best_candidate(candidates, evaluation)

        repair_result: Optional[RepairResult] = None
        if evaluation.requires_repair or evaluation.decision in {Decision.REVISE, Decision.REJECT, Decision.NEEDS_REPAIR}:
            repair_result = await self._repair_loop(task, intent, evidence, best_candidate, evaluation)
            best_candidate = repair_result.candidate
            candidates = [best_candidate] + [c for c in candidates if c.id != best_candidate.id]
            evaluation = await self._evaluate_candidates(task, intent, evidence, candidates)
            best_candidate = self._pick_best_candidate(candidates, evaluation)

        verification: Optional[VerificationResult] = None
        needs_verify = evaluation.requires_verification or evaluation.risk_summary.get("catastrophic", 0.0) >= 0.05
        if needs_verify:
            verification = await self.verifier_engine.verify(task, intent, evidence, best_candidate)
            if not verification.verified:
                repair_result = await self._repair_loop(task, intent, evidence, best_candidate, evaluation)
                best_candidate = repair_result.candidate
                candidates = [best_candidate] + [c for c in candidates if c.id != best_candidate.id]
                evaluation = await self._evaluate_candidates(task, intent, evidence, candidates)
                best_candidate = self._pick_best_candidate(candidates, evaluation)
                verification = await self.verifier_engine.verify(task, intent, evidence, best_candidate)

        final_decision = self._final_decision(evaluation, verification, repair_result)

        applied = False
        if final_decision == Decision.APPROVE and self.apply_on_approve:
            apply_result = await self.applier_engine.apply(task, best_candidate)
            applied = bool(apply_result.get("applied", False))

        result = PipelineResult(
            run_id=run_id,
            prompt=task.prompt,
            mode=task.mode.value,
            intent=intent,
            evidence=evidence,
            candidates=candidates,
            evaluation=evaluation,
            verification=verification,
            repair=repair_result,
            final_candidate=best_candidate,
            applied=applied,
            decision=final_decision,
            summary=self._build_summary(task, intent, evaluation, verification, repair_result, best_candidate),
            duration_ms=round((time.perf_counter() - started) * 1000.0, 2),
        )

        await self.memory_engine.write(task, result)

        if record_analysis_result is not None:
            try:
                record_analysis_result(
                    task.repo or task.context.get("repo", "unknown"),
                    pr_number=int(task.metadata.get("pr_number", -1) or -1),
                    trace_id=run_id,
                    risk=float(evaluation.risk_summary.get("catastrophic", 0.0)),
                    decision=final_decision.value,
                    label=intent.label,
                    explanation=evaluation.best_rationale[0] if evaluation.best_rationale else "",
                    metadata={
                        "mode": task.mode.value,
                        "repair_converged": repair_result.converged if repair_result else False,
                        "repair_iterations": repair_result.iterations if repair_result else 0,
                    },
                )
            except Exception:
                pass

        if record_outcome is not None:
            try:
                record_outcome(
                    task.repo or task.context.get("repo", "unknown"),
                    pr_number=int(task.metadata.get("pr_number", -1) or -1),
                    outcome=final_decision.value,
                    text=evaluation.best_rationale[0] if evaluation.best_rationale else "",
                    metadata={"trace_id": run_id},
                )
            except Exception:
                pass

        if record_strategy_result is not None and best_candidate:
            try:
                score = evaluation.scores.get(best_candidate.id)
                if score:
                    record_strategy_result(
                        task.repo or task.context.get("repo", "unknown"),
                        pr_number=int(task.metadata.get("pr_number", -1) or -1),
                        strategy=best_candidate.strategy,
                        intent=intent.label,
                        utility=score.utility,
                        security=score.security,
                        verified=bool(verification.verified if verification else False),
                        decision=final_decision.value,
                        metadata={"trace_id": run_id},
                    )
            except Exception:
                pass

        return result

    async def analyze_pr(self, task: TaskInput) -> PipelineResult:
        return await self.run(task)

    async def generate_only(self, task: TaskInput, max_candidates: Optional[int] = None) -> List[Candidate]:
        task = self._normalize_task(task)
        memory_snapshot = await self.memory_engine.read(task)
        graph_snapshot = await self.graph_engine.inspect(task)
        task.context.setdefault("memory", memory_snapshot)
        task.context.setdefault("graph", graph_snapshot)
        intent = await self.intent_engine.infer(task)
        evidence = await self.retriever_engine.retrieve(task, intent)
        evidence.memory = memory_snapshot
        evidence.graph = graph_snapshot
        return await self.generator_engine.generate(
            task=task,
            intent=intent,
            evidence=evidence,
            strategy=task.mode.value,
            max_candidates=max_candidates or self.max_candidates,
        )

    async def evaluate_only(self, task: TaskInput, candidates: List[Candidate]) -> EvaluationResult:
        task = self._normalize_task(task)
        memory_snapshot = await self.memory_engine.read(task)
        graph_snapshot = await self.graph_engine.inspect(task)
        task.context.setdefault("memory", memory_snapshot)
        task.context.setdefault("graph", graph_snapshot)
        intent = await self.intent_engine.infer(task)
        evidence = await self.retriever_engine.retrieve(task, intent)
        evidence.memory = memory_snapshot
        evidence.graph = graph_snapshot
        return await self._evaluate_candidates(task, intent, evidence, candidates)

    async def repair_only(self, task: TaskInput, candidate: Candidate, score: Optional[CandidateScore] = None) -> RepairResult:
        task = self._normalize_task(task)
        memory_snapshot = await self.memory_engine.read(task)
        graph_snapshot = await self.graph_engine.inspect(task)
        task.context.setdefault("memory", memory_snapshot)
        task.context.setdefault("graph", graph_snapshot)
        intent = await self.intent_engine.infer(task)
        evidence = await self.retriever_engine.retrieve(task, intent)
        evidence.memory = memory_snapshot
        evidence.graph = graph_snapshot
        if score is None:
            score = await self.evaluator_engine.evaluate(task, intent, evidence, candidate)
        return await self._repair_loop(task, intent, evidence, candidate, self._wrap_single_score(candidate, score))

    async def verify_only(self, task: TaskInput, candidate: Candidate) -> VerificationResult:
        task = self._normalize_task(task)
        memory_snapshot = await self.memory_engine.read(task)
        graph_snapshot = await self.graph_engine.inspect(task)
        task.context.setdefault("memory", memory_snapshot)
        task.context.setdefault("graph", graph_snapshot)
        intent = await self.intent_engine.infer(task)
        evidence = await self.retriever_engine.retrieve(task, intent)
        evidence.memory = memory_snapshot
        evidence.graph = graph_snapshot
        return await self.verifier_engine.verify(task, intent, evidence, candidate)

    def _normalize_task(self, task: TaskInput) -> TaskInput:
        if isinstance(task.mode, str):
            try:
                task.mode = Mode(task.mode.lower())
            except Exception:
                task.mode = Mode.BALANCED
        if task.context is None:
            task.context = {}
        if task.history is None:
            task.history = []
        if task.files is None:
            task.files = []
        if task.metadata is None:
            task.metadata = {}
        return task

    async def _evaluate_candidates(
        self,
        task: TaskInput,
        intent: IntentHypothesis,
        evidence: RetrievedEvidence,
        candidates: List[Candidate],
    ) -> EvaluationResult:
        scored: Dict[str, CandidateScore] = {}

        async def _eval(c: Candidate) -> Tuple[str, CandidateScore]:
            score = await self.evaluator_engine.evaluate(task, intent, evidence, c)
            return c.id, score

        results = await asyncio.gather(*[_eval(c) for c in candidates])
        for cid, score in results:
            scored[cid] = score

        best_candidate_id, best_score = self._select_best(scored)
        if best_candidate_id is None or best_score is None:
            return EvaluationResult(
                decision=Decision.ABSTAIN,
                chosen_candidate=None,
                scores=scored,
                risk_summary={"catastrophic": 1.0, "regression": 1.0, "uncertainty": 1.0},
                best_rationale=["no valid candidate"],
                requires_verification=False,
                requires_repair=True,
                threshold_hit=True,
            )

        requires_verification = (
            best_score.security < 0.90
            or best_score.catastrophic_risk >= 0.05
            or best_score.uncertainty >= self.uncertainty_threshold
            or best_score.utility < self.approval_threshold
        )
        requires_repair = (
            best_score.utility < self.approval_threshold
            or best_score.correctness < 0.80
            or best_score.security < 0.82
            or best_score.regression_risk > 0.20
        )
        decision = self._decision_from_score(best_score, requires_verification, requires_repair)

        return EvaluationResult(
            decision=decision,
            chosen_candidate=best_candidate_id,
            scores=scored,
            risk_summary={
                "catastrophic": round(best_score.catastrophic_risk, 4),
                "regression": round(best_score.regression_risk, 4),
                "uncertainty": round(best_score.uncertainty, 4),
            },
            best_rationale=list(best_score.rationale),
            requires_verification=requires_verification,
            requires_repair=requires_repair,
            threshold_hit=(best_score.utility < self.approval_threshold),
        )

    async def _repair_loop(
        self,
        task: TaskInput,
        intent: IntentHypothesis,
        evidence: RetrievedEvidence,
        candidate: Candidate,
        evaluation: EvaluationResult,
    ) -> RepairResult:
        history: List[Dict[str, Any]] = []
        current = candidate
        converged = False
        iterations = 0

        for i in range(self.max_repair_iters):
            iterations = i + 1
            score = evaluation.scores.get(current.id)
            if score is None:
                score = await self.evaluator_engine.evaluate(task, intent, evidence, current)

            history.append({
                "iteration": iterations,
                "candidate_id": current.id,
                "utility": score.utility,
                "correctness": score.correctness,
                "security": score.security,
                "uncertainty": score.uncertainty,
                "decision": evaluation.decision.value,
            })

            if score.utility >= self.approval_threshold and score.security >= 0.85 and score.uncertainty <= self.uncertainty_threshold:
                converged = True
                break

            next_candidate = await self.repairer_engine.repair(task, intent, evidence, current, score)
            if next_candidate.diff == current.diff and next_candidate.strategy == current.strategy:
                current = next_candidate
                break

            current = next_candidate

            new_score = await self.evaluator_engine.evaluate(task, intent, evidence, current)
            if new_score.utility >= self.approval_threshold and new_score.security >= 0.85 and new_score.uncertainty <= self.uncertainty_threshold:
                converged = True
                break

        return RepairResult(candidate=current, iterations=iterations, converged=converged, history=history)

    def _pick_best_candidate(self, candidates: List[Candidate], evaluation: EvaluationResult) -> Candidate:
        if evaluation.chosen_candidate:
            for c in candidates:
                if c.id == evaluation.chosen_candidate:
                    return c
        return candidates[0] if candidates else Candidate(id="fallback", diff="", strategy="", explanation="")

    def _select_best(self, scores: Dict[str, CandidateScore]) -> Tuple[Optional[str], Optional[CandidateScore]]:
        if not scores:
            return None, None
        best_id = max(
            scores.keys(),
            key=lambda cid: (
                scores[cid].utility,
                scores[cid].confidence,
                scores[cid].security,
                scores[cid].correctness,
                -scores[cid].catastrophic_risk,
                -scores[cid].regression_risk,
            ),
        )
        return best_id, scores[best_id]

    def _decision_from_score(
        self,
        score: CandidateScore,
        requires_verification: bool,
        requires_repair: bool,
    ) -> Decision:
        if score.uncertainty >= self.uncertainty_threshold and score.utility < self.approval_threshold:
            return Decision.NEEDS_VERIFICATION if requires_verification else Decision.REVISE

        if requires_repair and score.utility < self.approval_threshold:
            return Decision.REVISE

        if requires_verification:
            return Decision.NEEDS_VERIFICATION

        if score.utility >= self.approval_threshold and score.catastrophic_risk < 0.05:
            return Decision.APPROVE

        return Decision.REVISE

    def _final_decision(
        self,
        evaluation: EvaluationResult,
        verification: Optional[VerificationResult],
        repair_result: Optional[RepairResult],
    ) -> Decision:
        policy_input = {
            "decision": evaluation.decision.value,
            "risk_summary": evaluation.risk_summary,
            "repair_converged": repair_result.converged if repair_result else True,
            "repair_iterations": repair_result.iterations if repair_result else 0,
            "requires_verification": evaluation.requires_verification,
            "requires_repair": evaluation.requires_repair,
            "threshold_hit": evaluation.threshold_hit,
        }

        selected = None
        if evaluation.chosen_candidate and evaluation.chosen_candidate in evaluation.scores:
            score = evaluation.scores[evaluation.chosen_candidate]
            selected = {
                "candidate": evaluation.chosen_candidate,
                "utility": score.utility,
                "security": score.security,
                "uncertainty": score.uncertainty,
                "verified": verification.verified if verification else False,
                "critical_violations": verification.critical_violations if verification else [],
                "violations": verification.violations if verification else [],
            }

        try:
            policy = self.policy_engine.decide(policy_input, selected, mode=Mode(policy_input.get("decision", "balanced")) if False else None)
            if policy.merge_blocker and policy.action.value in {"revise", "needs_verification", "reject"}:
                return Decision(policy.action.value) if policy.action.value in Decision._value2member_map_ else evaluation.decision
        except Exception:
            pass

        if verification is not None:
            if not verification.verified:
                return Decision.REVISE
            if evaluation.decision == Decision.APPROVE and verification.confidence >= 0.80:
                return Decision.APPROVE
            if verification.confidence < 0.65:
                return Decision.NEEDS_REPAIR

        if repair_result is not None and not repair_result.converged:
            if evaluation.decision == Decision.APPROVE:
                return Decision.REVISE
            if evaluation.decision in {Decision.REVISE, Decision.NEEDS_REPAIR}:
                return Decision.NEEDS_REPAIR

        if evaluation.decision == Decision.NEEDS_VERIFICATION:
            return Decision.NEEDS_VERIFICATION
        if evaluation.decision == Decision.APPROVE:
            return Decision.APPROVE
        if evaluation.requires_repair:
            return Decision.REVISE
        return evaluation.decision

    def _build_summary(
        self,
        task: TaskInput,
        intent: IntentHypothesis,
        evaluation: EvaluationResult,
        verification: Optional[VerificationResult],
        repair_result: Optional[RepairResult],
        best_candidate: Candidate,
    ) -> Dict[str, Any]:
        best_score = evaluation.scores.get(best_candidate.id)
        return {
            "intent": intent.label,
            "intent_confidence": intent.confidence,
            "best_candidate": best_candidate.id,
            "utility": best_score.utility if best_score else None,
            "security": best_score.security if best_score else None,
            "correctness": best_score.correctness if best_score else None,
            "risk": evaluation.risk_summary,
            "verification": asdict(verification) if verification else None,
            "repair_converged": repair_result.converged if repair_result else False,
            "repair_iterations": repair_result.iterations if repair_result else 0,
            "mode": task.mode.value,
        }

    def _wrap_single_score(self, candidate: Candidate, score: CandidateScore) -> EvaluationResult:
        return EvaluationResult(
            decision=Decision.REVISE if score.utility < self.approval_threshold else Decision.APPROVE,
            chosen_candidate=candidate.id,
            scores={candidate.id: score},
            risk_summary={
                "catastrophic": score.catastrophic_risk,
                "regression": score.regression_risk,
                "uncertainty": score.uncertainty,
            },
            best_rationale=list(score.rationale),
            requires_verification=score.security < 0.90 or score.catastrophic_risk >= 0.05,
            requires_repair=score.utility < self.approval_threshold,
            threshold_hit=score.utility < self.approval_threshold,
        )


# ============================================================
# Public helpers
# ============================================================

async def run_pipeline_from_json(
    payload: Mapping[str, Any],
    pipeline: Optional[DevMindPipeline] = None,
) -> Dict[str, Any]:
    pipeline = pipeline or DevMindPipeline()
    task = task_from_json(payload)
    result = await pipeline.run(task)
    return result.to_dict()


def run_pipeline_sync(
    payload: Mapping[str, Any],
    pipeline: Optional[DevMindPipeline] = None,
) -> Dict[str, Any]:
    return asyncio.run(run_pipeline_from_json(payload, pipeline=pipeline))


if __name__ == "__main__":
    import sys

    raw = sys.stdin.read().strip()
    if not raw:
        example = {
            "prompt": "fix SQL injection in users/views.py",
            "mode": "critical",
            "context": {
                "repo": "demo-repo",
                "docs": [],
                "tests": [],
                "policy": [{"name": "no-sqli"}],
            },
            "history": [],
            "files": [{"path": "users/views.py", "content": 'cursor.execute("SELECT * FROM users WHERE email = \'" + email + "\'")'}],
        }
        print(json.dumps(run_pipeline_sync(example), indent=2))
    else:
        payload = json.loads(raw)
        print(json.dumps(run_pipeline_sync(payload), indent=2))