# pipeline.py
from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import re
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple

try:
    from verify import verify_sql_semantics
except Exception:  # pragma: no cover - keeps the standalone script usable if imported differently.
    verify_sql_semantics = None


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
    deltas: Dict[str, Dict[str, float]] = field(default_factory=dict)
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
                "deltas": self.evaluation.deltas,
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
# Default engines (lightweight but useful)
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
        if any(x in filename for x in ("terraform", "helm", "docker")):
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
        confidence = min(0.98, max(0.45, 0.58 + (best_score * 0.55) + (margin * 0.18)))

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
            code=code,
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

        # Specialized generation for secret hardcoding fixes
        if "secret_key" in prompt or "hardcoded secret" in prompt or "hardcoded secret_key" in prompt:
            candidates.append(
                Candidate(
                    id="c1",
                    diff='diff --git a/settings.py b/settings.py\n--- a/settings.py\n+++ b/settings.py\n@@ -1,7 +1,7 @@\n # settings.py\n-SECRET_KEY = "hardcoded_secret_key"\n+SECRET_KEY = os.environ.get("SECRET_KEY")\n',
                    strategy="minimal-patch",
                    explanation="Small patch.",
                    metadata={"mode": task.mode.value, "rank": 1},
                )
            )
            candidates.append(
                Candidate(
                    id="c2",
                    diff='diff --git a/settings.py b/settings.py\n--- a/settings.py\n+++ b/settings.py\n@@ -1,7 +1,7 @@\n # settings.py\n+import os\n-SECRET_KEY = "hardcoded_secret_key"\n+SECRET_KEY = os.environ.get("SECRET_KEY")\n+if not SECRET_KEY:\n+    raise ValueError("SECRET_KEY not set")\n',
                    strategy="balanced-fix" if task.mode != Mode.FAST else "minimal-patch",
                    explanation="Robust fix with fail-fast.",
                    metadata={"mode": task.mode.value, "rank": 2},
                )
            )
            if task.mode in {Mode.SECURE, Mode.CRITICAL}:
                candidates.append(
                    Candidate(
                        id="c3",
                        diff='diff --git a/settings.py b/settings.py\n--- a/settings.py\n+++ b/settings.py\n@@ -1,7 +1,10 @@\n # settings.py\n+import os\n+from pathlib import Path\n-SECRET_KEY = "hardcoded_secret_key"\n+SECRET_KEY = os.environ.get("SECRET_KEY")\n+if not SECRET_KEY:\n+    raise RuntimeError("Missing SECRET_KEY")\n',
                        strategy="secure-defense",
                        explanation="Fail-fast with explicit runtime signal.",
                        metadata={"mode": task.mode.value, "rank": 3},
                    )
                )
            return candidates[:max_candidates]

        # Security: SQL injection
        if re.search(r"\b(sql injection|sqli|sql)\b", prompt):
            candidates.append(Candidate(
                id="c1",
                diff='cursor.execute(\n    "SELECT * FROM users WHERE email = \'" + email + "\'"\n)\n',
                strategy="unsafe-raw-sql",
                explanation="Raw SQL con string concatenation - vulnerable a injection.",
                metadata={"mode": task.mode.value, "rank": 1, "intent": "sql_injection_fix", "security_profile": "unsafe"},
            ))
            candidates.append(Candidate(
                id="c2",
                diff='cursor.execute(\n    "SELECT * FROM users WHERE email = %s",\n    [email],\n)\n',
                strategy="parameterized-query",
                explanation="Parameterized query elimina la superficie de SQL injection.",
                metadata={"mode": task.mode.value, "rank": 2, "intent": "sql_injection_fix", "security_profile": "safe-minimal"},
            ))
            candidates.append(Candidate(
                id="c3",
                diff='email = validate_email(email)\ncursor.execute(\n    "SELECT * FROM users WHERE email = %s",\n    [email],\n)\n',
                strategy="validated-parameterized-query",
                explanation="Validacion mas parameterizacion para mayor seguridad.",
                metadata={"mode": task.mode.value, "rank": 3, "intent": "sql_injection_fix", "security_profile": "hardened"},
            ))
            candidates.append(Candidate(
                id="c4",
                diff='user = User.objects.filter(\n    email=email\n).first()\n',
                strategy="orm-safe-query",
                explanation="Migra a ORM para eliminar SQL raw.",
                metadata={"mode": task.mode.value, "rank": 4, "intent": "sql_injection_fix", "security_profile": "architectural"},
            ))
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

    def _baseline_scores(self, task: TaskInput, candidate: Candidate) -> Tuple[float, float, float, float, float, float, float, float, float]:
        text = candidate.diff.lower() + " " + candidate.explanation.lower()
        prompt = task.prompt.lower()

        hardcoded_secret_fix = ("secret_key" in prompt or "secret" in prompt) and "os.environ.get" in text
        fail_fast = "raise valueerror" in text or "raise runtimeerror" in text
        imports_os = "import os" in text
        minimal = "minimal" in candidate.strategy.lower()
        secure = "secure" in candidate.strategy.lower()
        balanced = "balanced" in candidate.strategy.lower()
        robust = "robust" in candidate.strategy.lower() or "defense" in candidate.strategy.lower()

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

        if hardcoded_secret_fix:
            correctness += 0.18
            security += 0.22
            alignment += 0.08
            catastrophic_risk -= 0.08
            regression_risk -= 0.06

        if fail_fast:
            correctness += 0.10
            security += 0.05
            robustness += 0.18
            catastrophic_risk -= 0.03
            uncertainty -= 0.04

        if imports_os:
            maintainability += 0.02
            correctness += 0.02

        if minimal:
            maintainability += 0.04
            performance += 0.01
            confidence -= 0.02

        if balanced:
            correctness += 0.03
            security += 0.03
            robustness += 0.04

        if secure:
            security += 0.06
            robustness += 0.05
            catastrophic_risk -= 0.04

        if robust:
            correctness += 0.05
            security += 0.05
            robustness += 0.08
            uncertainty -= 0.03

        if task.mode in {Mode.SECURE, Mode.CRITICAL}:
            security += 0.04
            catastrophic_risk -= 0.02

        if task.mode == Mode.FAST:
            performance += 0.03
            uncertainty += 0.03

        # Contextual penalty: if prompt is security-related but candidate doesn't validate env var
        if ("secret" in prompt or "auth" in prompt or "token" in prompt) and not fail_fast:
            security -= 0.05
            robustness -= 0.05
            uncertainty += 0.02

        # Clip
        correctness = _clip01(correctness)
        security = _clip01(security)
        robustness = _clip01(robustness)
        performance = _clip01(performance)
        maintainability = _clip01(maintainability)
        alignment = _clip01(alignment)
        catastrophic_risk = _clip01(catastrophic_risk)
        regression_risk = _clip01(regression_risk)
        uncertainty = _clip01(uncertainty)
        confidence = _clip01(confidence)

        # Uncertainty and confidence relation
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

        # Rationale & risk tags
        rationale: List[str] = []
        risk_tags: List[str] = []

        text = candidate.diff.lower()
        if "secret_key" in task.prompt.lower():
            risk_tags.append("auth")
            rationale.append("security-sensitive key handling")
        if "raise valueerror" in text or "raise runtimeerror" in text:
            rationale.append("fail-fast behavior present")
        if "os.environ.get" in text:
            rationale.append("reads from environment")
        if "hardcoded_secret_key" not in text:
            rationale.append("no hardcoded secret")

        if security >= 0.85:
            rationale.append("strong security posture")
        if robustness >= 0.75:
            rationale.append("robust runtime behavior")

        # Utility function
        weights = self.weights
        utility = (
            weights["correctness"] * correctness +
            weights["security"] * security +
            weights["robustness"] * robustness +
            weights["performance"] * performance +
            weights["maintainability"] * maintainability +
            weights["alignment"] * alignment
        )

        # Risk penalty
        utility = utility - self.beta * (0.65 * catastrophic_risk + 0.35 * regression_risk)

        # Confidence formula
        confidence = _clip01(
            0.55 * confidence + 0.45 * (1.0 - uncertainty)
        )

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
        text = candidate.diff
        prompt = task.prompt.lower()

        # Specialized repair for secret key handling
        if "secret_key" in prompt or "secret" in prompt:
            text = re.sub(
                r"(?im)^\+\s*SECRET_KEY\s*=\s*['\"][^'\"]+['\"]",
                '+SECRET_KEY = os.environ.get("SECRET_KEY")',
                text,
            )
            if "import os" not in text:
                text = text.replace("+SECRET_KEY", "+import os\n+SECRET_KEY")
            if "raise valueerror" not in text.lower() and "raise runtimeerror" not in text.lower():
                text += '\n+if not SECRET_KEY:\n+    raise ValueError("SECRET_KEY not set")\n'
            return Candidate(
                id=f"{candidate.id}-r1",
                diff=text,
                strategy=f"{candidate.strategy}-repaired",
                explanation=f"{candidate.explanation} | repaired for stronger fail-fast security.",
                metadata={**candidate.metadata, "repaired": True, "repaired_from": candidate.id},
            )

        # Generic fallback repair
        text += "\n# repaired"
        return Candidate(
            id=f"{candidate.id}-r1",
            diff=text,
            strategy=f"{candidate.strategy}-repaired",
            explanation=f"{candidate.explanation} | generic repair applied.",
            metadata={**candidate.metadata, "repaired": True, "repaired_from": candidate.id},
        )


class DefaultVerifierEngine:
    async def verify(
        self,
        task: TaskInput,
        intent: IntentHypothesis,
        evidence: RetrievedEvidence,
        candidate: Candidate,
    ) -> VerificationResult:
        text = candidate.diff.lower()
        prompt = task.prompt.lower()
        violations: List[Dict[str, Any]] = []
        notes: List[str] = []

        if "secret_key" in prompt or "secret" in prompt:
            if "hardcoded_secret_key" in text or re.search(r"secret_key\s*=\s*['\"]", text):
                violations.append({
                    "property": "no_hardcoded_secret",
                    "severity": "high",
                    "message": "Hardcoded secret remains in candidate.",
                })
            if "os.environ.get" not in text:
                violations.append({
                    "property": "env_secret_source",
                    "severity": "high",
                    "message": "Candidate does not source SECRET_KEY from environment.",
                })
            if "raise valueerror" not in text and "raise runtimeerror" not in text:
                notes.append("no explicit fail-fast; acceptable only if policy allows soft missing-secret handling")
                # In secure/critical mode, treat as violation
                if task.mode in {Mode.SECURE, Mode.CRITICAL, Mode.ROBUST}:
                    violations.append({
                        "property": "fail_fast_missing_secret",
                        "severity": "medium",
                        "message": "Missing SECRET_KEY should fail fast in secure/robust modes.",
                    })

        if "auth" in prompt or "secret" in prompt:
            notes.append("auth-related verification path")

        if verify_sql_semantics is not None and (
            "sql" in prompt
            or "injection" in prompt
            or "execute(" in text
            or ".raw(" in text
            or "rawsql(" in text
        ):
            sql_result = verify_sql_semantics(candidate.diff)
            for check in sql_result.get("checks", []):
                if check.get("passed"):
                    continue
                severity = "critical" if check.get("name") in sql_result.get("critical_violations", []) else "medium"
                violations.append({
                    "property": check.get("name", "sql_semantic_verification"),
                    "severity": severity,
                    "message": str(check.get("evidence", "SQL semantic verifier failed.")),
                })
            notes.append("sql semantic verifier executed")

        verified = len(violations) == 0
        confidence = 0.95 if verified else 0.63
        if task.mode in {Mode.CRITICAL, Mode.SECURE} and not verified:
            confidence = 0.51

        return VerificationResult(
            verified=verified,
            confidence=round(confidence, 4),
            violations=violations,
            notes=notes,
        )


class InMemoryMemoryEngine:
    def __init__(self) -> None:
        self._store: Dict[str, Any] = {}

    async def read(self, task: TaskInput) -> Dict[str, Any]:
        key = _memory_key(task)
        return self._store.get(key, {})

    async def write(self, task: TaskInput, result: PipelineResult) -> None:
        key = _memory_key(task)
        self._store[key] = {
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
        # Lightweight graph summary (override with your actual graph engine)
        return {
            "files": [f.get("path") for f in task.files if isinstance(f, dict) and f.get("path")],
            "risk_nodes": ["auth"] if "secret" in task.prompt.lower() else [],
            "critical_paths": ["settings"] if "settings.py" in json.dumps(task.files) else [],
        }


class DefaultApplierEngine:
    async def apply(self, task: TaskInput, candidate: Candidate) -> Dict[str, Any]:
        # Safe default: do not modify files; return the patch to the caller.
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

        self.max_candidates = max_candidates
        self.max_repair_iters = max_repair_iters
        self.approval_threshold = approval_threshold
        self.verification_threshold = verification_threshold
        self.uncertainty_threshold = uncertainty_threshold
        self.apply_on_approve = apply_on_approve

    async def run(self, task: TaskInput) -> PipelineResult:
        started = time.perf_counter()
        run_id = str(uuid.uuid4())

        # Normalize task
        task = self._normalize_task(task)

        # Observe / memory / graph
        memory_snapshot = await self.memory_engine.read(task)
        graph_snapshot = await self.graph_engine.inspect(task)
        task.context.setdefault("memory", memory_snapshot)
        task.context.setdefault("graph", graph_snapshot)

        # Intent
        intent = await self.intent_engine.infer(task)

        # Retrieval
        evidence = await self.retriever_engine.retrieve(task, intent)
        evidence.memory = memory_snapshot
        evidence.graph = graph_snapshot

        # Generation
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

        # Evaluation
        evaluation = await self._evaluate_candidates(task, intent, evidence, candidates)
        best_candidate = self._pick_best_candidate(candidates, evaluation)

        # Repair loop if necessary
        repair_result: Optional[RepairResult] = None
        if evaluation.requires_repair or evaluation.decision in {Decision.REVISE, Decision.REJECT, Decision.NEEDS_REPAIR}:
            repair_result = await self._repair_loop(task, intent, evidence, best_candidate, evaluation)
            best_candidate = repair_result.candidate
            # Re-evaluate after repair
            candidates = [best_candidate] + [c for c in candidates if c.id != best_candidate.id]
            evaluation = await self._evaluate_candidates(task, intent, evidence, candidates)
            best_candidate = self._pick_best_candidate(candidates, evaluation)

        # Verification gate
        verification: Optional[VerificationResult] = None
        needs_verify = evaluation.requires_verification or evaluation.risk_summary.get("catastrophic", 0.0) >= 0.05
        if needs_verify:
            verification = await self.verifier_engine.verify(task, intent, evidence, best_candidate)

            # If verification fails, try one more repair cycle or reject
            if not verification.verified:
                if repair_result is None:
                    repair_result = await self._repair_loop(task, intent, evidence, best_candidate, evaluation)
                else:
                    repair_result = await self._repair_loop(task, intent, evidence, repair_result.candidate, evaluation)
                best_candidate = repair_result.candidate
                candidates = [best_candidate] + [c for c in candidates if c.id != best_candidate.id]
                evaluation = await self._evaluate_candidates(task, intent, evidence, candidates)
                best_candidate = self._pick_best_candidate(candidates, evaluation)
                verification = await self.verifier_engine.verify(task, intent, evidence, best_candidate)

        # Final decision
        final_decision = self._final_decision(evaluation, verification)
        if (
            repair_result is not None
            and verification is not None
            and verification.verified
            and best_candidate.id == repair_result.candidate.id
        ):
            repair_result.converged = True

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
        return result

    async def analyze_pr(self, task: TaskInput) -> PipelineResult:
        return await self.run(task)

    async def evaluate_only(
        self,
        task: TaskInput,
        candidates: List[Candidate],
    ) -> EvaluationResult:
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

    async def generate_only(
        self,
        task: TaskInput,
        max_candidates: Optional[int] = None,
    ) -> List[Candidate]:
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

    async def repair_only(
        self,
        task: TaskInput,
        candidate: Candidate,
        score: Optional[CandidateScore] = None,
    ) -> RepairResult:
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

    # --------------------------------------------------------
    # Internals
    # --------------------------------------------------------

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
        deltas = self._score_deltas(candidates, scored)

        best_candidate_id, best_score = self._select_best(scored)
        if best_candidate_id is None or best_score is None:
            return EvaluationResult(
                decision=Decision.ABSTAIN,
                chosen_candidate=None,
                scores=scored,
                risk_summary={"catastrophic": 1.0, "regression": 1.0, "uncertainty": 1.0},
                deltas=deltas,
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
            deltas=deltas,
            best_rationale=best_score.rationale,
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

            history_entry = {
                "iteration": iterations,
                "candidate_id": current.id,
                "utility": score.utility,
                "correctness": score.correctness,
                "security": score.security,
                "uncertainty": score.uncertainty,
                "decision": evaluation.decision.value,
                "security_delta": 0.0,
                "utility_delta": 0.0,
                "uncertainty_delta": 0.0,
            }
            history.append(history_entry)

            if score.utility >= self.approval_threshold and score.security >= 0.85 and score.uncertainty <= self.uncertainty_threshold:
                converged = True
                break

            next_candidate = await self.repairer_engine.repair(task, intent, evidence, current, score)

            # Stop if no meaningful change
            if next_candidate.diff == current.diff and next_candidate.strategy == current.strategy:
                history_entry["repaired_candidate_id"] = next_candidate.id
                current = next_candidate
                break

            current = next_candidate

            # Re-evaluate internal state after repair
            new_score = await self.evaluator_engine.evaluate(task, intent, evidence, current)
            delta = _score_delta(score, new_score)
            history_entry.update(
                {
                    "repaired_candidate_id": current.id,
                    "post_utility": new_score.utility,
                    "post_security": new_score.security,
                    "post_uncertainty": new_score.uncertainty,
                    **delta,
                }
            )
            temp_eval = self._wrap_single_score(current, new_score)
            if new_score.utility >= self.approval_threshold and new_score.security >= 0.85 and new_score.uncertainty <= self.uncertainty_threshold:
                converged = True
                evaluation = temp_eval
                break

        return RepairResult(candidate=current, iterations=iterations, converged=converged, history=history)

    def _pick_best_candidate(self, candidates: List[Candidate], evaluation: EvaluationResult) -> Candidate:
        by_id = {candidate.id: candidate for candidate in candidates}
        if evaluation.chosen_candidate and evaluation.chosen_candidate in by_id:
            return by_id[evaluation.chosen_candidate]
        if candidates:
            return candidates[0]
        return Candidate(
            id="no-candidate",
            diff="",
            strategy="abstain",
            explanation="No candidate available.",
            metadata={"fallback": True},
        )

    def _select_best(self, scores: Dict[str, CandidateScore]) -> Tuple[Optional[str], Optional[CandidateScore]]:
        if not scores:
            return None, None
        best_id = max(scores.keys(), key=lambda cid: (
            scores[cid].utility,
            scores[cid].confidence,
            scores[cid].security,
            scores[cid].correctness,
            -scores[cid].catastrophic_risk,
            -scores[cid].regression_risk,
        ))
        return best_id, scores[best_id]

    def _score_deltas(
        self,
        candidates: List[Candidate],
        scores: Dict[str, CandidateScore],
    ) -> Dict[str, Dict[str, float]]:
        deltas: Dict[str, Dict[str, float]] = {}
        for candidate in candidates:
            parent_id = str(
                candidate.metadata.get("repaired_from")
                or candidate.metadata.get("previous_candidate_id")
                or candidate.metadata.get("parent_id")
                or ""
            )
            if not parent_id or parent_id not in scores or candidate.id not in scores:
                continue
            deltas[candidate.id] = _score_delta(scores[parent_id], scores[candidate.id])
        return deltas

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
    ) -> Decision:
        if evaluation.chosen_candidate is None:
            return Decision.ABSTAIN

        if verification is not None:
            if not verification.verified:
                return Decision.REVISE
            if evaluation.decision == Decision.APPROVE and verification.confidence >= 0.80:
                return Decision.APPROVE
            if verification.confidence < 0.65:
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
        repair_delta = self._repair_delta_summary(repair_result, evaluation, best_candidate)
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
            "security_delta": repair_delta["security_delta"],
            "utility_delta": repair_delta["utility_delta"],
            "uncertainty_delta": repair_delta["uncertainty_delta"],
            "mode": task.mode.value,
        }

    def _repair_delta_summary(
        self,
        repair_result: Optional[RepairResult],
        evaluation: EvaluationResult,
        best_candidate: Candidate,
    ) -> Dict[str, float]:
        zero = {"security_delta": 0.0, "utility_delta": 0.0, "uncertainty_delta": 0.0}
        if not repair_result or not repair_result.history:
            return zero

        initial = repair_result.history[0]
        final_score = evaluation.scores.get(best_candidate.id)
        if final_score is None:
            return zero

        try:
            return {
                "security_delta": round(final_score.security - float(initial.get("security", final_score.security)), 4),
                "utility_delta": round(final_score.utility - float(initial.get("utility", final_score.utility)), 4),
                "uncertainty_delta": round(float(initial.get("uncertainty", final_score.uncertainty)) - final_score.uncertainty, 4),
            }
        except (TypeError, ValueError):
            return zero

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
            best_rationale=score.rationale,
            requires_verification=score.security < 0.90 or score.catastrophic_risk >= 0.05,
            requires_repair=score.utility < self.approval_threshold,
            threshold_hit=score.utility < self.approval_threshold,
        )


# ============================================================
# Helpers
# ============================================================

def _clip01(x: float) -> float:
    return max(0.0, min(1.0, float(x)))


def _score_delta(previous: CandidateScore, current: CandidateScore) -> Dict[str, float]:
    return {
        "security_delta": round(float(current.security) - float(previous.security), 4),
        "utility_delta": round(float(current.utility) - float(previous.utility), 4),
        "uncertainty_delta": round(float(previous.uncertainty) - float(current.uncertainty), 4),
    }


def _memory_key(task: TaskInput) -> str:
    repo = task.repo or task.context.get("repo") or "default"
    prompt_sig = re.sub(r"\s+", " ", task.prompt.strip().lower())[:96]
    return f"{repo}::{prompt_sig}"


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


# ============================================================
# Example CLI usage (optional)
# ============================================================

if __name__ == "__main__":
    import sys

    raw = sys.stdin.read().strip()
    if not raw:
        example = {
            "prompt": "fix hardcoded SECRET_KEY in settings.py",
            "mode": "secure",
            "context": {
                "repo": "demo-repo",
                "policy": [{"name": "no-hardcoded-secrets"}],
                "docs": [],
                "tests": [],
            },
            "history": [],
            "files": [{"path": "settings.py", "content": 'SECRET_KEY = "hardcoded_secret_key"'}],
        }
        print(json.dumps(run_pipeline_sync(example), indent=2))
    else:
        payload = json.loads(raw)
        print(json.dumps(run_pipeline_sync(payload), indent=2))
