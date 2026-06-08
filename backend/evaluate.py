# evaluate.py
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple
import math
import re

from verify import verify_sql_semantics


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


@dataclass(frozen=True)
class Candidate:
    id: str
    diff: str
    strategy: str = ""
    explanation: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TaskInput:
    prompt: str
    context: Dict[str, Any] = field(default_factory=dict)
    history: List[Dict[str, Any]] = field(default_factory=list)
    files: List[Dict[str, Any]] = field(default_factory=list)
    mode: str = "balanced"
    repo: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class IntentHypothesis:
    label: str
    confidence: float
    alternatives: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class RetrievedEvidence:
    docs: List[Dict[str, Any]] = field(default_factory=list)
    code: List[Dict[str, Any]] = field(default_factory=list)
    tests: List[Dict[str, Any]] = field(default_factory=list)
    history: List[Dict[str, Any]] = field(default_factory=list)
    policy: List[Dict[str, Any]] = field(default_factory=list)
    graph: Dict[str, Any] = field(default_factory=dict)
    memory: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
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


@dataclass(frozen=True)
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


# ============================================================
# Config
# ============================================================

@dataclass(frozen=True)
class EvaluationConfig:
    weights: Dict[str, float] = field(default_factory=lambda: {
        "correctness": 0.30,
        "security": 0.30,
        "robustness": 0.15,
        "performance": 0.08,
        "maintainability": 0.09,
        "alignment": 0.08,
    })
    beta: float = 1.0
    approval_threshold: float = 0.62
    verification_threshold: float = 0.60
    uncertainty_threshold: float = 0.35

    # conservative gating for risky domains
    secure_mode_security_floor: float = 0.85
    critical_mode_security_floor: float = 0.90
    critical_mode_correctness_floor: float = 0.85


# ============================================================
# Evaluator
# ============================================================

class Evaluator:
    """
    Big-tech style evaluator:
    - deterministic scoring heuristics
    - probabilistic utility aggregation
    - uncertainty and confidence calibration hooks
    - risk gating for secure/critical tasks
    """

    def __init__(self, config: Optional[EvaluationConfig] = None) -> None:
        self.config = config or EvaluationConfig()

    # -------------------------
    # Public API
    # -------------------------

    def evaluate(
        self,
        task: TaskInput,
        intent: IntentHypothesis,
        evidence: RetrievedEvidence,
        candidates: Sequence[Candidate],
    ) -> EvaluationResult:
        if not candidates:
            return EvaluationResult(
                decision=Decision.ABSTAIN,
                chosen_candidate=None,
                scores={},
                risk_summary={"catastrophic": 1.0, "regression": 1.0, "uncertainty": 1.0},
                best_rationale=["no candidates provided"],
                requires_verification=False,
                requires_repair=True,
                threshold_hit=True,
            )

        scores: Dict[str, CandidateScore] = {}
        for candidate in candidates:
            scores[candidate.id] = self.evaluate_candidate(task, intent, evidence, candidate)
        deltas = self._score_deltas(task, candidates, scores)

        best_candidate_id, best_score = self._select_best(scores)
        if best_candidate_id is None or best_score is None:
            return EvaluationResult(
                decision=Decision.ABSTAIN,
                chosen_candidate=None,
                scores=scores,
                risk_summary={"catastrophic": 1.0, "regression": 1.0, "uncertainty": 1.0},
                deltas=deltas,
                best_rationale=["no valid best candidate"],
                requires_verification=False,
                requires_repair=True,
                threshold_hit=True,
            )

        requires_verification = self._requires_verification(task, best_score)
        requires_repair = self._requires_repair(task, best_score)

        decision = self._decision_from_score(
            task=task,
            score=best_score,
            requires_verification=requires_verification,
            requires_repair=requires_repair,
        )

        return EvaluationResult(
            decision=decision,
            chosen_candidate=best_candidate_id,
            scores=scores,
            risk_summary={
                "catastrophic": round(best_score.catastrophic_risk, 4),
                "regression": round(best_score.regression_risk, 4),
                "uncertainty": round(best_score.uncertainty, 4),
            },
            deltas=deltas,
            best_rationale=best_score.rationale,
            requires_verification=requires_verification,
            requires_repair=requires_repair,
            threshold_hit=best_score.utility < self.config.approval_threshold,
        )

    def evaluate_candidate(
        self,
        task: TaskInput,
        intent: IntentHypothesis,
        evidence: RetrievedEvidence,
        candidate: Candidate,
    ) -> CandidateScore:
        prompt = (task.prompt or "").lower()
        diff = (candidate.diff or "").lower()
        explanation = (candidate.explanation or "").lower()
        strategy = (candidate.strategy or "").lower()
        mode = (task.mode or "balanced").lower()

        risk_tags: List[str] = []
        rationale: List[str] = []

        # Base prior
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

        # Intent alignment prior
        intent_boost = self._intent_match_boost(intent, prompt, strategy, diff)
        alignment += intent_boost
        confidence += 0.04 if intent.confidence >= 0.70 else -0.03
        rationale.extend(self._intent_rationale(intent))

        # Feature extraction
        all_text = " ".join((prompt, diff, explanation, strategy))
        has_env_read = re.search(r"\b(os\.environ(?:\.get)?|os\.getenv|environ\.get)\b", diff) is not None
        has_fail_fast = self._has_fail_fast(diff)
        has_secret_handling = any(x in all_text for x in ("secret_key", "secret", "token", "api_key", "password"))
        has_auth_context = any(x in all_text for x in ("auth", "authentication", "authorization", "permission", "rbac", "policy", "is_admin"))
        has_sql_context = any(x in all_text for x in ("sql", "query", "cursor.execute", "select ", "injection", "database"))
        minimal = any(x in strategy for x in ("minimal", "small"))
        balanced = any(x in strategy for x in ("balanced",))
        secure = any(x in strategy for x in ("secure", "defense"))
        robust = any(x in strategy for x in ("robust", "defense"))
        performance_hint = any(x in strategy for x in ("perf", "fast"))
        imports_os = re.search(r"\bimport\s+os\b", diff) is not None
        touches_settings = "settings.py" in diff or "settings" in prompt
        hardcoded_secret = self._has_hardcoded_secret(diff)
        unsafe_sql = self._has_unsafe_sql(diff)
        safe_sql = self._has_parameterized_sql(diff)
        removes_auth_check = self._removes_auth_check(diff)
        has_policy_check = self._has_policy_check(diff)

        # Domain-specific scoring
        if has_secret_handling:
            risk_tags.append("secret")
            rationale.append("security-sensitive secret handling")
            security += 0.10
            catastrophic_risk -= 0.05
            regression_risk -= 0.03

            if has_env_read:
                correctness += 0.12
                security += 0.10
                rationale.append("reads secret from environment")
            else:
                security -= 0.12
                correctness -= 0.06

            if has_fail_fast:
                correctness += 0.12
                robustness += 0.18
                security += 0.05
                rationale.append("fails fast on missing secret")
            else:
                rationale.append("no explicit fail-fast path")
                if mode in ("secure", "robust", "critical"):
                    robustness -= 0.08
                    security -= 0.03
                    uncertainty += 0.03

        if has_auth_context:
            risk_tags.append("auth")
            catastrophic_risk += 0.03
            security += 0.05
            rationale.append("auth-related path")

            if removes_auth_check:
                correctness -= 0.30
                security -= 0.35
                robustness -= 0.10
                catastrophic_risk += 0.35
                uncertainty += 0.08
                rationale.append("removes or bypasses authorization check")

            if has_policy_check:
                correctness += 0.25
                security += 0.25
                robustness += 0.10
                catastrophic_risk -= 0.08
                rationale.append("uses explicit authorization policy")

            if has_fail_fast:
                correctness += 0.05
                robustness += 0.07
                rationale.append("fails closed on authorization failure")

        if has_sql_context:
            risk_tags.append("sql")

            if unsafe_sql:
                correctness -= 0.25
                security -= 0.35
                robustness -= 0.08
                catastrophic_risk += 0.30
                uncertainty += 0.08
                rationale.append("raw SQL is built from interpolated input")

            if safe_sql:
                correctness += 0.22
                security += 0.30
                robustness += 0.08
                catastrophic_risk -= 0.10
                uncertainty -= 0.03
                rationale.append("uses parameterized SQL")

        if imports_os:
            maintainability += 0.02
            correctness += 0.02

        if touches_settings:
            risk_tags.append("config")
            regression_risk += 0.02
            rationale.append("configuration path touched")

        if minimal:
            maintainability += 0.04
            performance += 0.01
            confidence -= 0.01
            rationale.append("minimal change")

        if balanced:
            correctness += 0.03
            security += 0.03
            robustness += 0.03
            rationale.append("balanced strategy")

        if secure:
            security += 0.06
            robustness += 0.04
            catastrophic_risk -= 0.03
            rationale.append("security-first strategy")

        if robust:
            correctness += 0.04
            security += 0.04
            robustness += 0.06
            uncertainty -= 0.03
            rationale.append("robust strategy")

        if performance_hint:
            performance += 0.04
            rationale.append("performance-oriented strategy")

        # Candidate explanation signals
        if "no hardcoded secret" in explanation:
            correctness += 0.04
            security += 0.04
            rationale.append("explicitly avoids hardcoded secret")
        if "fail-fast" in explanation:
            correctness += 0.03
            robustness += 0.05
            rationale.append("fail-fast rationale present")
        if "small patch" in explanation:
            maintainability += 0.02
            rationale.append("small patch rationale present")

        # Penalties
        if hardcoded_secret:
            correctness -= 0.25
            security -= 0.30
            catastrophic_risk += 0.22
            risk_tags.append("hardcoded_secret")
            rationale.append("introduces hardcoded secret material")

        if "os.environ.get" not in diff and has_secret_handling:
            security -= 0.08
            correctness -= 0.05
            uncertainty += 0.04

        if "raise valueerror" not in diff and "raise runtimeerror" not in diff and has_secret_handling:
            if mode in ("secure", "robust", "critical"):
                robustness -= 0.07
                uncertainty += 0.03

        # Contextual adjustments based on available evidence
        if evidence.policy:
            security += 0.02
            maintainability += 0.01
        if evidence.tests:
            correctness += 0.02
            regression_risk -= 0.02
        if evidence.graph:
            robustness += 0.01

        # Mode-specific calibration
        if mode == "fast":
            performance += 0.04
            uncertainty += 0.03
        elif mode == "secure":
            security += 0.06
            catastrophic_risk -= 0.03
            correctness += 0.03
        elif mode == "robust":
            robustness += 0.08
            correctness += 0.03
            security += 0.03
        elif mode == "critical":
            security += 0.10
            correctness += 0.05
            robustness += 0.05
            catastrophic_risk -= 0.05
            uncertainty -= 0.02

        # Clip all raw scores
        correctness = _clip01(correctness)
        security = _clip01(security)
        robustness = _clip01(robustness)
        performance = _clip01(performance)
        maintainability = _clip01(maintainability)
        alignment = _clip01(alignment)
        catastrophic_risk = _clip01(catastrophic_risk)
        regression_risk = _clip01(regression_risk)
        uncertainty = _clip01(uncertainty)

        # Confidence is a function of calibration + uncertainty
        confidence = _clip01(0.58 * confidence + 0.42 * (1.0 - uncertainty))

        utility = self._utility(
            correctness=correctness,
            security=security,
            robustness=robustness,
            performance=performance,
            maintainability=maintainability,
            alignment=alignment,
            catastrophic_risk=catastrophic_risk,
            regression_risk=regression_risk,
        )

        # More rationales
        if security >= 0.85:
            rationale.append("strong security posture")
        if correctness >= 0.85:
            rationale.append("high semantic correctness")
        if robustness >= 0.75:
            rationale.append("stable failure handling")

        return CandidateScore(
            correctness=round(correctness, 4),
            correctness_uncertainty=round(self._uncertainty_band(uncertainty, base=0.08), 4),
            security=round(security, 4),
            security_uncertainty=round(self._uncertainty_band(uncertainty, base=0.06), 4),
            robustness=round(robustness, 4),
            performance=round(performance, 4),
            maintainability=round(maintainability, 4),
            alignment=round(alignment, 4),
            catastrophic_risk=round(catastrophic_risk, 4),
            regression_risk=round(regression_risk, 4),
            uncertainty=round(uncertainty, 4),
            utility=round(utility, 4),
            confidence=round(confidence, 4),
            risk_tags=sorted(set(risk_tags)),
            rationale=rationale or ["heuristic evaluation completed"],
        )

    # -------------------------
    # Internals
    # -------------------------

    def _utility(
        self,
        *,
        correctness: float,
        security: float,
        robustness: float,
        performance: float,
        maintainability: float,
        alignment: float,
        catastrophic_risk: float,
        regression_risk: float,
    ) -> float:
        w = self.config.weights
        raw = (
            w["correctness"] * correctness
            + w["security"] * security
            + w["robustness"] * robustness
            + w["performance"] * performance
            + w["maintainability"] * maintainability
            + w["alignment"] * alignment
        )
        risk_penalty = self.config.beta * (0.65 * catastrophic_risk + 0.35 * regression_risk)
        return _clip01(raw - risk_penalty)

    def _intent_match_boost(
        self,
        intent: IntentHypothesis,
        prompt: str,
        strategy: str,
        diff: str,
    ) -> float:
        boost = 0.0
        label = (intent.label or "").lower()

        if "secure" in label and ("secure" in strategy or "valueerror" in diff or "runtimeerror" in diff):
            boost += 0.08
        if "safe_concurrency" in label and any(x in strategy for x in ("robust", "secure")):
            boost += 0.07
        if "performance" in label and "perf" in strategy:
            boost += 0.06
        if "refactor" in label and "maintain" in strategy:
            boost += 0.05
        if "general" in label:
            boost += 0.02
        if "secret" in prompt and ("os.environ.get" in diff or "raise" in diff):
            boost += 0.06

        return min(0.12, boost)

    def _intent_rationale(self, intent: IntentHypothesis) -> List[str]:
        notes = []
        if intent.confidence >= 0.75:
            notes.append(f"intent-confidence-high:{intent.label}")
        else:
            notes.append(f"intent-confidence-moderate:{intent.label}")
        if intent.alternatives:
            notes.append("intent alternatives considered")
        return notes

    def _has_fail_fast(self, diff: str) -> bool:
        d = diff.lower()
        return re.search(r"\braise\s+\w*error\b", d) is not None or ("assert " in d)

    def _has_hardcoded_secret(self, diff: str) -> bool:
        return re.search(
            r"(?im)^\+?\s*(SECRET_KEY|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY)\s*=\s*['\"][^'\"]{8,}['\"]",
            diff,
        ) is not None

    def _has_unsafe_sql(self, diff: str) -> bool:
        semantic = verify_sql_semantics(diff)
        if semantic.get("critical_violations"):
            return True
        if self._has_parameterized_sql(diff):
            return False
        d = diff.lower()
        if re.search(r"execute\s*\([^,\n]*(\+|%|\.format\(|f['\"])", d):
            return True
        if re.search(r"select\s+.*\+\s*\w+", d):
            return True
        return False

    def _has_parameterized_sql(self, diff: str) -> bool:
        d = diff.lower()
        return re.search(r"execute\s*\([^,\n]+,\s*(\[|\(|\{)", d) is not None

    def _removes_auth_check(self, diff: str) -> bool:
        d = diff.lower()
        removes_guard = re.search(r"(?m)^-\s*(if|raise|return).*?(is_admin|permission|authorize|can_|policy|rbac)", d) is not None
        added_sensitive_action = re.search(r"(?m)^\+\s*return\s+\w*(delete|update|transfer|charge|grant|revoke)", d) is not None
        return bool(removes_guard and added_sensitive_action)

    def _has_policy_check(self, diff: str) -> bool:
        d = diff.lower()
        return re.search(r"(?m)^\+\s*if\s+not\s+.*?(policy\.|can_|authorize|has_permission|is_admin)", d) is not None

    def _uncertainty_band(self, uncertainty: float, base: float = 0.08) -> float:
        return min(0.25, base + uncertainty * 0.18)

    def _requires_verification(self, task: TaskInput, score: CandidateScore) -> bool:
        mode = (task.mode or "balanced").lower()
        if score.catastrophic_risk >= 0.25:
            return True
        if score.uncertainty >= self.config.uncertainty_threshold:
            return True
        if score.security < self.config.verification_threshold:
            return True
        if mode in ("secure", "robust", "critical"):
            return True
        return False

    def _requires_repair(self, task: TaskInput, score: CandidateScore) -> bool:
        """Mitnick mindset v2: No bloquear cambios legítimos de seguridad/config."""
        prompt = getattr(task, "prompt", "") or ""
        prompt_lower = prompt.lower()
        
        # Fast-path MUCHO más amplio para cambios de hashing y configuración
        low_risk_patterns = [
            "password_hasher", "password hashers", "scrypt", "argon2", 
            "pbkdf2", "hashing", "hasher", "django", "settings", 
            "security upgrade", "algorithm", "PASSWORD_HASHERS"
        ]
        
        if any(pattern in prompt_lower for pattern in low_risk_patterns):
            pass  # Print eliminado
            # return False  # FIX: Delegar al decision_resolver
            
        # Solo repair en riesgos reales
        if score.catastrophic_risk >= 0.40 or score.security < 0.35:
            return True
        if score.regression_risk > 0.45:
            return True
        if getattr(task, "mode", "") == "critical" and score.security < self.config.critical_mode_security_floor:
            return True
        return False
            
        # Solo repair en riesgos reales
        if score.catastrophic_risk >= 0.40 or score.security < 0.35:
            return True
        if score.regression_risk > 0.45:
            return True
        if task.mode == "critical" and score.security < self.config.critical_mode_security_floor:
            return True
        return False
        return False

    def _decision_from_score(
        self,
        task: TaskInput,
        score: CandidateScore,
        requires_verification: bool,
        requires_repair: bool,
    ) -> Decision:
        mode = (task.mode or "balanced").lower()

        if mode == "critical":
            if score.security < self.config.critical_mode_security_floor:
                return Decision.REVISE
            if score.correctness < self.config.critical_mode_correctness_floor:
                return Decision.REVISE

        if requires_repair and score.utility < self.config.approval_threshold:
            return Decision.REVISE

        if score.uncertainty >= self.config.uncertainty_threshold and score.utility < self.config.approval_threshold:
            return Decision.NEEDS_VERIFICATION if requires_verification else Decision.REVISE

        if requires_verification:
            return Decision.NEEDS_VERIFICATION

        if score.utility >= self.config.approval_threshold and score.catastrophic_risk < 0.05:
            return Decision.APPROVE

        return Decision.REVISE

    def _select_best(self, scores: Dict[str, CandidateScore]) -> Tuple[Optional[str], Optional[CandidateScore]]:
        if not scores:
            return None, None

        def rank(score: CandidateScore) -> Tuple[float, float, float, float, float, float]:
            return (
                score.utility,
                score.confidence,
                score.security,
                score.correctness,
                -score.catastrophic_risk,
                -score.regression_risk,
            )

        best_id = max(scores.keys(), key=lambda cid: rank(scores[cid]))
        return best_id, scores[best_id]

    def _score_deltas(
        self,
        task: TaskInput,
        candidates: Sequence[Candidate],
        scores: Dict[str, CandidateScore],
    ) -> Dict[str, Dict[str, float]]:
        deltas: Dict[str, Dict[str, float]] = {}
        previous_state = self._previous_state(task)

        for candidate in candidates:
            current = scores.get(candidate.id)
            if current is None:
                continue

            previous = None
            parent_id = str(
                candidate.metadata.get("repaired_from")
                or candidate.metadata.get("previous_candidate_id")
                or candidate.metadata.get("parent_id")
                or ""
            )
            if parent_id and parent_id in scores:
                previous = self._score_metrics(scores[parent_id])
            else:
                previous = self._previous_metrics_for(candidate.id, candidate.metadata, previous_state)

            if previous is None:
                continue

            deltas[candidate.id] = self._metric_delta(previous, self._score_metrics(current))

        return deltas

    def _previous_state(self, task: TaskInput) -> Mapping[str, Any]:
        metadata = task.metadata or {}
        context = task.context or {}
        state = metadata.get("previous_state", context.get("previous_state", {}))
        return state if isinstance(state, Mapping) else {}

    def _previous_metrics_for(
        self,
        candidate_id: str,
        metadata: Mapping[str, Any],
        previous_state: Mapping[str, Any],
    ) -> Optional[Dict[str, float]]:
        for source in (
            metadata.get("previous_score"),
            metadata.get("previous_state"),
            previous_state.get(candidate_id),
            (previous_state.get("scores", {}) or {}).get(candidate_id)
            if isinstance(previous_state.get("scores", {}), Mapping)
            else None,
            previous_state,
        ):
            metrics = self._coerce_metrics(source)
            if metrics is not None:
                return metrics
        return None

    def _score_metrics(self, score: CandidateScore) -> Dict[str, float]:
        return {
            "security": float(score.security),
            "utility": float(score.utility),
            "uncertainty": float(score.uncertainty),
        }

    def _coerce_metrics(self, value: Any) -> Optional[Dict[str, float]]:
        if isinstance(value, CandidateScore):
            return self._score_metrics(value)
        if not isinstance(value, Mapping):
            return None
        if not {"security", "utility", "uncertainty"} <= set(value.keys()):
            return None
        try:
            return {
                "security": float(value["security"]),
                "utility": float(value["utility"]),
                "uncertainty": float(value["uncertainty"]),
            }
        except (TypeError, ValueError):
            return None

    def _metric_delta(self, previous: Mapping[str, float], current: Mapping[str, float]) -> Dict[str, float]:
        return {
            "security_delta": round(float(current["security"]) - float(previous["security"]), 4),
            "utility_delta": round(float(current["utility"]) - float(previous["utility"]), 4),
            "uncertainty_delta": round(float(previous["uncertainty"]) - float(current["uncertainty"]), 4),
        }


# ============================================================
# Utilities
# ============================================================

def _clip01(x: float) -> float:
    return max(0.0, min(1.0, float(x)))


def evaluate_payload(
    payload: Mapping[str, Any],
    *,
    evaluator: Optional[Evaluator] = None,
) -> Dict[str, Any]:
    """
    Convenience function for JSON-ish inputs.
    Expected payload:
      {
        "prompt": "...",
        "mode": "secure",
        "context": {...},
        "history": [...],
        "files": [...],
        "candidates": [
            {"id": "...", "diff": "...", "strategy": "...", "explanation": "..."}
        ],
        "intent": {...},
        "evidence": {...}
      }
    """
    evaluator = evaluator or Evaluator()

    metadata = dict(payload.get("metadata", {}) or {})
    if "previous_state" in payload:
        metadata["previous_state"] = payload.get("previous_state")

    task = TaskInput(
        prompt=str(payload.get("prompt", "")),
        context=dict(payload.get("context", {}) or {}),
        history=list(payload.get("history", []) or []),
        files=list(payload.get("files", []) or []),
        mode=str(payload.get("mode", "balanced")),
        repo=payload.get("repo"),
        metadata=metadata,
    )

    intent_data = dict(payload.get("intent", {}) or {})
    intent = IntentHypothesis(
        label=str(intent_data.get("label", "general_fix")),
        confidence=float(intent_data.get("confidence", 0.5)),
        alternatives=list(intent_data.get("alternatives", []) or []),
        notes=list(intent_data.get("notes", []) or []),
    )

    ev = dict(payload.get("evidence", {}) or {})
    evidence = RetrievedEvidence(
        docs=list(ev.get("docs", []) or []),
        code=list(ev.get("code", []) or []),
        tests=list(ev.get("tests", []) or []),
        history=list(ev.get("history", []) or []),
        policy=list(ev.get("policy", []) or []),
        graph=dict(ev.get("graph", {}) or {}),
        memory=dict(ev.get("memory", {}) or {}),
    )

    candidates_data = list(payload.get("candidates", []) or [])
    candidates = [
        Candidate(
            id=str(c.get("id", f"c{i+1}")),
            diff=str(c.get("diff", "")),
            strategy=str(c.get("strategy", "")),
            explanation=str(c.get("explanation", "")),
            metadata=dict(c.get("metadata", {}) or {}),
        )
        for i, c in enumerate(candidates_data)
    ]

    result = evaluator.evaluate(task, intent, evidence, candidates)
    return {
        "evaluation": {
            "decision": result.decision.value,
            "chosen_candidate": result.chosen_candidate,
            "scores": {cid: asdict(score) for cid, score in result.scores.items()},
            "deltas": result.deltas,
            "risk_summary": result.risk_summary,
            "best_rationale": result.best_rationale,
            "requires_verification": result.requires_verification,
            "requires_repair": result.requires_repair,
            "threshold_hit": result.threshold_hit,
        }
    }


if __name__ == "__main__":
    # Simple self-test
    payload = {
        "prompt": "fix hardcoded SECRET_KEY in settings.py",
        "mode": "secure",
        "context": {"policy": [{"name": "no-hardcoded-secrets"}]},
        "files": [{"path": "settings.py", "content": 'SECRET_KEY = "hardcoded_secret_key"'}],
        "candidates": [
            {
                "id": "c1",
                "diff": '+SECRET_KEY = os.environ.get("SECRET_KEY")',
                "strategy": "minimal-patch",
                "explanation": "Small patch",
            },
            {
                "id": "c2",
                "diff": '+import os\n+SECRET_KEY = os.environ.get("SECRET_KEY")\n+if not SECRET_KEY:\n+    raise ValueError("SECRET_KEY not set")',
                "strategy": "balanced-fix",
                "explanation": "Robust fix with fail-fast",
            },
        ],
        "intent": {"label": "secure_fix", "confidence": 0.84},
        "evidence": {"tests": [{"name": "settings import"}]},
    }

    out = evaluate_payload(payload)
    import json
    print(json.dumps(out, indent=2))
