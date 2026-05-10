from __future__ import annotations

import asyncio
import json
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class CandidateState(str, Enum):
    RUNNABLE = "runnable"
    VERIFYING = "verifying"
    REPAIRING = "repairing"
    REJECTED = "rejected"
    APPROVED = "approved"
    DEAD = "dead"


class VerificationTrap(str, Enum):
    SQL_INJECTION = "sql_injection"
    HARDCODED_SECRET = "hardcoded_secret"
    SHELL_EXECUTION = "shell_execution"
    UNSAFE_IMPORT = "unsafe_import"
    TEST_FAILURE = "test_failure"
    BANDIT_HIGH = "bandit_high"
    SYNTAX_ERROR = "syntax_error"
    HIGH_UNCERTAINTY = "high_uncertainty"
    SECURITY_REGRESSION = "security_regression"


@dataclass
class RuntimeMessage:
    sender: str
    target: str
    type: str
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass
class CandidateEnv:
    id: str
    state: CandidateState
    candidate: Any
    score: Any | None = None
    verifier_state: dict[str, Any] = field(default_factory=dict)
    sandbox_evidence: dict[str, Any] = field(default_factory=dict)
    repair_history: list[dict[str, Any]] = field(default_factory=list)
    messages: list[RuntimeMessage] = field(default_factory=list)
    env_runs: int = 0

    def to_dict(self) -> dict[str, Any]:
        score = self.score
        return {
            "id": self.id,
            "state": self.state.value,
            "candidate_id": getattr(self.candidate, "id", self.id),
            "utility": getattr(score, "utility", None),
            "security": getattr(score, "security", None),
            "uncertainty": getattr(score, "uncertainty", None),
            "verifier_state": self.verifier_state,
            "sandbox_status": self.sandbox_evidence.get("status"),
            "repair_history": self.repair_history,
            "env_runs": self.env_runs,
            "messages": [asdict(message) for message in self.messages],
        }


@dataclass
class RuntimeMemory:
    successful_repairs: list[dict[str, Any]] = field(default_factory=list)
    failed_repairs: list[dict[str, Any]] = field(default_factory=list)
    verifier_patterns: list[dict[str, Any]] = field(default_factory=list)
    regression_patterns: list[dict[str, Any]] = field(default_factory=list)
    repo_risk_history: list[dict[str, Any]] = field(default_factory=list)
    repair_priors: dict[str, float] = field(default_factory=dict)
    security_priors: dict[str, float] = field(default_factory=dict)
    storage_path: str = field(default_factory=lambda: str(Path(__file__).with_name(".runtime_memory.json")))

    @classmethod
    def load(cls, storage_path: str | None = None) -> "RuntimeMemory":
        path = Path(storage_path) if storage_path else Path(__file__).with_name(".runtime_memory.json")
        if not path.exists():
            return cls(storage_path=str(path))
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return cls(
                successful_repairs=list(data.get("successful_repairs") or []),
                failed_repairs=list(data.get("failed_repairs") or []),
                verifier_patterns=list(data.get("verifier_patterns") or []),
                regression_patterns=list(data.get("regression_patterns") or []),
                repo_risk_history=list(data.get("repo_risk_history") or []),
                repair_priors=dict(data.get("repair_priors") or {}),
                security_priors=dict(data.get("security_priors") or {}),
                storage_path=str(path),
            )
        except (OSError, json.JSONDecodeError, TypeError):
            return cls(storage_path=str(path))

    def save(self) -> None:
        path = Path(self.storage_path)
        payload = {
            "successful_repairs": self.successful_repairs[-500:],
            "failed_repairs": self.failed_repairs[-500:],
            "verifier_patterns": self.verifier_patterns[-500:],
            "regression_patterns": self.regression_patterns[-500:],
            "repo_risk_history": self.repo_risk_history[-500:],
            "repair_priors": self.repair_priors,
            "security_priors": self.security_priors,
        }
        try:
            path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        except OSError:
            pass

    def record_successful_repair(self, intent: Any, strategy: str, delta: dict[str, Any]) -> None:
        intent_key = _intent_key(intent)
        utility_delta = float(delta.get("utility_delta", 0.0) or 0.0)
        security_delta = float(delta.get("security_delta", 0.0) or 0.0)
        prior = float(self.repair_priors.get(intent_key, 0.5))
        signal = 0.5 + max(-0.5, min(0.5, 0.35 * utility_delta + 0.45 * security_delta))
        self.repair_priors[intent_key] = round(max(0.0, min(1.0, 0.75 * prior + 0.25 * signal)), 4)
        self.successful_repairs.append(
            {
                "intent": intent_key,
                "strategy": strategy,
                "delta": dict(delta),
                "recorded_at": time.time(),
            }
        )
        self.save()

    def record_failed_repair(self, intent: Any, strategy: str, reason: str, delta: dict[str, Any] | None = None) -> None:
        intent_key = _intent_key(intent)
        prior = float(self.repair_priors.get(intent_key, 0.5))
        self.repair_priors[intent_key] = round(max(0.0, min(1.0, prior * 0.85)), 4)
        self.failed_repairs.append(
            {
                "intent": intent_key,
                "strategy": strategy,
                "reason": reason,
                "delta": dict(delta or {}),
                "recorded_at": time.time(),
            }
        )
        self.save()

    def get_repair_prior(self, intent: Any) -> float:
        return float(self.repair_priors.get(_intent_key(intent), 0.5))

    def record_repair(self, env: CandidateEnv, *, success: bool) -> None:
        record = {
            "candidate": env.id,
            "state": env.state.value,
            "sandbox_status": env.sandbox_evidence.get("status"),
            "repair_history": list(env.repair_history),
        }
        if success:
            self.successful_repairs.append(record)
        else:
            self.failed_repairs.append(record)

    def query(self, key: str) -> Any:
        if key in self.repair_priors:
            return self.repair_priors[key]
        return getattr(self, key, None)


class CandidateScheduler:
    MAX_REPAIR_BUDGET = 2
    MAX_SECURITY_REGRESSION = -0.10
    MAX_UNCERTAINTY = 0.50
    MAX_RUNTIME_RUNS = 3

    def __init__(self, memory: RuntimeMemory | None = None) -> None:
        self.envs: dict[str, CandidateEnv] = {}
        self.messages: list[RuntimeMessage] = []
        self.memory = memory or RuntimeMemory()

    def add(self, env: CandidateEnv) -> CandidateEnv:
        self.envs[env.id] = env
        return env

    def add_candidate(self, candidate: Any, score: Any | None = None) -> CandidateEnv:
        env_id = str(getattr(candidate, "id", None) or getattr(candidate, "get", lambda _k, _d=None: _d)("id", "candidate"))
        return self.add(CandidateEnv(id=env_id, state=CandidateState.RUNNABLE, candidate=candidate, score=score))

    def send(self, sender: str, target: str, type: str, payload: dict[str, Any] | None = None) -> RuntimeMessage:
        message = RuntimeMessage(sender=sender, target=target, type=type, payload=dict(payload or {}))
        self.messages.append(message)
        if target in self.envs:
            self.envs[target].messages.append(message)
        return message

    def dispatch_trap(self, env_id: str, trap: VerificationTrap, evidence: dict[str, Any] | None = None) -> None:
        env = self.envs.get(env_id)
        if env is None:
            return

        evidence = dict(evidence or {})
        env.verifier_state.setdefault("traps", []).append({"type": trap.value, "evidence": evidence})
        self.send("verifier", env_id, "trap", {"trap": trap.value, "evidence": evidence})

        if trap in {VerificationTrap.SQL_INJECTION, VerificationTrap.HARDCODED_SECRET, VerificationTrap.SHELL_EXECUTION, VerificationTrap.BANDIT_HIGH, VerificationTrap.SYNTAX_ERROR}:
            env.state = CandidateState.REPAIRING if len(env.repair_history) < self.MAX_REPAIR_BUDGET else CandidateState.REJECTED
        elif trap in {VerificationTrap.TEST_FAILURE, VerificationTrap.HIGH_UNCERTAINTY, VerificationTrap.UNSAFE_IMPORT}:
            env.state = CandidateState.VERIFYING

    def schedule(self) -> list[CandidateEnv]:
        for env in self.envs.values():
            env.env_runs += 1
            score = env.score
            utility = float(getattr(score, "utility", 0.0) or 0.0)
            security = float(getattr(score, "security", 0.0) or 0.0)
            uncertainty = float(getattr(score, "uncertainty", 1.0) or 1.0)
            delta = env.verifier_state.get("delta") or {}
            security_delta = float(delta.get("security_delta", 0.0) or 0.0)

            if env.env_runs > self.MAX_RUNTIME_RUNS:
                env.state = CandidateState.DEAD
            elif security_delta < self.MAX_SECURITY_REGRESSION:
                env.state = CandidateState.DEAD
                self.dispatch_trap(env.id, VerificationTrap.SECURITY_REGRESSION, delta)
            elif uncertainty > self.MAX_UNCERTAINTY:
                env.state = CandidateState.VERIFYING
                self.dispatch_trap(env.id, VerificationTrap.HIGH_UNCERTAINTY, {"uncertainty": uncertainty})
            elif env.sandbox_evidence.get("status") == "failed":
                for trap in traps_from_sandbox(env.sandbox_evidence):
                    self.dispatch_trap(env.id, trap, env.sandbox_evidence)
            elif security >= 0.85 and utility >= 0.62 and uncertainty <= 0.35:
                env.state = CandidateState.APPROVED
            elif utility < 0.62 or security < 0.82:
                env.state = CandidateState.REPAIRING
            else:
                env.state = CandidateState.VERIFYING

        return sorted(
            self.envs.values(),
            key=lambda env: (
                env.state not in {CandidateState.RUNNABLE, CandidateState.VERIFYING},
                -float(getattr(env.score, "utility", 0.0) or 0.0),
                float(getattr(env.score, "uncertainty", 1.0) or 1.0),
            ),
        )

    async def gather(self, *coroutines: Any) -> list[Any]:
        return list(await asyncio.gather(*coroutines))

    def snapshot(self) -> dict[str, Any]:
        return {
            "envs": [env.to_dict() for env in self.schedule()],
            "messages": [asdict(message) for message in self.messages],
            "memory": {
                "successful_repairs": len(self.memory.successful_repairs),
                "failed_repairs": len(self.memory.failed_repairs),
                "repair_priors": self.memory.repair_priors,
                "security_priors": self.memory.security_priors,
            },
        }


class RuntimeSyscalls:
    def __init__(self, *, evaluator: Any = None, verifier: Any = None, repairer: Any = None, sandbox: Any = None, memory: RuntimeMemory | None = None) -> None:
        self.evaluator = evaluator
        self.verifier = verifier
        self.repairer = repairer
        self.sandbox = sandbox
        self.memory = memory or RuntimeMemory()

    async def evaluate(self, *args: Any, **kwargs: Any) -> Any:
        if self.evaluator is None:
            raise RuntimeError("No evaluator syscall configured")
        result = self.evaluator.evaluate(*args, **kwargs)
        return await result if asyncio.iscoroutine(result) else result

    async def verify(self, *args: Any, **kwargs: Any) -> Any:
        if self.verifier is None:
            raise RuntimeError("No verifier syscall configured")
        result = self.verifier.verify(*args, **kwargs)
        return await result if asyncio.iscoroutine(result) else result

    async def repair(self, *args: Any, **kwargs: Any) -> Any:
        if self.repairer is None:
            raise RuntimeError("No repairer syscall configured")
        result = self.repairer.repair(*args, **kwargs)
        return await result if asyncio.iscoroutine(result) else result

    def sandbox_run(self, *args: Any, **kwargs: Any) -> Any:
        if self.sandbox is None:
            raise RuntimeError("No sandbox syscall configured")
        return self.sandbox(*args, **kwargs)

    def memory_query(self, key: str) -> Any:
        return self.memory.query(key)


class DevMindRuntime:
    def __init__(
        self,
        *,
        evaluator: Any = None,
        verifier: Any = None,
        repairer: Any = None,
        sandbox: Any = None,
        memory: RuntimeMemory | None = None,
    ) -> None:
        self.evaluator = evaluator
        self.verifier = verifier
        self.repairer = repairer
        self.sandbox_runner = sandbox
        self.memory = memory or RuntimeMemory.load()

    async def evaluate(self, candidate: Any, task: Any, intent: Any = None, evidence: Any = None) -> Any:
        if self.evaluator is None:
            raise RuntimeError("No evaluator configured")
        result = self.evaluator.evaluate(task, intent, evidence, candidate)
        return await result if asyncio.iscoroutine(result) else result

    async def verify(self, candidate: Any, task: Any, intent: Any = None, evidence: Any = None) -> Any:
        if self.verifier is None:
            raise RuntimeError("No verifier configured")
        result = self.verifier.verify(task, intent, evidence, candidate)
        return await result if asyncio.iscoroutine(result) else result

    async def repair(self, candidate: Any, task: Any, intent: Any = None, evidence: Any = None, score: Any = None) -> Any:
        if self.repairer is None:
            raise RuntimeError("No repairer configured")
        result = self.repairer.repair(task, intent, evidence, candidate, score)
        return await result if asyncio.iscoroutine(result) else result

    async def sandbox(self, candidate: Any) -> Any:
        if self.sandbox_runner is None:
            raise RuntimeError("No sandbox configured")
        result = self.sandbox_runner(candidate)
        return await result if asyncio.iscoroutine(result) else result

    async def memory_query(self, intent: Any) -> float:
        return self.memory.get_repair_prior(intent)


def traps_from_sandbox(evidence: dict[str, Any]) -> list[VerificationTrap]:
    traps: list[VerificationTrap] = []
    if evidence.get("syntax_valid") is False:
        traps.append(VerificationTrap.SYNTAX_ERROR)
    static = evidence.get("static_analysis") or {}
    unsafe_calls = " ".join(str(item.get("call", "")) for item in static.get("unsafe_calls") or [])
    regex_hits = " ".join(static.get("regex_hits") or [])
    if "shell=True" in unsafe_calls or "shell=True" in regex_hits or "os.system" in unsafe_calls:
        traps.append(VerificationTrap.SHELL_EXECUTION)
    if static.get("dangerous_imports"):
        traps.append(VerificationTrap.UNSAFE_IMPORT)
    if evidence.get("test_passed") is False:
        traps.append(VerificationTrap.TEST_FAILURE)
    for issue in evidence.get("bandit_issues") or []:
        if str(issue.get("issue_severity", "")).upper() in {"HIGH", "CRITICAL"}:
            traps.append(VerificationTrap.BANDIT_HIGH)
            break
    return list(dict.fromkeys(traps))


def _intent_key(intent: Any) -> str:
    if isinstance(intent, str):
        return intent or "general"
    return str(getattr(intent, "label", None) or "general")
