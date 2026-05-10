from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
from enum import Enum
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
