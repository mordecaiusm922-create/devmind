from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, Field


@dataclass(slots=True)
class Candidate:
    id: str
    diff: str
    strategy: str
    explanation: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Weights:
    correctness: float = 0.30
    security: float = 0.30
    performance: float = 0.15
    maintainability: float = 0.15
    alignment: float = 0.10
    risk_penalty: float = 0.35


class ContextModel(BaseModel):
    repo: str | None = None
    files: list[str] = Field(default_factory=list)
    history: str = ""
    constraints: dict[str, Any] = Field(default_factory=dict)
    docs: list[str] = Field(default_factory=list)
    memory: dict[str, Any] = Field(default_factory=dict)


class CandidateModel(BaseModel):
    id: str
    diff: str
    strategy: str = "balanced"
    explanation: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class EvaluateRequest(BaseModel):
    prompt: str
    context: ContextModel = Field(default_factory=ContextModel)
    candidates: list[CandidateModel]
    weights: Weights | None = None


class CandidateScores(BaseModel):
    correctness: float
    security: float
    performance: float
    maintainability: float
    alignment: float
    catastrophic_risk: float
    regression_risk: float
    utility: float
    confidence: float
    risk_tags: list[str] = Field(default_factory=list)
    rationale: list[str] = Field(default_factory=list)


class EvaluateResult(BaseModel):
    decision: Literal["approve", "revise", "reject"]
    chosen_candidate: str | None = None
    scores: dict[str, CandidateScores]
    risk_summary: dict[str, float] = Field(default_factory=dict)
    best_rationale: list[str] = Field(default_factory=list)
    requires_verification: bool = True
    requires_repair: bool = False


class GenerateRequest(BaseModel):
    prompt: str
    context: ContextModel = Field(default_factory=ContextModel)
    n_candidates: int = 4
    mode: Literal["secure", "balanced", "fast", "robust"] = "balanced"
    weights: Weights | None = None


class GenerateResult(BaseModel):
    prompt: str
    candidates: list[CandidateModel]
    evaluation: EvaluateResult


class RepairRequest(BaseModel):
    prompt: str
    context: ContextModel = Field(default_factory=ContextModel)
    candidate: CandidateModel | None = None
    max_iters: int = 4
    mode: Literal["secure", "balanced", "fast", "robust"] = "balanced"
    weights: Weights | None = None


class RepairResult(BaseModel):
    converged: bool
    iterations: int
    candidate: CandidateModel
    evaluation: EvaluateResult
    history: list[dict[str, Any]] = Field(default_factory=list)


class VerifyRequest(BaseModel):
    code: str
    properties: list[str] = Field(default_factory=list)


class VerifyResult(BaseModel):
    verified: bool
    score: float
    violations: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
