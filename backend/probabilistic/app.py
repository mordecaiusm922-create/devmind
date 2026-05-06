from __future__ import annotations

from fastapi import FastAPI

from .evaluate import evaluate_request
from .generate import generate_request
from .repair import repair_request
from .schemas import EvaluateRequest, GenerateRequest, RepairRequest, VerifyRequest
from .verifier import verify_candidate

app = FastAPI(title="DevMind Probabilistic Engine", version="0.1.0")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/evaluate")
def evaluate_endpoint(req: EvaluateRequest):
    return evaluate_request(req)


@app.post("/generate")
def generate_endpoint(req: GenerateRequest):
    return generate_request(req)


@app.post("/repair")
def repair_endpoint(req: RepairRequest):
    return repair_request(req)


@app.post("/verify")
def verify_endpoint(req: VerifyRequest):
    return verify_candidate(req.code, req.properties)
