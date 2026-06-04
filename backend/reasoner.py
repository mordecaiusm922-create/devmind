from __future__ import annotations
from pydantic import BaseModel
from typing import Literal, List, Optional, Dict, Any
from openai import OpenAI
import os
import json

class RiskDecision(BaseModel):
    action: Literal["ALLOW", "REVIEW", "BLOCK"]
    score: int
    triage: Literal["P0", "P1", "P2", "P3"]
    reason: str
    evidence: List[str]
    confidence: float
    attack_path: Optional[str] = None
    merge_blocker: bool = False
    why_chain: List[str] = []

class RiskReasoner:
    def __init__(self):
        self.client = OpenAI(
            api_key=os.getenv("GROQ_API_KEY"),
            base_url="https://api.groq.com/openai/v1"
        )

    async def analyze_pr(self, pr_data: dict, full_diff: str, context: dict = None) -> RiskDecision:
        context = context or {}
        
        system_prompt = """Eres un senior security engineer con mentalidad Red Team.
Analiza el PR de forma profunda, justa y pragmática."""

        user_prompt = f"""Repo: {pr_data.get('repo')}
PR: {pr_data.get('title')}

Diff:
{full_diff[:15000]}

Contexto: {json.dumps(context, default=str)}

Devuelve solo JSON con estructura RiskDecision."""

        try:
            response = self.client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "system", "content": system_prompt},
                          {"role": "user", "content": user_prompt}],
                temperature=0.0,
                response_format={"type": "json_object"}
            )
            return RiskDecision.model_validate_json(response.choices[0].message.content)
        except Exception as e:
            return RiskDecision(
                action="REVIEW", score=45, triage="P2",
                reason=f"Reasoner fallback: {str(e)[:80]}",
                evidence=["reasoner_error"], confidence=0.4,
                merge_blocker=False, why_chain=["fallback"]
            )
