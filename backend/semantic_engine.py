from __future__ import annotations
import json
import os
from typing import Any
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

_client = OpenAI(
    api_key=os.getenv("GROQ_API_KEY"),
    base_url="https://api.groq.com/openai/v1",
)
_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

_SYSTEM = """You are a security and correctness analyzer for code diffs.
Respond ONLY with valid JSON. No markdown, no explanation outside JSON.
Always include all required fields."""

def analyze_diff(diff: str, intent: str = "general_fix") -> dict[str, Any]:
    """
    Analiza un diff con Groq y devuelve scores semanticos reales.
    Incluye behavior_preservation_score como dimension independiente.
    """
    prompt = f"""Analyze this code diff for intent: {intent}

DIFF:
{diff[:3000]}

Respond with ONLY this JSON:
{{
  "security_score": 0.0-1.0,
  "correctness_score": 0.0-1.0,
  "behavior_preservation": {{
    "score": 0.0-1.0,
    "signals": {{
      "symbol_exists": true/false,
      "signature_compatible": true/false,
      "exception_surface_changed": true/false,
      "caller_compatibility": true/false
    }},
    "risks": ["list of behavioral risks"]
  }},
  "has_sql_injection": true/false,
  "has_hardcoded_secret": true/false,
  "has_unsafe_eval": true/false,
  "missing_dependencies": ["list of undefined functions/imports"],
  "behavioral_risks": ["list of potential regressions"],
  "security_improvements": ["list of security improvements made"],
  "runtime_confidence": 0.0-1.0,
  "confidence": 0.0-1.0,
  "reasons": ["list of reasons for decision"],
  "reasoning": "one sentence explanation"
}}"""

    try:
        response = _client.chat.completions.create(
            model=_MODEL,
            messages=[
                {"role": "system", "content": _SYSTEM},
                {"role": "user", "content": prompt},
            ],
            max_tokens=512,
            temperature=0.1,
        )
        text = response.choices[0].message.content.strip()
        # Limpia markdown si hay
        text = text.replace("```json", "").replace("```", "").strip()
        return json.loads(text)
    except Exception as exc:
        return {
            "security_score": None,
            "correctness_score": None,
            "has_sql_injection": None,
            "has_hardcoded_secret": None,
            "has_unsafe_eval": None,
            "missing_dependencies": [],
            "behavioral_risks": [],
            "security_improvements": [],
            "confidence": 0.0,
            "reasoning": f"groq_error: {str(exc)[:100]}",
            "error": str(exc),
        }
