from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from summarizer import summarize_pr


@dataclass
class AgentConfig:
    """
    Configuración del agente.

    retry_on_failure:
        Reintenta una vez si el summarizer falla por parsing o truncation.
    max_retries:
        Número máximo de reintentos totales.
    """
    retry_on_failure: bool = True
    max_retries: int = 1
    verbose: bool = False


@dataclass
class AgentResult:
    """
    Resultado unificado del agente.
    """
    summary: dict[str, Any]
    pre_analysis: Any
    evaluation: Any
    status: str
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "pre_analysis": self.pre_analysis,
            "evaluation": self.evaluation,
            "status": self.status,
            "errors": self.errors,
        }


class DevMindAgent:
    """
    Agente fino y limpio sobre summarize_pr().

    Responsabilidad:
    - orquestar la ejecución
    - manejar errores/reintentos
    - devolver un resultado estable para el resto del sistema

    No re-implementa la lógica de análisis.
    """
    def __init__(
        self,
        config: AgentConfig | None = None,
        on_event: Callable[[str, dict[str, Any]], None] | None = None,
    ):
        self.config = config or AgentConfig()
        self.on_event = on_event

    def run(self, pr_data: dict[str, Any]) -> AgentResult:
        errors: list[str] = []

        last_exc: Exception | None = None
        attempts = self.config.max_retries + 1

        for attempt in range(attempts):
            try:
                if self.config.verbose:
                    self._emit("agent.start", {"attempt": attempt + 1, "max_attempts": attempts})

                summary, pre, ev = summarize_pr(pr_data)

                if self.config.verbose:
                    self._emit(
                        "agent.success",
                        {
                            "attempt": attempt + 1,
                            "risk_score": summary.get("scores", {}).get("risk_score"),
                            "triage": summary.get("triage"),
                            "merge_blocker": summary.get("merge_blocker"),
                        },
                    )

                return AgentResult(
                    summary=summary,
                    pre_analysis=pre,
                    evaluation=ev,
                    status="ok",
                    errors=errors,
                )

            except Exception as exc:
                last_exc = exc
                errors.append(f"{type(exc).__name__}: {exc}")

                if self.config.verbose:
                    self._emit(
                        "agent.failure",
                        {
                            "attempt": attempt + 1,
                            "error": type(exc).__name__,
                            "message": str(exc),
                        },
                    )

                if not self.config.retry_on_failure:
                    break

                if attempt >= self.config.max_retries:
                    break

        return AgentResult(
            summary=self._fallback_summary(pr_data, errors, last_exc),
            pre_analysis=None,
            evaluation=None,
            status="error",
            errors=errors,
        )

    def analyze(self, pr_data: dict[str, Any]) -> dict[str, Any]:
        """
        API simple para usar desde el resto del proyecto.
        Devuelve un diccionario serializable.
        """
        result = self.run(pr_data)
        return result.to_dict()

    def _fallback_summary(
        self,
        pr_data: dict[str, Any],
        errors: list[str],
        exc: Exception | None,
    ) -> dict[str, Any]:
        title = str(pr_data.get("title", "") or "")
        files = pr_data.get("files", []) or []

        return {
            "what": title or "PR analysis unavailable",
            "why": "The summarizer pipeline failed before producing a structured result.",
            "impact": "Could not complete automated security assessment.",
            "risk_note": {
                "level": "low",
                "reason": "Fallback result returned after an internal pipeline error.",
            },
            "permissions_analysis": None,
            "attack_path": None,
            "vulnerabilities": [],
            "ci_cd_risks": [],
            "key_changes": [],
            "review_focus": "Inspect the failing pipeline and rerun analysis.",
            "evidence": [],
            "scores": {},
            "triage": None,
            "merge_blocker": False,
            "errors": errors,
            "fallback_reason": type(exc).__name__ if exc else "unknown",
            "files_seen": len(files),
        }

    def _emit(self, event: str, payload: dict[str, Any]) -> None:
        if self.on_event is not None:
            self.on_event(event, payload)


def agent_run(pr_data: dict[str, Any], config: AgentConfig | None = None) -> dict[str, Any]:
    """
    Función cómoda para integración directa.
    """
    agent = DevMindAgent(config=config)
    return agent.analyze(pr_data)