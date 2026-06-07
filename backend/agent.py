from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from memory import record_analysis_result
from retriever import retrieve_security_signals
from summarizer import summarize_pr


@dataclass(frozen=True)
class AgentConfig:
    """
    Configuración del agente.

    retry_on_failure:
        Reintenta si el summarizer falla por parsing, truncation o inestabilidad transitoria.
    max_retries:
        Número máximo de reintentos adicionales.
    verbose:
        Emite eventos estructurados para observabilidad.
    fail_closed:
        Si el pipeline queda ambiguo, retorna un fallback conservador.
    """

    retry_on_failure: bool = True
    max_retries: int = 1
    verbose: bool = False
    fail_closed: bool = True


@dataclass
class AgentResult:
    """
    Resultado unificado del agente.

    Mantiene el contrato simple para el resto del sistema, pero añade metadatos
    útiles para análisis, calibración y auditoría.
    """

    summary: dict[str, Any]
    pre_analysis: Any
    evaluation: Any
    status: str
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    signals: dict[str, Any] = field(default_factory=dict)
    attack_chain: dict[str, Any] = field(default_factory=dict)
    trace: dict[str, Any] = field(default_factory=dict)
    retry_count: int = 0
    fallback_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "pre_analysis": self.pre_analysis,
            "evaluation": self.evaluation,
            "status": self.status,
            "errors": self.errors,
            "warnings": self.warnings,
            "signals": self.signals,
            "attack_chain": self.attack_chain,
            "trace": self.trace,
            "retry_count": self.retry_count,
            "fallback_reason": self.fallback_reason,
        }


class DevMindAgent:
    """
    Orquestador defensivo sobre summarize_pr().

    Mentalidad:
    - primero recoge contexto y señales externas
    - luego busca rutas de abuso / cadena de ataque
    - después evalúa consistencia, severidad y confianza
    - si hay ambigüedad, falla cerrado

    No re-implementa la lógica de análisis semántico; solo la envuelve con
    control de flujo, resiliencia y persistencia segura.
    """

    def __init__(
        self,
        config: AgentConfig | None = None,
        on_event: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        self.config = config or AgentConfig()
        self.on_event = on_event

    def run(self, pr_data: dict[str, Any]) -> AgentResult:
        errors: list[str] = []
        warnings: list[str] = []
        trace: dict[str, Any] = {}
        last_exc: Exception | None = None
        attempts = self.config.max_retries + 1
        retry_count = 0

        repo = str(pr_data.get("repo", "") or "")
        pr_number = int(pr_data.get("number") or 0)
        trace_id = str(pr_data.get("trace_id", "") or "")

        retrieval_ctx = self._safe_retrieve_security_signals(repo, pr_data, warnings)
        signals = self._extract_security_signals(pr_data, retrieval_ctx)
        attack_chain = self._build_attack_chain_hypothesis(pr_data, retrieval_ctx, signals)

        trace.update(
            {
                "repo": repo,
                "pr_number": pr_number,
                "trace_id": trace_id,
                "attempts": attempts,
                "retrieval_used": bool(retrieval_ctx),
                "signal_count": len(signals.get("items", [])),
                "attack_chain_score": attack_chain.get("score", 0),
                "attack_chain_path": attack_chain.get("path", []),
            }
        )

        for attempt in range(attempts):
            retry_count = attempt
            try:
                if self.config.verbose:
                    self._emit(
                        "agent.start",
                        {
                            "attempt": attempt + 1,
                            "max_attempts": attempts,
                            "repo": repo,
                            "pr_number": pr_number,
                            "attack_chain_score": attack_chain.get("score", 0),
                            "retrieved_signals": len(signals.get("items", [])),
                        },
                    )

                summary, pre, ev = summarize_pr(pr_data, retriever_ctx=retrieval_ctx)
                normalized = self._normalize_summary(summary)
                normalized = self._enrich_summary(
                    normalized,
                    pr_data=pr_data,
                    signals=signals,
                    attack_chain=attack_chain,
                )

                result = AgentResult(
                    summary=normalized,
                    pre_analysis=pre,
                    evaluation=ev,
                    status="ok",
                    errors=errors,
                    warnings=warnings,
                    signals=signals,
                    attack_chain=attack_chain,
                    trace=trace,
                    retry_count=retry_count,
                )

                if self.config.verbose:
                    self._emit(
                        "agent.success",
                        {
                            "attempt": attempt + 1,
                            "risk_score": self._risk_score(normalized),
                            "triage": normalized.get("triage"),
                            "merge_blocker": normalized.get("merge_blocker"),
                            "attack_chain_score": attack_chain.get("score", 0),
                            "confidence_hints": self._confidence_hints(pre, ev, attack_chain),
                        },
                    )

                self._record_outcome(pr_data, normalized, attack_chain, status="approved" if not normalized.get("merge_blocker") else "blocked")
                return result

            except Exception as exc:
                last_exc = exc
                errors.append(f"{type(exc).__name__}: {exc}")
                trace["last_exception"] = {"type": type(exc).__name__, "message": str(exc)}

                if self.config.verbose:
                    self._emit(
                        "agent.failure",
                        {
                            "attempt": attempt + 1,
                            "error": type(exc).__name__,
                            "message": str(exc),
                            "retryable": self._is_retryable(exc),
                        },
                    )

                if not self.config.retry_on_failure or attempt >= self.config.max_retries or not self._is_retryable(exc):
                    break

        fallback = self._fallback_summary(pr_data, errors, last_exc, signals, attack_chain)
        if self.config.fail_closed:
            fallback["merge_blocker"] = True
            fallback["merge_block_reason"] = fallback.get("merge_block_reason") or "Pipeline failed closed after internal analysis error."

        self._record_outcome(pr_data, fallback, attack_chain, status="error")
        return AgentResult(
            summary=fallback,
            pre_analysis=None,
            evaluation=None,
            status="error",
            errors=errors,
            warnings=warnings,
            signals=signals,
            attack_chain=attack_chain,
            trace=trace,
            retry_count=retry_count,
            fallback_reason=type(last_exc).__name__ if last_exc else "unknown",
        )

    def analyze(self, pr_data: dict[str, Any]) -> dict[str, Any]:
        """API simple para usar desde el resto del proyecto."""
        return self.run(pr_data).to_dict()

    def _safe_retrieve_security_signals(
        self,
        repo: str,
        pr_data: dict[str, Any],
        warnings: list[str],
    ) -> dict[str, Any]:
        try:
            return retrieve_security_signals(repo, pr_data) or {}
        except Exception as exc:
            warnings.append(f"retrieval_failed: {type(exc).__name__}: {exc}")
            if self.config.verbose:
                self._emit(
                    "agent.retrieval_failed",
                    {"repo": repo, "error": type(exc).__name__, "message": str(exc)},
                )
            return {}

    def _extract_security_signals(
        self,
        pr_data: dict[str, Any],
        retriever_ctx: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Normaliza el contexto recuperado a una estructura más útil para análisis.
        """
        items: list[dict[str, Any]] = []

        for raw in retriever_ctx.get("signals", []) or []:
            if isinstance(raw, dict):
                items.append(
                    {
                        "kind": str(raw.get("kind", "unknown")),
                        "severity": str(raw.get("severity", "low")),
                        "surface": str(raw.get("surface", "unknown")),
                        "evidence": str(raw.get("evidence", "")),
                        "confidence": self._as_float(raw.get("confidence"), 0.5),
                    }
                )

        summary_hint = str(pr_data.get("title", "") or "")
        if summary_hint:
            items.append(
                {
                    "kind": "pr_title",
                    "severity": "low",
                    "surface": self._guess_surface(summary_hint),
                    "evidence": summary_hint,
                    "confidence": 0.25,
                }
            )

        top_severity = self._max_severity(items)
        suspicious_count = sum(1 for item in items if item.get("severity") in {"high", "critical"})

        return {
            "items": items,
            "top_severity": top_severity,
            "suspicious_count": suspicious_count,
            "has_auth_surface": any(item.get("surface") == "auth" for item in items),
            "has_ci_surface": any(item.get("surface") == "ci_cd" for item in items),
            "has_secret_surface": any(item.get("surface") == "secrets" for item in items),
            "has_infra_surface": any(item.get("surface") == "infra" for item in items),
        }

    def _build_attack_chain_hypothesis(
        self,
        pr_data: dict[str, Any],
        retriever_ctx: dict[str, Any],
        signals: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Inspirado en mentalidad adversarial: no mira solo hallazgos, mira rutas.
        Pregunta: ¿qué tendría que combinar un atacante para convertir esto en acceso, abuso o exfiltración?
        """
        text = " ".join(
            [
                str(pr_data.get("title", "")),
                str(pr_data.get("description", "")),
                str(retriever_ctx),
                str(signals),
            ]
        ).lower()

        path: list[str] = []
        score = 0

        if any(k in text for k in ("secret", "token", "api_key", "private key", "credential")):
            path.append("secret_surface")
            score += 15
        if any(k in text for k in ("auth", "authorization", "authentication", "oauth", "jwt", "sso", "session")):
            path.append("identity_surface")
            score += 12
        if any(k in text for k in ("eval(", "subprocess", "os.system", "shell=true", "| bash", "curl http")):
            path.append("dangerous_sink")
            score += 35
        if any(k in text for k in ("0.0.0.0/0", "public-read", "privileged: true", "hostnetwork", "wildcard")):
            path.append("exposure_surface")
            score += 25
        if any(k in text for k in ("pull_request_target", "workflow_run", "github_token", "secrets.")):
            path.append("ci_trust_boundary")
            score += 20
        if any(k in text for k in ("drop table", "drop column", "delete from", "force_destroy", "truncate")):
            path.append("destructive_change")
            score += 30

        if {"secret_surface", "identity_surface"}.issubset(path):
            score += 10
            path.append("credential_to_identity_chain")
        if {"identity_surface", "dangerous_sink"}.issubset(path):
            score += 10
            path.append("identity_to_sink_chain")
        if {"ci_trust_boundary", "secret_surface"}.issubset(path):
            score += 12
            path.append("ci_secret_exposure_chain")
        if {"exposure_surface", "dangerous_sink"}.issubset(path):
            score += 10
            path.append("remote_reachability_chain")

        if signals.get("top_severity") == "critical":
            score += 20
            path.append("critical_signal_present")

        return {
            "score": min(100, score),
            "path": path,
            "hypothesis": " -> ".join(path) if path else "no_clear_chain",
            "risk_band": self._risk_band(score),
        }

    def _normalize_summary(self, summary: dict[str, Any]) -> dict[str, Any]:
        data = dict(summary or {})
        scores = data.get("scores") or {}
        risk_note = data.get("risk_note") or {}

        if isinstance(risk_note, str):
            parts = risk_note.split("--", 1)
            level = parts[0].strip().lower()
            reason = parts[1].strip() if len(parts) > 1 else risk_note.strip()
            risk_note = {"level": level, "reason": reason}
        elif isinstance(risk_note, dict):
            risk_note = {
                "level": str(risk_note.get("level", "low")).lower(),
                "reason": str(risk_note.get("reason", "")).strip(),
            }
        else:
            risk_note = {"level": "low", "reason": ""}

        data["risk_note"] = risk_note
        data["scores"] = scores if isinstance(scores, dict) else {}
        data.setdefault("vulnerabilities", [])
        data.setdefault("ci_cd_risks", [])
        data.setdefault("key_changes", [])
        data.setdefault("evidence", [])
        data.setdefault("review_focus", "")
        data.setdefault("what", "")
        data.setdefault("why", "")
        data.setdefault("impact", "")
        return data

    def _enrich_summary(
        self,
        summary: dict[str, Any],
        *,
        pr_data: dict[str, Any],
        signals: dict[str, Any],
        attack_chain: dict[str, Any],
    ) -> dict[str, Any]:
        enriched = dict(summary)

        existing_evidence = list(enriched.get("evidence") or [])
        existing_evidence.append(
            {
                "source": "agent",
                "kind": "attack_chain",
                "score": attack_chain.get("score", 0),
                "path": attack_chain.get("path", []),
            }
        )
        enriched["evidence"] = existing_evidence

        if not enriched.get("review_focus"):
            enriched["review_focus"] = self._build_review_focus(signals, attack_chain)

        # Fail closed if the attack chain looks realistic even when the summarizer was optimistic.
        if attack_chain.get("score", 0) >= 70:
            enriched["merge_blocker"] = True
            enriched["merge_block_reason"] = enriched.get("merge_block_reason") or "Exploit chain reaches a practical sink."
            enriched["triage"] = enriched.get("triage") or "P0"
            enriched["risk_note"] = enriched.get("risk_note") or {"level": "critical", "reason": "Attack-chain analysis elevated the risk floor."}

        # Surface-based hints to make later policy layers sharper.
        if signals.get("has_secret_surface") and not enriched.get("permissions_analysis"):
            enriched["permissions_analysis"] = {
                "permissions_block_present": False,
                "scopes_granted": [],
                "secrets_accessed_before_validation": True,
                "github_token_scope": "unknown",
                "trust_boundary_respected": False,
            }

        if pr_data.get("files") and not enriched.get("key_changes"):
            enriched["key_changes"] = self._derive_key_changes(pr_data)

        return enriched

    def _build_review_focus(self, signals: dict[str, Any], attack_chain: dict[str, Any]) -> str:
        if attack_chain.get("score", 0) >= 70:
            return "Inspect the full exploit path, especially trust boundaries and dangerous sinks."
        if signals.get("has_ci_surface") and signals.get("has_secret_surface"):
            return "Inspect CI/CD trust boundaries and secret exposure paths."
        if signals.get("has_auth_surface"):
            return "Inspect auth, session, and authorization boundaries."
        if signals.get("has_infra_surface"):
            return "Inspect public exposure, IAM scope, and privileged deployment settings."
        return "Inspect changed files for hidden sinks, validation gaps, and over-broad permissions."

    def _derive_key_changes(self, pr_data: dict[str, Any]) -> list[str]:
        changes: list[str] = []
        for f in pr_data.get("files", []) or []:
            filename = str(f.get("filename") or f.get("path") or "")
            if not filename:
                continue
            additions = int(f.get("additions") or 0)
            deletions = int(f.get("deletions") or 0)
            if additions or deletions:
                changes.append(f"{filename}: +{additions}/-{deletions}")
        return changes[:10]

    def _fallback_summary(
        self,
        pr_data: dict[str, Any],
        errors: list[str],
        exc: Exception | None,
        signals: dict[str, Any],
        attack_chain: dict[str, Any],
    ) -> dict[str, Any]:
        title = str(pr_data.get("title", "") or "")
        files = pr_data.get("files", []) or []

        return {
            "what": title or "PR analysis unavailable",
            "why": "The summarizer pipeline failed before producing a structured result.",
            "impact": "Could not complete automated security assessment.",
            "risk_note": {
                "level": "critical" if attack_chain.get("score", 0) >= 70 else "low",
                "reason": "Fallback result returned after an internal pipeline error.",
            },
            "permissions_analysis": {
                "permissions_block_present": False,
                "scopes_granted": [],
                "secrets_accessed_before_validation": bool(signals.get("has_secret_surface")),
                "github_token_scope": "unknown",
                "trust_boundary_respected": not bool(signals.get("has_secret_surface") or signals.get("has_ci_surface")),
            },
            "attack_path": {
                "entry_point": "unknown",
                "attacker_control_verified": False,
                "exploit_steps": attack_chain.get("path", []),
                "sink": "unknown",
                "blast_radius": "unknown",
                "impact": "unknown",
            },
            "vulnerabilities": [],
            "ci_cd_risks": [],
            "key_changes": self._derive_key_changes(pr_data),
            "review_focus": self._build_review_focus(signals, attack_chain),
            "evidence": [
                {
                    "source": "agent",
                    "kind": "fallback",
                    "error_count": len(errors),
                    "fallback_reason": type(exc).__name__ if exc else "unknown",
                }
            ],
            "scores": {},
            "triage": "P0" if attack_chain.get("score", 0) >= 70 else None,
            "merge_blocker": True if self.config.fail_closed else False,
            "merge_block_reason": "Pipeline failed closed after internal analysis error.",
            "errors": errors,
            "fallback_reason": type(exc).__name__ if exc else "unknown",
            "files_seen": len(files),
            "signals": signals,
            "attack_chain": attack_chain,
        }

    def _record_outcome(
        self,
        pr_data: dict[str, Any],
        summary: dict[str, Any],
        attack_chain: dict[str, Any],
        *,
        status: str,
    ) -> None:
        try:
            record_analysis_result(
                str(pr_data.get("repo", "") or ""),
                pr_number=int(pr_data.get("number") or 0),
                trace_id=str(pr_data.get("trace_id", "") or ""),
                risk=float(self._risk_score(summary)),
                decision="blocked" if summary.get("merge_blocker") else "approved",
                label=str(summary.get("triage") or "unknown"),
                explanation=str(summary.get("what", "")),
            )
        except Exception as exc:
            if self.config.verbose:
                self._emit(
                    "agent.record_failed",
                    {
                        "status": status,
                        "error": type(exc).__name__,
                        "message": str(exc),
                        "attack_chain_score": attack_chain.get("score", 0),
                    },
                )

    def _risk_score(self, summary: dict[str, Any]) -> float:
        scores = summary.get("scores") or {}
        if isinstance(scores, dict) and scores:
            return float(scores.get("risk_score", scores.get("score", 0)) or 0)
        risk_note = summary.get("risk_note") or {}
        level = str(risk_note.get("level", "low")).lower() if isinstance(risk_note, dict) else "low"
        return {
            "critical": 95.0,
            "high": 75.0,
            "medium": 50.0,
            "low": 20.0,
        }.get(level, 20.0)

    def _confidence_hints(self, pre: Any, ev: Any, attack_chain: dict[str, Any]) -> dict[str, Any]:
        return {
            "attack_chain_score": attack_chain.get("score", 0),
            "has_pre_analysis": pre is not None,
            "has_evaluation": ev is not None,
            "risk_band": attack_chain.get("risk_band", "unknown"),
        }

    def _guess_surface(self, text: str) -> str:
        text_l = text.lower()
        if any(k in text_l for k in ("secret", "token", "credential", "password")):
            return "secrets"
        if any(k in text_l for k in ("auth", "oauth", "jwt", "sso", "session")):
            return "auth"
        if any(k in text_l for k in ("terraform", "kubernetes", "docker", "iam", "s3", "rds")):
            return "infra"
        if any(k in text_l for k in ("workflow", "actions", "pull_request_target", "github")):
            return "ci_cd"
        return "runtime"

    def _max_severity(self, items: list[dict[str, Any]]) -> str:
        order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        best = "low"
        for item in items:
            sev = str(item.get("severity", "low")).lower()
            if order.get(sev, 0) > order.get(best, 0):
                best = sev
        return best

    def _risk_band(self, score: int) -> str:
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 40:
            return "medium"
        if score >= 20:
            return "low"
        return "minimal"

    def _is_retryable(self, exc: Exception) -> bool:
        name = type(exc).__name__.lower()
        msg = str(exc).lower()
        return any(
            token in name or token in msg
            for token in (
                "timeout",
                "parse",
                "trunc",
                "json",
                "temporary",
                "connection",
                "rate",
            )
        )

    def _as_float(self, value: Any, default: float = 0.5) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    def _emit(self, event: str, payload: dict[str, Any]) -> None:
        if self.on_event is not None:
            self.on_event(event, payload)


def agent_run(pr_data: dict[str, Any], config: AgentConfig | None = None) -> dict[str, Any]:
    """Función cómoda para integración directa."""
    agent = DevMindAgent(config=config)
    return agent.analyze(pr_data)
