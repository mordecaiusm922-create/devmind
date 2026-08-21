"""
tests/test_session_composition_review.py -- unit tests for the
session-composition context added to _review()'s LLM escalation
prompt.

Mocks runtime.backend_connector._post entirely (module-level
function) so no real network call happens. Verifies the prompt
includes recent session history when available, and cleanly omits
the section when there's no session or no history.
"""
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.types import AgentAction, AgentSession, ActionContext, ActionSurface
import runtime.backend_connector as backend_connector


def make_action(payload: str = "rm -rf /tmp/test") -> AgentAction:
    return AgentAction(
        action_id="a1", session_id="s1", agent="test-agent",
        tool="terminal", operation="execute", payload=payload,
        timestamp=datetime.now(timezone.utc), context=ActionContext(environment="staging"),
    )


def make_local_decision():
    """Only the attributes _review() actually reads."""
    return SimpleNamespace(
        signals=[{"name": "recursive_delete"}],
        risk_score=65.0,
        why_chain=["signal:recursive_delete", "risk_threshold_review"],
        surface=ActionSurface.TERMINAL,
    )


def make_session(recent_payloads: list[str]) -> AgentSession:
    return AgentSession(
        session_id="s1", agent="test-agent", organization="org-1",
        user=None, started_at=datetime.now(timezone.utc),
        recent_payloads=recent_payloads,
    )


class TestSessionCompositionInPrompt:
    def test_prompt_includes_recent_payloads_when_session_has_history(self):
        captured = {}

        def fake_post(endpoint, payload):
            captured["prompt"] = payload["prompt"]
            return {"decision": "REVIEW", "risk_score": 50, "reason": "ok"}

        session = make_session(["cat /etc/config", "grep secret /etc/config"])
        with patch.object(backend_connector, "_post", side_effect=fake_post):
            backend_connector._review(make_action(), make_local_decision(), session)

        assert "cat /etc/config" in captured["prompt"]
        assert "grep secret /etc/config" in captured["prompt"]
        assert "Consider composition" in captured["prompt"]

    def test_prompt_omits_session_context_when_session_is_none(self):
        captured = {}

        def fake_post(endpoint, payload):
            captured["prompt"] = payload["prompt"]
            return {"decision": "REVIEW", "risk_score": 50, "reason": "ok"}

        with patch.object(backend_connector, "_post", side_effect=fake_post):
            backend_connector._review(make_action(), make_local_decision(), None)

        assert "Consider composition" not in captured["prompt"]
        assert "Recent actions in this session" not in captured["prompt"]

    def test_prompt_omits_session_context_when_recent_payloads_empty(self):
        captured = {}

        def fake_post(endpoint, payload):
            captured["prompt"] = payload["prompt"]
            return {"decision": "REVIEW", "risk_score": 50, "reason": "ok"}

        session = make_session([])
        with patch.object(backend_connector, "_post", side_effect=fake_post):
            backend_connector._review(make_action(), make_local_decision(), session)

        assert "Consider composition" not in captured["prompt"]

    def test_review_still_works_without_session_argument_at_all(self):
        """Backwards compatibility: session is optional, defaults to None."""
        def fake_post(endpoint, payload):
            return {"decision": "ALLOW", "risk_score": 10, "reason": "fine"}

        with patch.object(backend_connector, "_post", side_effect=fake_post):
            verdict = backend_connector._review(make_action(), make_local_decision())

        assert verdict.decision.name == "ALLOW"