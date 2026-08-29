"""
tests/test_break_glass.py -- DevMind Agent Governance
Coverage for the break-glass override path in devmind_server.py.

Point 4 of NEXT STEPS (2026-08-23 snapshot). Requested scope: "override
succeeds for BLOCK/REVIEW with justification, fails without
justification, never applies to ESCALATE, logs correctly to
break_glass_log."

Design note: break-glass enforcement lives inline inside
execute_command() in devmind_server.py, not as a separate testable
unit -- @mcp.tool() (FastMCP) leaves the function directly callable as
plain Python, confirmed empirically before writing these tests. Two
things must be mocked per test:
  - devmind_server.sandbox.intercept() -- to control which
    GovernanceDecision comes back, without exercising the real policy
    engine (that's policy_engine's own test suite's job).
  - e2b_code_interpreter.Sandbox.create() -- overriding a BLOCK/REVIEW
    genuinely reaches the execution block (confirmed by reading the
    code: there's no `return` after _log_break_glass_override(), so
    control falls through to the E2B call). Never let a test actually
    hit e2b's API.

Two layers, same discipline as the sandbox/evasion regression suites:
  1. Unit tests directly on _log_break_glass_override() -- the audit
     record shape and its non-fatal failure handling.
  2. Integration tests against execute_command() itself, covering the
     full enforcement decision table from the docstring / requested
     scope.
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import devmind_server
from core.types import ActionSurface, Decision, GovernanceDecision, RiskBand


def make_decision(
    decision: Decision,
    reason: str = "test reason",
    risk_score: int = 90,
    why_chain: list[str] | None = None,
) -> GovernanceDecision:
    return GovernanceDecision(
        action_id="test-action-1",
        decision=decision,
        risk_score=risk_score,
        band=RiskBand.HIGH,
        surface=ActionSurface.TERMINAL,
        why_chain=why_chain or ["some violation"],
        reason=reason,
        signals=[],
    )


def make_e2b_mocks():
    """A working E2B sandbox mock: context-manager Sandbox.create()
    returning an object whose .commands.run() succeeds cleanly."""
    fake_result = MagicMock(exit_code=0, stdout="ok", stderr="")
    fake_sbx = MagicMock()
    fake_sbx.commands.run.return_value = fake_result
    fake_sbx_cm = MagicMock()
    fake_sbx_cm.__enter__.return_value = fake_sbx
    fake_sbx_cm.__exit__.return_value = False
    return fake_sbx_cm


# =============================================================================
# Layer 1 -- _log_break_glass_override() as a unit
# =============================================================================

class TestLogBreakGlassOverride:

    def test_writes_expected_row_to_break_glass_log(self) -> None:
        client = MagicMock()
        decision = make_decision(Decision.BLOCK, reason="hard block: sql_drop", risk_score=95)

        with patch.object(devmind_server._supabase_audit, "_client", client):
            devmind_server._log_break_glass_override(
                "DROP TABLE customers", decision, "emergency data recovery, VP approved"
            )

        client.table.assert_any_call("break_glass_log")
        insert_call = client.table.return_value.insert
        assert insert_call.called, "break_glass_log.insert() was never called"
        row = insert_call.call_args[0][0]

        assert row["command"] == "DROP TABLE customers"
        assert row["original_decision"] == "BLOCK"
        assert row["original_reason"] == "hard block: sql_drop"
        assert row["risk_score"] == 95
        assert row["justification"] == "emergency data recovery, VP approved"
        assert row["agent"] == devmind_server.AGENT_NAME
        assert row["session_id"] == devmind_server._SESSION_ID

    def test_no_supabase_client_is_non_fatal(self) -> None:
        """Docstring says 'non-fatal on write failure' -- with no
        client at all, this must not raise, matching the codebase's
        established fail-safe pattern for audit writes."""
        decision = make_decision(Decision.REVIEW)
        with patch.object(devmind_server._supabase_audit, "_client", None):
            devmind_server._log_break_glass_override("echo hi", decision, "test")  # must not raise

    def test_supabase_write_exception_is_non_fatal(self) -> None:
        client = MagicMock()
        client.table.return_value.insert.return_value.execute.side_effect = RuntimeError("db down")
        decision = make_decision(Decision.REVIEW)
        with patch.object(devmind_server._supabase_audit, "_client", client):
            devmind_server._log_break_glass_override("echo hi", decision, "test")  # must not raise


# =============================================================================
# Layer 2 -- execute_command()'s break-glass enforcement decision table
# =============================================================================

class TestBreakGlassOverridesBlock:

    def test_override_with_justification_reaches_execution(self) -> None:
        decision = make_decision(Decision.BLOCK, reason="hard block: sql_drop")
        e2b_mock = make_e2b_mocks()

        with patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("e2b_code_interpreter.Sandbox.create", return_value=e2b_mock) as create:
            result = devmind_server.execute_command(
                command="DROP TABLE customers",
                rationale="emergency cleanup",
                break_glass=True,
                break_glass_justification="VP-approved incident response, ticket INC-4471",
            )

        assert create.called, "REGRESSION: break_glass override on BLOCK never reached E2B execution"
        assert result.startswith("[DEVMIND ALLOW]"), result

    def test_override_calls_log_break_glass_override(self) -> None:
        decision = make_decision(Decision.BLOCK)
        e2b_mock = make_e2b_mocks()

        with patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("e2b_code_interpreter.Sandbox.create", return_value=e2b_mock), \
             patch.object(devmind_server, "_log_break_glass_override") as log_mock:
            devmind_server.execute_command(
                command="rm -rf /data",
                rationale="test",
                break_glass=True,
                break_glass_justification="justified",
            )

        log_mock.assert_called_once()
        call_args = log_mock.call_args[0]
        assert call_args[0] == "rm -rf /data"
        assert call_args[1] is decision
        assert call_args[2] == "justified"


class TestBreakGlassOverridesReview:

    def test_override_with_justification_reaches_execution(self) -> None:
        decision = make_decision(Decision.REVIEW, reason="risk_threshold_review", risk_score=30)
        e2b_mock = make_e2b_mocks()

        with patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("e2b_code_interpreter.Sandbox.create", return_value=e2b_mock) as create:
            result = devmind_server.execute_command(
                command="some-unrecognized-command --flag",
                rationale="test",
                break_glass=True,
                break_glass_justification="on-call approved via Slack thread #incidents",
            )

        assert create.called, "REGRESSION: break_glass override on REVIEW never reached E2B execution"
        assert result.startswith("[DEVMIND ALLOW]"), result


class TestBreakGlassRequiresJustification:

    def test_block_with_break_glass_true_but_empty_justification_fails(self) -> None:
        decision = make_decision(Decision.BLOCK)

        with patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("e2b_code_interpreter.Sandbox.create") as create:
            result = devmind_server.execute_command(
                command="DROP TABLE customers",
                rationale="test",
                break_glass=True,
                break_glass_justification="",
            )

        assert not create.called, "REGRESSION: execution proceeded without a justification"
        assert "break_glass_justification" in result
        assert "[DEVMIND BLOCK]" in result  # original block message is preserved, not discarded

    def test_whitespace_only_justification_fails(self) -> None:
        """.strip() is used in the real guard -- confirm whitespace-only
        text doesn't count as a real justification."""
        decision = make_decision(Decision.REVIEW)

        with patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("e2b_code_interpreter.Sandbox.create") as create:
            result = devmind_server.execute_command(
                command="risky-thing",
                rationale="test",
                break_glass=True,
                break_glass_justification="   \n\t  ",
            )

        assert not create.called
        assert "break_glass_justification" in result

    def test_review_without_break_glass_at_all_is_blocked_normally(self) -> None:
        """Baseline: break_glass defaults to False -- a REVIEW verdict
        with no override attempt must not execute."""
        decision = make_decision(Decision.REVIEW)

        with patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("e2b_code_interpreter.Sandbox.create") as create:
            result = devmind_server.execute_command(command="risky-thing", rationale="test")

        assert not create.called
        assert "[DEVMIND REVIEW REQUIRED]" in result


class TestBreakGlassNeverAppliesToEscalate:

    def test_escalate_ignores_break_glass_true_with_justification(self) -> None:
        decision = make_decision(Decision.ESCALATE, reason="repeated violations")

        with patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("e2b_code_interpreter.Sandbox.create") as create, \
             patch.object(devmind_server, "_log_break_glass_override") as log_mock:
            result = devmind_server.execute_command(
                command="rm -rf /",
                rationale="test",
                break_glass=True,
                break_glass_justification="I really need this, please, ticket INC-9999",
            )

        assert not create.called, (
            "REGRESSION: break_glass overrode an ESCALATE verdict -- must never happen"
        )
        assert not log_mock.called, (
            "REGRESSION: break-glass was logged for an ESCALATE it should have refused outright"
        )
        assert "cannot override ESCALATE" in result
        assert "[DEVMIND ESCALATE]" in result

    def test_escalate_without_break_glass_is_also_blocked(self) -> None:
        decision = make_decision(Decision.ESCALATE)

        with patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("e2b_code_interpreter.Sandbox.create") as create:
            result = devmind_server.execute_command(command="rm -rf /", rationale="test")

        assert not create.called
        assert "[DEVMIND ESCALATE]" in result


class TestBreakGlassInertOnAllow:

    def test_allow_with_break_glass_true_executes_normally_no_override_logged(self) -> None:
        """break_glass=True is inert when there's nothing to override --
        an ALLOW verdict should execute without ever touching the
        break-glass audit trail."""
        decision = make_decision(Decision.ALLOW, reason="clean")
        e2b_mock = make_e2b_mocks()

        with patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("e2b_code_interpreter.Sandbox.create", return_value=e2b_mock) as create, \
             patch.object(devmind_server, "_log_break_glass_override") as log_mock:
            result = devmind_server.execute_command(
                command="echo hello",
                rationale="test",
                break_glass=True,
                break_glass_justification="not needed but provided anyway",
            )

        assert create.called
        assert result.startswith("[DEVMIND ALLOW]")
        assert not log_mock.called, (
            "break_glass audit trail must only fire for an actual override, not a routine ALLOW"
        )