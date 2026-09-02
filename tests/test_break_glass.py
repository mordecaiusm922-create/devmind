"""
tests/test_break_glass.py -- DevMind Agent Governance
Coverage for the break-glass override path in devmind_server.py.

Point 4 of NEXT STEPS (2026-08-23 snapshot). Requested scope: "override
succeeds for BLOCK/REVIEW with justification, fails without
justification, never applies to ESCALATE, logs correctly to
break_glass_log."

Also covers point 5 (org-level break-glass-prohibited flag, added
after point 4 shipped): _is_break_glass_prohibited_for_org() fails
CLOSED -- invalid/unrecognized org_id, no Supabase client, no matching
row, or a raising query are all treated as prohibited. This means
every point-4 "override succeeds" test below must now explicitly mock
_is_break_glass_prohibited_for_org to return False (the org allows
it) -- otherwise the fail-closed default refuses every override
before the justification check is even reached, since the test env's
org_id ("devmind-default" in these tests, matching production before
the DEVMIND_ORG_ID env var is updated to a real organizations.id UUID)
is not a valid UUID.

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


def org_allows_break_glass():
    """Patch context: the org's break_glass_prohibited flag reads as
    False, i.e. break-glass is permitted. Needed for every test below
    that expects an override to actually succeed, since the fail-closed
    default treats an unverifiable org (no client, invalid org_id) as
    prohibited."""
    return patch.object(devmind_server, "_is_break_glass_prohibited_for_org", return_value=False)


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
# Layer 1b -- _is_break_glass_prohibited_for_org(), point 5
# =============================================================================

class TestIsBreakGlassProhibitedForOrg:

    def test_invalid_org_id_fails_closed(self) -> None:
        """The exact production case today: ORG_ID="devmind-default" is
        not a UUID at all -- must fail closed regardless of Supabase
        state."""
        assert devmind_server._is_break_glass_prohibited_for_org("devmind-default") is True

    def test_no_supabase_client_fails_closed(self) -> None:
        import uuid as uuid_module
        real_org_id = str(uuid_module.uuid4())
        with patch.object(devmind_server._supabase_audit, "_client", None):
            assert devmind_server._is_break_glass_prohibited_for_org(real_org_id) is True

    def test_no_matching_org_row_fails_closed(self) -> None:
        import uuid as uuid_module
        real_org_id = str(uuid_module.uuid4())
        client = MagicMock()
        client.table.return_value.select.return_value.eq.return_value.limit.return_value.execute.return_value = \
            MagicMock(data=[])
        with patch.object(devmind_server._supabase_audit, "_client", client):
            assert devmind_server._is_break_glass_prohibited_for_org(real_org_id) is True

    def test_query_exception_fails_closed(self) -> None:
        import uuid as uuid_module
        real_org_id = str(uuid_module.uuid4())
        client = MagicMock()
        client.table.return_value.select.return_value.eq.return_value.limit.return_value.execute.side_effect = \
            RuntimeError("db down")
        with patch.object(devmind_server._supabase_audit, "_client", client):
            assert devmind_server._is_break_glass_prohibited_for_org(real_org_id) is True

    def test_org_row_with_flag_true_is_prohibited(self) -> None:
        import uuid as uuid_module
        real_org_id = str(uuid_module.uuid4())
        client = MagicMock()
        client.table.return_value.select.return_value.eq.return_value.limit.return_value.execute.return_value = \
            MagicMock(data=[{"break_glass_prohibited": True}])
        with patch.object(devmind_server._supabase_audit, "_client", client):
            assert devmind_server._is_break_glass_prohibited_for_org(real_org_id) is True

    def test_org_row_with_flag_false_is_allowed(self) -> None:
        import uuid as uuid_module
        real_org_id = str(uuid_module.uuid4())
        client = MagicMock()
        client.table.return_value.select.return_value.eq.return_value.limit.return_value.execute.return_value = \
            MagicMock(data=[{"break_glass_prohibited": False}])
        with patch.object(devmind_server._supabase_audit, "_client", client):
            assert devmind_server._is_break_glass_prohibited_for_org(real_org_id) is False

    def test_queries_correct_table_and_column(self) -> None:
        """Confirms the query targets organizations.id / .break_glass_prohibited
        -- not a typo'd table/column name that would silently always
        fail closed in production."""
        import uuid as uuid_module
        real_org_id = str(uuid_module.uuid4())
        client = MagicMock()
        client.table.return_value.select.return_value.eq.return_value.limit.return_value.execute.return_value = \
            MagicMock(data=[{"break_glass_prohibited": False}])
        with patch.object(devmind_server._supabase_audit, "_client", client):
            devmind_server._is_break_glass_prohibited_for_org(real_org_id)

        client.table.assert_called_once_with("organizations")
        client.table.return_value.select.assert_called_once_with("break_glass_prohibited")
        client.table.return_value.select.return_value.eq.assert_called_once_with("id", real_org_id)


# =============================================================================
# Layer 2 -- execute_command()'s break-glass enforcement decision table
# =============================================================================

class TestBreakGlassOverridesBlock:

    def test_override_with_justification_reaches_execution(self) -> None:
        decision = make_decision(Decision.BLOCK, reason="hard block: sql_drop")
        e2b_mock = make_e2b_mocks()

        with patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("e2b_code_interpreter.Sandbox.create", return_value=e2b_mock) as create, \
             org_allows_break_glass():
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
             org_allows_break_glass(), \
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


class TestBreakGlassNoLongerAppliesToReview:
    """Point 6 (2026-08-30): REVIEW now goes exclusively through the
    Slack human-approval channel (tests/test_review_approval.py).
    break_glass has no effect on REVIEW anymore -- this is a
    deliberate behavior change from point 4: if break_glass could
    still bypass REVIEW, the approval channel would have no teeth,
    since an agent could always self-serve past it with a fabricated
    justification. break_glass remains available for BLOCK only."""

    def test_break_glass_true_on_review_is_ignored_creates_review_request_instead(self) -> None:
        decision = make_decision(Decision.REVIEW, reason="risk_threshold_review", risk_score=30)
        e2b_mock = make_e2b_mocks()

        with patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("e2b_code_interpreter.Sandbox.create", return_value=e2b_mock) as create, \
             org_allows_break_glass(), \
             patch.object(devmind_server, "_create_review_request", return_value=99) as create_req, \
             patch.object(devmind_server, "_send_slack_review_notification") as notify:
            result = devmind_server.execute_command(
                command="some-unrecognized-command --flag",
                rationale="test",
                break_glass=True,
                break_glass_justification="on-call approved via Slack thread #incidents",
            )

        assert not create.called, (
            "REGRESSION: break_glass=True bypassed REVIEW directly, skipping human approval"
        )
        assert create_req.called, "a review request should still be created even with break_glass=True"
        assert notify.called
        assert "#99" in result

    def test_org_prohibited_check_never_runs_for_review(self) -> None:
        """The point-5 org-level kill switch only makes sense for
        BLOCK's break_glass path now -- it must not even be consulted
        for a REVIEW decision."""
        decision = make_decision(Decision.REVIEW)

        with patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("e2b_code_interpreter.Sandbox.create") as create, \
             patch.object(devmind_server, "_is_break_glass_prohibited_for_org") as org_check, \
             patch.object(devmind_server, "_create_review_request", return_value=1), \
             patch.object(devmind_server, "_send_slack_review_notification"):
            devmind_server.execute_command(
                command="risky-thing",
                rationale="test",
                break_glass=True,
                break_glass_justification="on-call approved",
            )

        assert not create.called
        assert not org_check.called, (
            "REGRESSION: the BLOCK-only org-prohibited check ran for a REVIEW decision"
        )


class TestBreakGlassRequiresJustification:

    def test_block_with_break_glass_true_but_empty_justification_fails(self) -> None:
        """org_allows_break_glass() isolates this test to the
        justification check specifically -- without it, the new
        org-prohibited fail-closed check (point 5) would refuse first
        and this test would pass for the wrong reason."""
        decision = make_decision(Decision.BLOCK)

        with patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("e2b_code_interpreter.Sandbox.create") as create, \
             org_allows_break_glass():
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
        text doesn't count as a real justification. Uses BLOCK: since
        point 6, break_glass no longer reaches this guard at all for
        REVIEW (see TestBreakGlassNoLongerAppliesToReview)."""
        decision = make_decision(Decision.BLOCK)

        with patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("e2b_code_interpreter.Sandbox.create") as create, \
             org_allows_break_glass():
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
        with no override attempt must not execute. Since point 6, this
        also attempts to create a review request; with no Supabase
        client configured in the test env, that attempt fails
        gracefully (returns None) and the base REVIEW message is
        still returned intact -- see test_review_approval.py for the
        full request-creation path with a mocked client."""
        decision = make_decision(Decision.REVIEW)

        with patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("e2b_code_interpreter.Sandbox.create") as create:
            result = devmind_server.execute_command(command="risky-thing", rationale="test")

        assert not create.called
        assert "[DEVMIND REVIEW REQUIRED]" in result


class TestBreakGlassOrgProhibited:
    """Point 5's actual acceptance test: an org that has explicitly
    prohibited break-glass must refuse the override regardless of how
    good the justification is -- and must never touch E2B or write to
    break_glass_log for a refusal."""

    def test_org_prohibited_refuses_block_override_even_with_good_justification(self) -> None:
        decision = make_decision(Decision.BLOCK)

        with patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("e2b_code_interpreter.Sandbox.create") as create, \
             patch.object(devmind_server, "_is_break_glass_prohibited_for_org", return_value=True), \
             patch.object(devmind_server, "_log_break_glass_override") as log_mock:
            result = devmind_server.execute_command(
                command="DROP TABLE customers",
                rationale="test",
                break_glass=True,
                break_glass_justification="VP-approved, ticket INC-4471, verified emergency",
            )

        assert not create.called, (
            "REGRESSION: an org-prohibited break-glass still reached execution"
        )
        assert not log_mock.called, (
            "REGRESSION: a refused override was still written to break_glass_log"
        )
        assert "disabled for this organization" in result
        assert "[DEVMIND BLOCK]" in result

    def test_org_prohibited_refuses_review_override_even_with_good_justification(self) -> None:
        pytest.skip(
            "Obsolete since point 6: break_glass no longer applies to REVIEW at "
            "all, so the org-prohibited check is never reached for it. See "
            "TestBreakGlassNoLongerAppliesToReview.test_org_prohibited_check_never_runs_for_review."
        )

    def test_org_check_is_bypassed_entirely_when_break_glass_is_false(self) -> None:
        """A routine (non-override) BLOCK shouldn't even call the org
        lookup -- it's irrelevant when nobody asked to override
        anything."""
        decision = make_decision(Decision.BLOCK)

        with patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("e2b_code_interpreter.Sandbox.create") as create, \
             patch.object(devmind_server, "_is_break_glass_prohibited_for_org") as org_check:
            result = devmind_server.execute_command(command="DROP TABLE customers", rationale="test")

        assert not create.called
        assert not org_check.called, (
            "the org-prohibited check should only run when break_glass=True is actually requested"
        )
        assert "[DEVMIND BLOCK]" in result


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


# =============================================================================
# _send_slack_block_notification() -- informational-only awareness ping for
# BLOCK, no buttons, nothing to approve. Point 6 follow-up.
# =============================================================================

class TestSendSlackBlockNotification:

    def test_posts_no_action_buttons(self) -> None:
        """Confirms this is purely informational -- unlike the REVIEW
        notification, there must be no 'actions' block (no buttons to
        click), since there's nothing to approve here."""
        decision = make_decision(Decision.BLOCK, reason="hardblock_pattern", risk_score=98)
        with patch.object(devmind_server, "_slack_post_message") as post_mock:
            devmind_server._send_slack_block_notification(
                "rm -rf /", "test", decision, overridden=False
            )

        assert post_mock.called
        blocks = post_mock.call_args[0][0]
        assert not any(b.get("type") == "actions" for b in blocks)

    def test_plain_block_message_has_no_justification_line(self) -> None:
        decision = make_decision(Decision.BLOCK, reason="hardblock_pattern", risk_score=98)
        with patch.object(devmind_server, "_slack_post_message") as post_mock:
            devmind_server._send_slack_block_notification(
                "rm -rf /", "test", decision, overridden=False
            )

        section_text = post_mock.call_args[0][0][0]["text"]["text"]
        assert "Justification" not in section_text
        assert "overridden" not in section_text.lower()

    def test_overridden_block_message_includes_justification(self) -> None:
        decision = make_decision(Decision.BLOCK, reason="hardblock_pattern", risk_score=98)
        with patch.object(devmind_server, "_slack_post_message") as post_mock:
            devmind_server._send_slack_block_notification(
                "rm -rf /", "test", decision, overridden=True,
                justification="prod down, emergency rollback",
            )

        section_text = post_mock.call_args[0][0][0]["text"]["text"]
        assert "overridden" in section_text.lower()
        assert "prod down, emergency rollback" in section_text

    def test_message_includes_command_and_risk_score(self) -> None:
        decision = make_decision(Decision.BLOCK, reason="hardblock_pattern", risk_score=98)
        with patch.object(devmind_server, "_slack_post_message") as post_mock:
            devmind_server._send_slack_block_notification(
                "rm -rf /", "cleanup", decision, overridden=False
            )

        section_text = post_mock.call_args[0][0][0]["text"]["text"]
        assert "rm -rf /" in section_text
        assert "98" in section_text


class TestExecuteCommandSendsBlockNotification:

    def test_plain_block_sends_notification_not_overridden(self) -> None:
        decision = make_decision(Decision.BLOCK)
        with patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("e2b_code_interpreter.Sandbox.create") as create, \
             patch.object(devmind_server, "_send_slack_block_notification") as notify:
            devmind_server.execute_command(command="rm -rf /", rationale="test")

        assert not create.called
        notify.assert_called_once()
        call_kwargs = notify.call_args.kwargs
        assert call_kwargs.get("overridden") is False

    def test_overridden_block_sends_notification_overridden_true(self) -> None:
        decision = make_decision(Decision.BLOCK)
        e2b_mock = make_e2b_mocks()
        with patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("e2b_code_interpreter.Sandbox.create", return_value=e2b_mock), \
             org_allows_break_glass(), \
             patch.object(devmind_server, "_send_slack_block_notification") as notify:
            devmind_server.execute_command(
                command="rm -rf /", rationale="test",
                break_glass=True, break_glass_justification="emergency",
            )

        notify.assert_called_once()
        call_kwargs = notify.call_args.kwargs
        assert call_kwargs.get("overridden") is True
        assert call_kwargs.get("justification") == "emergency"

    def test_org_prohibited_refusal_does_not_send_block_notification(self) -> None:
        """The org-prohibited refusal path returns before ever reaching
        break_glass handling -- it must not send a BLOCK notification
        either, since nothing was actually blocked-and-executed or
        blocked-and-refused at that point, just a break-glass attempt
        that was itself rejected up front."""
        decision = make_decision(Decision.BLOCK)
        with patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("e2b_code_interpreter.Sandbox.create") as create, \
             patch.object(devmind_server, "_is_break_glass_prohibited_for_org", return_value=True), \
             patch.object(devmind_server, "_send_slack_block_notification") as notify:
            devmind_server.execute_command(
                command="rm -rf /", rationale="test",
                break_glass=True, break_glass_justification="emergency",
            )

        assert not create.called
        assert not notify.called

    def test_review_verdict_never_sends_block_notification(self) -> None:
        decision = make_decision(Decision.REVIEW)
        with patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("e2b_code_interpreter.Sandbox.create"), \
             patch.object(devmind_server, "_create_review_request", return_value=1), \
             patch.object(devmind_server, "_send_slack_review_notification"), \
             patch.object(devmind_server, "_send_slack_block_notification") as notify:
            devmind_server.execute_command(command="risky-thing", rationale="test")

        assert not notify.called
