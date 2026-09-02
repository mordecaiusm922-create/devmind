"""
tests/test_review_approval.py -- DevMind Agent Governance
Coverage for the point-6 human-review-via-Slack channel: the
review_requests table, Slack notification/interactivity helpers, and
execute_command()'s REVIEW-verdict wiring.

Point 6 of NEXT STEPS: REVIEW now goes exclusively through Slack
human approval. break_glass no longer applies to REVIEW at all (see
tests/test_break_glass.py::TestBreakGlassNoLongerAppliesToReview for
that side of the change) -- it remains available for BLOCK only.

Design recap (see devmind_server.py for the real implementation):
  - No approval_id: _create_review_request() inserts a pending row,
    _send_slack_review_notification() posts Block Kit buttons to
    Slack, execute_command() returns the request id without executing.
  - With approval_id: _check_review_approval() looks up the row by id
    and returns one of "approved" / "rejected" / "pending" / "expired"
    / "command_mismatch" / "not_found". Only "approved" lets execution
    proceed. Approval is bound to the exact command text (strict, not
    fuzzy) per the point-6 design decision.
  - All Supabase/Slack calls are non-fatal on failure -- a
    misconfigured or unreachable integration must never crash command
    handling, only degrade the review channel's availability.

Two layers, same discipline as every other suite this session:
  1. Unit tests directly on the four new helpers.
  2. Integration tests against execute_command()'s REVIEW branch.
"""
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import devmind_server
from core.types import ActionSurface, Decision, GovernanceDecision, RiskBand


def make_decision(
    decision: Decision = Decision.REVIEW,
    reason: str = "risk_threshold_review",
    risk_score: int = 30,
) -> GovernanceDecision:
    return GovernanceDecision(
        action_id="test-action-1",
        decision=decision,
        risk_score=risk_score,
        band=RiskBand.MEDIUM,
        surface=ActionSurface.TERMINAL,
        why_chain=["not in allowlist"],
        reason=reason,
        signals=[],
    )


def make_e2b_mocks():
    fake_result = MagicMock(exit_code=0, stdout="ok", stderr="")
    fake_sbx = MagicMock()
    fake_sbx.commands.run.return_value = fake_result
    fake_sbx_cm = MagicMock()
    fake_sbx_cm.__enter__.return_value = fake_sbx
    fake_sbx_cm.__exit__.return_value = False
    return fake_sbx_cm


def future_iso(minutes: int = 30) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()


def past_iso(minutes: int = 5) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()


# =============================================================================
# Layer 1a -- _slack_post_message()
# =============================================================================

def slack_signature(secret: str, timestamp: str, body: str) -> str:
    import hmac, hashlib
    basestring = f"v0:{timestamp}:{body}".encode()
    return "v0=" + hmac.new(secret.encode(), basestring, hashlib.sha256).hexdigest()


class TestSlackPostMessage:

    def test_missing_config_returns_none_non_fatal(self) -> None:
        with patch.object(devmind_server, "SLACK_BOT_TOKEN", ""), \
             patch.object(devmind_server, "SLACK_REVIEW_CHANNEL", "C123"):
            result = devmind_server._slack_post_message([], "fallback")
        assert result is None

    def test_successful_post_returns_parsed_response(self) -> None:
        fake_resp = MagicMock()
        fake_resp.json.return_value = {"ok": True, "ts": "123.456", "channel": "C123"}
        with patch.object(devmind_server, "SLACK_BOT_TOKEN", "xoxb-fake"), \
             patch.object(devmind_server, "SLACK_REVIEW_CHANNEL", "C123"), \
             patch.object(devmind_server._requests, "post", return_value=fake_resp) as post_mock:
            result = devmind_server._slack_post_message([{"type": "section"}], "fallback text")

        assert result == {"ok": True, "ts": "123.456", "channel": "C123"}
        call_kwargs = post_mock.call_args
        assert call_kwargs.args[0] == "https://slack.com/api/chat.postMessage"
        assert call_kwargs.kwargs["headers"]["Authorization"] == "Bearer xoxb-fake"
        assert call_kwargs.kwargs["json"]["channel"] == "C123"

    def test_slack_api_error_returns_none_non_fatal(self) -> None:
        fake_resp = MagicMock()
        fake_resp.json.return_value = {"ok": False, "error": "channel_not_found"}
        with patch.object(devmind_server, "SLACK_BOT_TOKEN", "xoxb-fake"), \
             patch.object(devmind_server, "SLACK_REVIEW_CHANNEL", "C123"), \
             patch.object(devmind_server._requests, "post", return_value=fake_resp):
            result = devmind_server._slack_post_message([], "fallback")
        assert result is None

    def test_network_exception_returns_none_non_fatal(self) -> None:
        with patch.object(devmind_server, "SLACK_BOT_TOKEN", "xoxb-fake"), \
             patch.object(devmind_server, "SLACK_REVIEW_CHANNEL", "C123"), \
             patch.object(devmind_server._requests, "post", side_effect=RuntimeError("timeout")):
            result = devmind_server._slack_post_message([], "fallback")  # must not raise
        assert result is None


# =============================================================================
# Layer 1b -- _create_review_request()
# =============================================================================

class TestCreateReviewRequest:

    def test_no_supabase_client_returns_none(self) -> None:
        decision = make_decision()
        with patch.object(devmind_server._supabase_audit, "_client", None):
            result = devmind_server._create_review_request("echo hi", "test", decision, "org-1")
        assert result is None

    def test_writes_expected_row_and_returns_id(self) -> None:
        client = MagicMock()
        client.table.return_value.insert.return_value.execute.return_value = MagicMock(
            data=[{"id": 42}]
        )
        decision = make_decision(reason="risk_threshold_review", risk_score=30)

        with patch.object(devmind_server._supabase_audit, "_client", client):
            result = devmind_server._create_review_request(
                "echo hi", "diagnostic check", decision, "devmind-default"
            )

        assert result == 42
        client.table.assert_any_call("review_requests")
        row = client.table.return_value.insert.call_args[0][0]
        assert row["command"] == "echo hi"
        assert row["rationale"] == "diagnostic check"
        assert row["reason"] == "risk_threshold_review"
        assert row["risk_score"] == 30
        assert row["decision"] == "REVIEW"
        assert row["status"] == "pending"
        assert row["agent"] == devmind_server.AGENT_NAME
        assert row["session_id"] == devmind_server._SESSION_ID
        assert "expires_at" in row

    def test_invalid_org_id_stored_as_none(self) -> None:
        """Same UUID-safety discipline as agent_sessions (point 3) and
        organizations (point 5): an invalid org_id must never be sent
        raw to a UUID-typed column."""
        client = MagicMock()
        client.table.return_value.insert.return_value.execute.return_value = MagicMock(
            data=[{"id": 1}]
        )
        decision = make_decision()
        with patch.object(devmind_server._supabase_audit, "_client", client):
            devmind_server._create_review_request("echo hi", "test", decision, "devmind-default")

        row = client.table.return_value.insert.call_args[0][0]
        assert row["org_id"] is None

    def test_valid_org_id_passed_through(self) -> None:
        import uuid as uuid_module
        real_org_id = str(uuid_module.uuid4())
        client = MagicMock()
        client.table.return_value.insert.return_value.execute.return_value = MagicMock(
            data=[{"id": 1}]
        )
        decision = make_decision()
        with patch.object(devmind_server._supabase_audit, "_client", client):
            devmind_server._create_review_request("echo hi", "test", decision, real_org_id)

        row = client.table.return_value.insert.call_args[0][0]
        assert row["org_id"] == real_org_id

    def test_insert_exception_returns_none_non_fatal(self) -> None:
        client = MagicMock()
        client.table.return_value.insert.return_value.execute.side_effect = RuntimeError("db down")
        decision = make_decision()
        with patch.object(devmind_server._supabase_audit, "_client", client):
            result = devmind_server._create_review_request("echo hi", "test", decision, "org-1")
        assert result is None


# =============================================================================
# Layer 1c -- _check_review_approval()
# =============================================================================

class TestCheckReviewApproval:

    def test_no_supabase_client_returns_not_found(self) -> None:
        with patch.object(devmind_server._supabase_audit, "_client", None):
            status, row = devmind_server._check_review_approval("1", "echo hi")
        assert status == "not_found"
        assert row is None

    def test_nonexistent_id_returns_not_found(self) -> None:
        client = MagicMock()
        client.table.return_value.select.return_value.eq.return_value.limit.return_value.execute.return_value = \
            MagicMock(data=[])
        with patch.object(devmind_server._supabase_audit, "_client", client):
            status, row = devmind_server._check_review_approval("999", "echo hi")
        assert status == "not_found"

    def test_command_mismatch(self) -> None:
        client = MagicMock()
        client.table.return_value.select.return_value.eq.return_value.limit.return_value.execute.return_value = \
            MagicMock(data=[{"id": 1, "command": "echo original", "status": "approved", "expires_at": future_iso()}])
        with patch.object(devmind_server._supabase_audit, "_client", client):
            status, row = devmind_server._check_review_approval("1", "echo different")
        assert status == "command_mismatch"

    def test_expired(self) -> None:
        client = MagicMock()
        client.table.return_value.select.return_value.eq.return_value.limit.return_value.execute.return_value = \
            MagicMock(data=[{"id": 1, "command": "echo hi", "status": "pending", "expires_at": past_iso()}])
        with patch.object(devmind_server._supabase_audit, "_client", client):
            status, row = devmind_server._check_review_approval("1", "echo hi")
        assert status == "expired"

    def test_pending(self) -> None:
        client = MagicMock()
        client.table.return_value.select.return_value.eq.return_value.limit.return_value.execute.return_value = \
            MagicMock(data=[{"id": 1, "command": "echo hi", "status": "pending", "expires_at": future_iso()}])
        with patch.object(devmind_server._supabase_audit, "_client", client):
            status, row = devmind_server._check_review_approval("1", "echo hi")
        assert status == "pending"

    def test_approved(self) -> None:
        client = MagicMock()
        client.table.return_value.select.return_value.eq.return_value.limit.return_value.execute.return_value = \
            MagicMock(data=[{"id": 1, "command": "echo hi", "status": "approved", "expires_at": future_iso()}])
        with patch.object(devmind_server._supabase_audit, "_client", client):
            status, row = devmind_server._check_review_approval("1", "echo hi")
        assert status == "approved"

    def test_rejected(self) -> None:
        client = MagicMock()
        client.table.return_value.select.return_value.eq.return_value.limit.return_value.execute.return_value = \
            MagicMock(data=[{"id": 1, "command": "echo hi", "status": "rejected", "expires_at": future_iso()}])
        with patch.object(devmind_server._supabase_audit, "_client", client):
            status, row = devmind_server._check_review_approval("1", "echo hi")
        assert status == "rejected"

    def test_query_exception_returns_not_found_non_fatal(self) -> None:
        client = MagicMock()
        client.table.return_value.select.return_value.eq.return_value.limit.return_value.execute.side_effect = \
            RuntimeError("db down")
        with patch.object(devmind_server._supabase_audit, "_client", client):
            status, row = devmind_server._check_review_approval("1", "echo hi")  # must not raise
        assert status == "not_found"

    def test_expiry_checked_before_status_for_a_pending_request(self) -> None:
        """An expired-but-still-'pending' row (nobody ever clicked a
        button) must report 'expired', not 'pending' -- the agent
        needs a clear signal to submit a fresh request rather than
        polling a dead one forever."""
        client = MagicMock()
        client.table.return_value.select.return_value.eq.return_value.limit.return_value.execute.return_value = \
            MagicMock(data=[{"id": 1, "command": "echo hi", "status": "pending", "expires_at": past_iso()}])
        with patch.object(devmind_server._supabase_audit, "_client", client):
            status, row = devmind_server._check_review_approval("1", "echo hi")
        assert status == "expired"


# =============================================================================
# Layer 1d -- _send_slack_review_notification()
# =============================================================================

class TestSendSlackReviewNotification:

    def test_posts_message_with_approve_and_reject_buttons_carrying_request_id(self) -> None:
        decision = make_decision(reason="risk_threshold_review", risk_score=30)
        with patch.object(devmind_server, "_slack_post_message") as post_mock:
            devmind_server._send_slack_review_notification(42, "echo hi", "diagnostic", decision)

        assert post_mock.called
        blocks = post_mock.call_args[0][0]
        actions_block = next(b for b in blocks if b["type"] == "actions")
        buttons = actions_block["elements"]
        assert len(buttons) == 2
        action_ids = {b["action_id"] for b in buttons}
        assert action_ids == {"approve_review", "reject_review"}
        for b in buttons:
            assert b["value"] == "42"

    def test_message_text_includes_command_and_risk_score(self) -> None:
        decision = make_decision(reason="risk_threshold_review", risk_score=55)
        with patch.object(devmind_server, "_slack_post_message") as post_mock:
            devmind_server._send_slack_review_notification(7, "terraform apply", "infra change", decision)

        blocks = post_mock.call_args[0][0]
        section_text = blocks[0]["text"]["text"]
        assert "terraform apply" in section_text
        assert "55" in section_text
        assert "risk_threshold_review" in section_text


# =============================================================================
# Layer 2 -- execute_command()'s REVIEW branch, end to end
# =============================================================================

class TestExecuteCommandReviewFlow:

    def test_no_approval_id_creates_request_notifies_slack_does_not_execute(self) -> None:
        decision = make_decision()

        with patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("e2b_code_interpreter.Sandbox.create") as e2b_create, \
             patch.object(devmind_server, "_create_review_request", return_value=42) as create_req, \
             patch.object(devmind_server, "_send_slack_review_notification") as notify:
            result = devmind_server.execute_command(command="risky-thing", rationale="test")

        assert not e2b_create.called
        assert create_req.called
        assert notify.called
        assert "#42" in result
        assert 'approval_id="42"' in result

    def test_no_supabase_configured_returns_clear_message(self) -> None:
        decision = make_decision()

        with patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("e2b_code_interpreter.Sandbox.create") as e2b_create, \
             patch.object(devmind_server, "_create_review_request", return_value=None):
            result = devmind_server.execute_command(command="risky-thing", rationale="test")

        assert not e2b_create.called
        assert "couldn't create a review request" in result

    def test_approved_approval_id_executes(self) -> None:
        decision = make_decision()
        e2b_mock = make_e2b_mocks()

        with patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("e2b_code_interpreter.Sandbox.create", return_value=e2b_mock) as e2b_create, \
             patch.object(devmind_server, "_check_review_approval", return_value=("approved", {})):
            result = devmind_server.execute_command(
                command="risky-thing", rationale="test", approval_id="42"
            )

        assert e2b_create.called
        assert result.startswith("[DEVMIND ALLOW]")

    def test_rejected_approval_id_refuses_with_clear_message(self) -> None:
        decision = make_decision()

        with patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("e2b_code_interpreter.Sandbox.create") as e2b_create, \
             patch.object(devmind_server, "_check_review_approval", return_value=("rejected", {})):
            result = devmind_server.execute_command(
                command="risky-thing", rationale="test", approval_id="42"
            )

        assert not e2b_create.called
        assert "rejected" in result

    def test_pending_approval_id_refuses_and_says_to_check_back(self) -> None:
        decision = make_decision()

        with patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("e2b_code_interpreter.Sandbox.create") as e2b_create, \
             patch.object(devmind_server, "_check_review_approval", return_value=("pending", {})):
            result = devmind_server.execute_command(
                command="risky-thing", rationale="test", approval_id="42"
            )

        assert not e2b_create.called
        assert "pending" in result

    def test_expired_approval_id_refuses_and_asks_for_new_request(self) -> None:
        decision = make_decision()

        with patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("e2b_code_interpreter.Sandbox.create") as e2b_create, \
             patch.object(devmind_server, "_check_review_approval", return_value=("expired", {})):
            result = devmind_server.execute_command(
                command="risky-thing", rationale="test", approval_id="42"
            )

        assert not e2b_create.called
        assert "expired" in result

    def test_command_mismatch_refuses_and_explains_binding(self) -> None:
        decision = make_decision()

        with patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("e2b_code_interpreter.Sandbox.create") as e2b_create, \
             patch.object(devmind_server, "_check_review_approval", return_value=("command_mismatch", {})):
            result = devmind_server.execute_command(
                command="risky-thing", rationale="test", approval_id="42"
            )

        assert not e2b_create.called
        assert "different command" in result

    def test_not_found_approval_id_refuses_with_clear_message(self) -> None:
        decision = make_decision()

        with patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("e2b_code_interpreter.Sandbox.create") as e2b_create, \
             patch.object(devmind_server, "_check_review_approval", return_value=("not_found", None)):
            result = devmind_server.execute_command(
                command="risky-thing", rationale="test", approval_id="999"
            )

        assert not e2b_create.called
        assert "couldn't find" in result

    def test_approval_id_is_passed_through_unchanged_to_check_function(self) -> None:
        decision = make_decision()
        with patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("e2b_code_interpreter.Sandbox.create"), \
             patch.object(devmind_server, "_check_review_approval", return_value=("pending", {})) as check_mock:
            devmind_server.execute_command(
                command="risky-thing", rationale="test", approval_id="42"
            )

        check_mock.assert_called_once_with("42", "risky-thing")


# =============================================================================
# Layer 1e -- _verify_slack_signature()
# =============================================================================

class TestVerifySlackSignature:

    def test_valid_signature_and_fresh_timestamp_passes(self) -> None:
        import time as time_module
        secret = "test-secret-123"
        timestamp = str(int(time_module.time()))
        body = "payload=%7B%22type%22%3A%22block_actions%22%7D"
        sig = slack_signature(secret, timestamp, body)

        with patch.object(devmind_server, "SLACK_SIGNING_SECRET", secret):
            assert devmind_server._verify_slack_signature(body.encode(), timestamp, sig) is True

    def test_wrong_signature_fails(self) -> None:
        import time as time_module
        with patch.object(devmind_server, "SLACK_SIGNING_SECRET", "test-secret-123"):
            result = devmind_server._verify_slack_signature(
                b"payload=x", str(int(time_module.time())), "v0=not_the_real_signature"
            )
        assert result is False

    def test_no_signing_secret_configured_fails(self) -> None:
        import time as time_module
        secret = "test-secret-123"
        timestamp = str(int(time_module.time()))
        body = "payload=x"
        sig = slack_signature(secret, timestamp, body)
        with patch.object(devmind_server, "SLACK_SIGNING_SECRET", ""):
            result = devmind_server._verify_slack_signature(body.encode(), timestamp, sig)
        assert result is False

    def test_stale_timestamp_fails_replay_protection(self) -> None:
        """A signature computed correctly but for a timestamp more than
        5 minutes old must be rejected -- prevents a captured request
        from being replayed later."""
        secret = "test-secret-123"
        old_timestamp = str(int(__import__("time").time()) - 60 * 10)
        body = "payload=x"
        sig = slack_signature(secret, old_timestamp, body)
        with patch.object(devmind_server, "SLACK_SIGNING_SECRET", secret):
            result = devmind_server._verify_slack_signature(body.encode(), old_timestamp, sig)
        assert result is False

    def test_signature_computed_over_wrong_body_fails(self) -> None:
        """The signature must cover the exact raw body -- confirms
        tampering with the payload after signing is detected."""
        import time as time_module
        secret = "test-secret-123"
        timestamp = str(int(time_module.time()))
        sig = slack_signature(secret, timestamp, "payload=original")
        with patch.object(devmind_server, "SLACK_SIGNING_SECRET", secret):
            result = devmind_server._verify_slack_signature(
                b"payload=tampered", timestamp, sig
            )
        assert result is False

    def test_missing_timestamp_or_signature_fails(self) -> None:
        with patch.object(devmind_server, "SLACK_SIGNING_SECRET", "test-secret-123"):
            assert devmind_server._verify_slack_signature(b"x", "", "v0=abc") is False
            assert devmind_server._verify_slack_signature(b"x", "123", "") is False

    def test_non_numeric_timestamp_fails(self) -> None:
        with patch.object(devmind_server, "SLACK_SIGNING_SECRET", "test-secret-123"):
            result = devmind_server._verify_slack_signature(b"x", "not-a-number", "v0=abc")
        assert result is False


# =============================================================================
# Layer 1f -- _resolve_review_request()
# =============================================================================

class TestResolveReviewRequest:

    def test_no_supabase_client_returns_false(self) -> None:
        with patch.object(devmind_server._supabase_audit, "_client", None):
            result = devmind_server._resolve_review_request("42", "approved", "jonny")
        assert result is False

    def test_successful_update_returns_true(self) -> None:
        client = MagicMock()
        client.table.return_value.update.return_value.eq.return_value.eq.return_value.execute.return_value = \
            MagicMock(data=[{"id": 42, "status": "approved"}])
        with patch.object(devmind_server._supabase_audit, "_client", client):
            result = devmind_server._resolve_review_request("42", "approved", "jonny")
        assert result is True

    def test_update_only_targets_pending_rows(self) -> None:
        """The optimistic-concurrency guard: the update must be scoped
        to status='pending', so a second click (double-approve, or
        approve-then-reject) can't silently overwrite an
        already-resolved decision."""
        client = MagicMock()
        client.table.return_value.update.return_value.eq.return_value.eq.return_value.execute.return_value = \
            MagicMock(data=[{"id": 42}])
        with patch.object(devmind_server._supabase_audit, "_client", client):
            devmind_server._resolve_review_request("42", "approved", "jonny")

        first_eq = client.table.return_value.update.return_value.eq
        second_eq = client.table.return_value.update.return_value.eq.return_value.eq
        assert first_eq.call_args_list == [call("id", "42")]
        assert second_eq.call_args_list == [call("status", "pending")]

    def test_already_resolved_row_returns_false(self) -> None:
        """A second click on an already-resolved request matches zero
        rows (since the .eq("status", "pending") guard excludes it) --
        must report False, not silently succeed."""
        client = MagicMock()
        client.table.return_value.update.return_value.eq.return_value.eq.return_value.execute.return_value = \
            MagicMock(data=[])
        with patch.object(devmind_server._supabase_audit, "_client", client):
            result = devmind_server._resolve_review_request("42", "approved", "jonny")
        assert result is False

    def test_update_exception_returns_false_non_fatal(self) -> None:
        client = MagicMock()
        client.table.return_value.update.return_value.eq.return_value.eq.return_value.execute.side_effect = \
            RuntimeError("db down")
        with patch.object(devmind_server._supabase_audit, "_client", client):
            result = devmind_server._resolve_review_request("42", "approved", "jonny")  # must not raise
        assert result is False

    def test_writes_resolver_and_resolved_at(self) -> None:
        client = MagicMock()
        client.table.return_value.update.return_value.eq.return_value.eq.return_value.execute.return_value = \
            MagicMock(data=[{"id": 42}])
        with patch.object(devmind_server._supabase_audit, "_client", client):
            devmind_server._resolve_review_request("42", "rejected", "on-call-alice")

        update_payload = client.table.return_value.update.call_args[0][0]
        assert update_payload["status"] == "rejected"
        assert update_payload["resolved_by"] == "on-call-alice"
        assert "resolved_at" in update_payload
