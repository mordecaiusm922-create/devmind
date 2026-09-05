"""
tests/test_allowlist_enforce.py -- DevMind Agent Governance
Coverage for the allowlist enforce-mode override in execute_command().

Point 1 of the roadmap (Sept 2026): the allowlist has run in shadow
mode since it was built, logging comparisons without ever changing
enforcement. This is the mechanism itself -- a real, tested,
deliberately OFF-by-default toggle (DEVMIND_ALLOWLIST_ENFORCE) -- not
a decision to flip it on in production. That's a separate, later
call once allowlist coverage gaps found by the synthetic stress test
(scripts/allowlist_stress_test.py) are addressed and/or real usage
data exists.

Design, confirmed by reading the code before writing these tests:
  - Only upgrades REVIEW -> ALLOW. Never touches BLOCK or ESCALATE --
    those are the blocklist's hard denials and a session-level
    "something is wrong" signal respectively; being allowlisted must
    never silently override either.
  - Only fires when the allowlist actually recognized the command
    (allowlist_allowed=True). A command absent from every category
    gets no special treatment.
  - The override is recorded in decision.why_chain
    ("allowlist_override:<category>") so the audit trail always shows
    it happened -- consistent with the project's "don't hide your own
    gaps" principle. It never silently swaps the verdict without a
    trace.
  - Off by default (DEVMIND_ALLOWLIST_ENFORCE unset or not "true").
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
    reason: str = "risk_threshold_review",
    risk_score: int = 30,
    why_chain: list[str] | None = None,
) -> GovernanceDecision:
    return GovernanceDecision(
        action_id="test-action-1",
        decision=decision,
        risk_score=risk_score,
        band=RiskBand.MEDIUM,
        surface=ActionSurface.TERMINAL,
        why_chain=why_chain or ["not in allowlist"],
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


class TestAllowlistEnforceOffByDefault:

    def test_enforce_flag_defaults_false(self) -> None:
        assert devmind_server.ALLOWLIST_ENFORCE is False

    def test_review_allowlisted_command_still_blocked_when_enforce_off(self) -> None:
        """The critical baseline: with the toggle at its default (off),
        behavior must be byte-for-byte identical to before this
        feature existed -- allowlisted or not, REVIEW still refuses."""
        decision = make_decision(Decision.REVIEW)
        with patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("engines.allowlist.is_allowlisted", return_value=(True, "diagnostic_investigation")), \
             patch("e2b_code_interpreter.Sandbox.create") as create:
            result = devmind_server.execute_command(command="kubectl get pods", rationale="test")

        assert not create.called
        assert "[DEVMIND REVIEW REQUIRED]" in result


class TestAllowlistEnforceUpgradesReview:

    def test_allowlisted_review_executes_when_enforce_on(self) -> None:
        decision = make_decision(Decision.REVIEW, reason="risk_threshold_review", risk_score=30)
        e2b_mock = make_e2b_mocks()

        with patch.object(devmind_server, "ALLOWLIST_ENFORCE", True), \
             patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("engines.allowlist.is_allowlisted", return_value=(True, "diagnostic_investigation")), \
             patch("e2b_code_interpreter.Sandbox.create", return_value=e2b_mock) as create:
            result = devmind_server.execute_command(command="kubectl get pods", rationale="test")

        assert create.called, "REGRESSION: allowlisted REVIEW was not upgraded to ALLOW"
        assert result.startswith("[DEVMIND ALLOW]"), result

    def test_override_recorded_in_why_chain(self) -> None:
        """The audit trail must show the override happened, not swap
        the verdict silently -- confirmed by inspecting the decision
        object sandbox.intercept() actually returned to execute_command
        (captured via the mock), not just the final text output."""
        decision = make_decision(Decision.REVIEW, reason="risk_threshold_review", risk_score=30)
        e2b_mock = make_e2b_mocks()
        captured = {}

        original_replace = devmind_server.dataclasses.replace

        def spy_replace(obj, **kwargs):
            result = original_replace(obj, **kwargs)
            captured["decision"] = result
            return result

        with patch.object(devmind_server, "ALLOWLIST_ENFORCE", True), \
             patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("engines.allowlist.is_allowlisted", return_value=(True, "diagnostic_investigation")), \
             patch("e2b_code_interpreter.Sandbox.create", return_value=e2b_mock), \
             patch.object(devmind_server.dataclasses, "replace", side_effect=spy_replace):
            devmind_server.execute_command(command="kubectl get pods", rationale="test")

        assert "decision" in captured, "the allowlist override path was never taken"
        assert any(
            entry.startswith("allowlist_override:") for entry in captured["decision"].why_chain
        ), captured["decision"].why_chain

    def test_not_allowlisted_review_still_blocked_even_with_enforce_on(self) -> None:
        """Enforce mode is not a blanket REVIEW->ALLOW switch -- only
        commands the allowlist actually recognizes get upgraded."""
        decision = make_decision(Decision.REVIEW)
        with patch.object(devmind_server, "ALLOWLIST_ENFORCE", True), \
             patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("engines.allowlist.is_allowlisted", return_value=(False, "not in allowlist")), \
             patch("e2b_code_interpreter.Sandbox.create") as create:
            result = devmind_server.execute_command(command="some-unrecognized-thing", rationale="test")

        assert not create.called
        assert "[DEVMIND REVIEW REQUIRED]" in result


class TestAllowlistEnforceNeverTouchesBlockOrEscalate:

    def test_allowlisted_block_is_not_upgraded(self) -> None:
        """Being on the allowlist must never override a hard BLOCK --
        the blocklist's denial always wins. (Contrived scenario for a
        real allowlist category, but the barrier itself must hold
        unconditionally regardless of how it could arise.)"""
        decision = make_decision(Decision.BLOCK, reason="hardblock_pattern", risk_score=95)
        with patch.object(devmind_server, "ALLOWLIST_ENFORCE", True), \
             patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("engines.allowlist.is_allowlisted", return_value=(True, "diagnostic_investigation")), \
             patch("e2b_code_interpreter.Sandbox.create") as create:
            result = devmind_server.execute_command(command="rm -rf /", rationale="test")

        assert not create.called, "REGRESSION: allowlist override reached a BLOCK verdict"
        assert "[DEVMIND BLOCK]" in result

    def test_allowlisted_escalate_is_not_upgraded(self) -> None:
        """Being on the allowlist must never override ESCALATE -- a
        session-level signal that something is wrong overall, which an
        individual command's allowlist status cannot vouch for."""
        decision = make_decision(Decision.ESCALATE, reason="repeated violations")
        with patch.object(devmind_server, "ALLOWLIST_ENFORCE", True), \
             patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("engines.allowlist.is_allowlisted", return_value=(True, "diagnostic_investigation")), \
             patch("e2b_code_interpreter.Sandbox.create") as create:
            result = devmind_server.execute_command(command="kubectl get pods", rationale="test")

        assert not create.called, "REGRESSION: allowlist override reached an ESCALATE verdict"
        assert "[DEVMIND ESCALATE]" in result


class TestAllowlistEnforceShadowComputationFailureIsSafe:

    def test_allowlist_import_failure_does_not_crash_or_upgrade(self) -> None:
        """If the shadow-mode classification itself fails for any
        reason, allowlist_context stays None -- enforce mode must
        degrade to doing nothing (fail closed on the upgrade, not
        fail open), never crash execute_command entirely."""
        decision = make_decision(Decision.REVIEW)
        with patch.object(devmind_server, "ALLOWLIST_ENFORCE", True), \
             patch.object(devmind_server.sandbox, "intercept", return_value=decision), \
             patch("engines.allowlist.is_allowlisted", side_effect=RuntimeError("boom")), \
             patch("e2b_code_interpreter.Sandbox.create") as create:
            result = devmind_server.execute_command(command="kubectl get pods", rationale="test")  # must not raise

        assert not create.called
        assert "[DEVMIND REVIEW REQUIRED]" in result
