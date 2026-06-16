"""
tests/test_release_gate.py — DevMind Agent Governance
Invariant tests for the release gate engine.

These tests encode the behavioral guarantees of release_gate.
If any of these fail, the release governance layer is broken.

Run: pytest tests/ -v (from devmind/ root with PYTHONPATH=devmind/devmind)
"""

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "devmind"))

from core.types import (
    ActionSurface,
    AgentChange,
    AgentSession,
    ActionContext,
    ChangeImpact,
    ChangeType,
    Decision,
    RiskBand,
    SessionRiskProfile,
    SessionState,
    RiskTrend,
)
from engines.release_gate import evaluate_release, SessionAudit, ArtifactScan


# =============================================================================
# Helpers
# =============================================================================

def release_change(
    version: str = "v1.0.0",
    artifact: str = "Release notes: minor bugfixes and performance improvements.",
    environment: str = "staging",
    affects_production: bool = False,
    change_type: ChangeType = ChangeType.RELEASE_PUBLISH,
    diff_summary: str | None = None,
) -> AgentChange:
    return AgentChange(
        action_id=str(uuid.uuid4()),
        session_id=str(uuid.uuid4()),
        agent="claude-code",
        change_type=change_type,
        surface=ActionSurface.DEPLOYMENT,
        payload=artifact,
        timestamp=datetime.now(timezone.utc),
        impact=ChangeImpact(affects_production=affects_production),
        context=ActionContext(environment=environment),
        artifact_ref=version,
        diff_summary=diff_summary,
    )


def clean_session() -> AgentSession:
    return AgentSession(
        session_id=str(uuid.uuid4()),
        agent="claude-code",
        organization="test-org",
        user="alice",
        started_at=datetime.now(timezone.utc),
        state=SessionState.ACTIVE,
        risk_profile=SessionRiskProfile(),
    )


def session_with_violations(n: int) -> AgentSession:
    rp = SessionRiskProfile(
        policy_violations=n,
        total_actions=n + 5,
        blocked_actions=n,
        cumulative_score=float(n * 20),
        peak_score=n * 20,
    )
    return AgentSession(
        session_id=str(uuid.uuid4()),
        agent="claude-code",
        organization="test-org",
        user="alice",
        started_at=datetime.now(timezone.utc),
        state=SessionState.RESTRICTED if n >= 3 else SessionState.ACTIVE,
        risk_profile=rp,
    )


# =============================================================================
# INVARIANT 1: Hard rules — secrets in artifact ALWAYS block
# =============================================================================

class TestSecretsHardBlock:
    """
    Secrets detected in the release artifact must BLOCK unconditionally.
    No session score, no environment, no threshold can override this.
    """

    SECRET_CASES = [
        "AKIAIOSFODNN7EXAMPLE",                        # AWS key
        "ghp_abc123def456ghi789jkl012mno345pqr",       # GitHub token
        "-----BEGIN RSA PRIVATE KEY-----",             # Private key
        'api_key = "sk-abc123def456ghi789jkl"',        # Generic API key
        'password: "supersecret123"',                   # Password in config
    ]

    @pytest.mark.parametrize("secret", SECRET_CASES)
    def test_secret_in_artifact_blocks(self, secret: str) -> None:
        c = release_change(artifact=f"Release v1.0\n{secret}\nOther content here.")
        decision = evaluate_release(c, session=clean_session())
        assert decision.decision == Decision.BLOCK, (
            f"Expected BLOCK for secret={secret!r}, got {decision.decision}. "
            f"why_chain={decision.why_chain}"
        )

    @pytest.mark.parametrize("secret", SECRET_CASES)
    def test_secret_blocks_even_with_clean_session(self, secret: str) -> None:
        c = release_change(artifact=secret, environment="staging")
        decision = evaluate_release(c, session=clean_session())
        assert decision.decision == Decision.BLOCK

    @pytest.mark.parametrize("secret", SECRET_CASES)
    def test_secret_blocks_score_at_least_85(self, secret: str) -> None:
        c = release_change(artifact=secret)
        decision = evaluate_release(c, session=clean_session())
        assert decision.risk_score >= 85


# =============================================================================
# INVARIANT 2: Hard rules — 3+ violations in session ALWAYS block
# =============================================================================

class TestSessionViolationsHardBlock:
    """
    3 or more policy violations accumulated in the session must BLOCK the release,
    regardless of how clean the artifact looks.
    """

    @pytest.mark.parametrize("n_violations", [3, 4, 5, 10])
    def test_three_plus_violations_blocks_release(self, n_violations: int) -> None:
        c = release_change(artifact="Release notes: minor bugfixes.")
        session = session_with_violations(n_violations)
        decision = evaluate_release(c, session=session)
        assert decision.decision == Decision.BLOCK, (
            f"Expected BLOCK for {n_violations} violations, got {decision.decision}. "
            f"why_chain={decision.why_chain}"
        )

    @pytest.mark.parametrize("n_violations", [0, 1, 2])
    def test_fewer_than_three_violations_does_not_auto_block(
        self, n_violations: int
    ) -> None:
        c = release_change(artifact="Release notes: minor bugfixes.")
        session = session_with_violations(n_violations)
        decision = evaluate_release(c, session=session)
        # 0-2 violations should NOT trigger the hard block rule
        # (may still REVIEW or ALLOW depending on combined score)
        if decision.decision == Decision.BLOCK:
            # If BLOCK, it must NOT be due to the 3+ violations rule
            violation_block_fired = any(
                "3" in w and "violation" in w.lower()
                for w in decision.why_chain
            )
            assert not violation_block_fired, (
                f"3+ violations hard rule fired with only {n_violations} violations"
            )


# =============================================================================
# INVARIANT 3: Production target — minimum REVIEW
# =============================================================================

class TestProductionMinimumReview:
    """
    Any release targeting production must receive at least REVIEW.
    ALLOW is never acceptable for a production release.
    """

    def test_production_release_minimum_review(self) -> None:
        c = release_change(
            artifact="Release notes: minor bugfixes.",
            environment="production",
            affects_production=True,
        )
        decision = evaluate_release(c, session=clean_session())
        assert decision.decision in (Decision.REVIEW, Decision.BLOCK, Decision.ESCALATE), (
            f"Production release must not ALLOW, got {decision.decision}"
        )
        assert decision.decision != Decision.ALLOW

    def test_staging_release_can_allow(self) -> None:
        c = release_change(
            artifact="Release notes: minor bugfixes.",
            environment="staging",
            affects_production=False,
        )
        decision = evaluate_release(c, session=clean_session())
        assert decision.decision == Decision.ALLOW

    def test_local_release_can_allow(self) -> None:
        c = release_change(
            artifact="Release notes: minor bugfixes.",
            environment="local",
            affects_production=False,
        )
        decision = evaluate_release(c, session=clean_session())
        assert decision.decision == Decision.ALLOW


# =============================================================================
# INVARIANT 4: Session audit weighting — dirty session raises score
# =============================================================================

class TestSessionAuditWeighting:
    """
    The session audit (70% weight) must meaningfully raise the combined score
    when the session has accumulated risk. A dirty session with a clean artifact
    should score higher than a clean session with the same artifact.
    """

    def test_dirty_session_raises_combined_score(self) -> None:
        artifact = "Release notes: minor bugfixes."
        c_clean = release_change(artifact=artifact)
        c_dirty = release_change(artifact=artifact)

        decision_clean = evaluate_release(c_clean, session=clean_session())
        decision_dirty = evaluate_release(c_dirty, session=session_with_violations(2))

        assert decision_dirty.risk_score > decision_clean.risk_score, (
            f"Dirty session score ({decision_dirty.risk_score}) should exceed "
            f"clean session score ({decision_clean.risk_score})"
        )

    def test_no_session_treated_as_clean(self) -> None:
        """evaluate_release with session=None should not crash and treat as clean."""
        c = release_change(artifact="Release notes: minor bugfixes.")
        decision = evaluate_release(c, session=None)
        assert decision.decision in (Decision.ALLOW, Decision.REVIEW, Decision.BLOCK)
        assert 0 <= decision.risk_score <= 100

    def test_session_audit_score_from_session(self) -> None:
        session = session_with_violations(2)
        audit = SessionAudit.from_session(session)
        assert audit.score > 0
        assert audit.policy_violations == 2
        assert len(audit.why) > 0

    def test_clean_session_audit_score_is_zero(self) -> None:
        audit = SessionAudit.from_session(clean_session())
        assert audit.score == 0
        assert audit.policy_violations == 0


# =============================================================================
# INVARIANT 5: Artifact scan correctness
# =============================================================================

class TestArtifactScan:
    """
    ArtifactScan must correctly identify secrets and risk markers.
    """

    def test_clean_artifact_no_secrets(self) -> None:
        scan = ArtifactScan.from_payload(
            "Release v1.0.0: minor bugfixes and performance improvements.",
            diff_summary=None,
        )
        assert not scan.secrets_found
        assert scan.score == 0

    def test_aws_key_detected_as_secret(self) -> None:
        scan = ArtifactScan.from_payload(
            "Config: AKIAIOSFODNN7EXAMPLE",
            diff_summary=None,
        )
        assert scan.secrets_found

    def test_debug_mode_raises_score(self) -> None:
        scan = ArtifactScan.from_payload(
            "debug: true\nrelease notes here",
            diff_summary=None,
        )
        assert scan.score > 0

    def test_breaking_change_raises_score(self) -> None:
        scan = ArtifactScan.from_payload(
            "BREAKING CHANGE: removed deprecated API endpoint",
            diff_summary=None,
        )
        assert scan.score > 0

    def test_diff_summary_scanned_too(self) -> None:
        """Secrets in diff_summary must also be detected."""
        scan = ArtifactScan.from_payload(
            "Release notes: minor bugfixes.",
            diff_summary="AKIAIOSFODNN7EXAMPLE added to config",
        )
        assert scan.secrets_found


# =============================================================================
# INVARIANT 6: Strictest decision wins
# =============================================================================

class TestDecisionInvariants:
    """Structural guarantees on every GovernanceDecision from release_gate."""

    def test_why_chain_never_empty(self) -> None:
        c = release_change()
        decision = evaluate_release(c, session=clean_session())
        assert len(decision.why_chain) > 0

    def test_score_always_in_bounds(self) -> None:
        cases = [
            (release_change(), clean_session()),
            (release_change(artifact="AKIAIOSFODNN7EXAMPLE"), clean_session()),
            (release_change(), session_with_violations(5)),
            (release_change(affects_production=True, environment="production"), clean_session()),
        ]
        for c, session in cases:
            decision = evaluate_release(c, session=session)
            assert 0 <= decision.risk_score <= 100, (
                f"Score out of bounds: {decision.risk_score}"
            )

    def test_action_id_in_decision(self) -> None:
        c = release_change()
        decision = evaluate_release(c, session=clean_session())
        assert decision.action_id == c.action_id

    def test_block_has_high_band(self) -> None:
        c = release_change(artifact="AKIAIOSFODNN7EXAMPLE")
        decision = evaluate_release(c, session=clean_session())
        assert decision.decision == Decision.BLOCK
        assert decision.band in (RiskBand.CRITICAL, RiskBand.HIGH)

    def test_allow_has_low_band(self) -> None:
        c = release_change(
            artifact="Release notes: minor bugfixes.",
            environment="local",
        )
        decision = evaluate_release(c, session=clean_session())
        assert decision.decision == Decision.ALLOW
        assert decision.band in (RiskBand.LOW, RiskBand.MINIMAL)
