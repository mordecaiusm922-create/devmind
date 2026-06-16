"""
engines/release_gate.py — DevMind Agent Governance
Release gate: governs RELEASE_PUBLISH / RELEASE_PROMOTE changes.

Entry point: evaluate_release(change: AgentChange, session: AgentSession) -> GovernanceDecision

Core logic:
    - SessionAudit.from_session(session) builds a 0-100 risk score from the
      session's accumulated risk_profile (70% weight of final score).
    - Artifact scan reuses infra-style + secret signals against the release
      payload/diff_summary (30% weight).
    - Hard rule: secrets detected in the artifact -> BLOCK always.
    - Hard rule: 3+ policy_violations in session -> BLOCK always.
    - Production target -> minimum REVIEW.
    - Strictest decision wins: BLOCK > ESCALATE > REVIEW > ALLOW.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass

from core.types import (
    AgentChange,
    AgentSession,
    Decision,
    GovernanceDecision,
    RiskBand,
)


# =============================================================================
# Artifact scan signals — secrets and dangerous content in release artifacts
# =============================================================================

_ARTIFACT_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'),
    re.compile(r'\bgh[pousr]_[A-Za-z0-9_]{20,}\b'),
    re.compile(r'(?i)(api[_-]?key|secret|password|private[_-]?key|token)'
               r'(\s*[:=]\s*["\']?)[^\s"\']{8,}'),
    re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
)

_ARTIFACT_RISK_PATTERNS: tuple[tuple[str, int, re.Pattern[str]], ...] = (
    ("debug_mode_enabled", 15, re.compile(r'(?i)debug\s*[:=]\s*true')),
    ("disabled_auth", 30, re.compile(r'(?i)(auth|authentication)\s*[:=]\s*(false|disabled|none)')),
    ("wildcard_cors", 20, re.compile(r'(?i)Access-Control-Allow-Origin\s*[:=]\s*["\']?\*')),
    ("version_downgrade_marker", 10, re.compile(r'(?i)\bdowngrade\b')),
    ("breaking_change_marker", 15, re.compile(r'(?i)\bBREAKING[\s_-]?CHANGE\b')),
)


# =============================================================================
# SessionAudit — derives a 0-100 score from accumulated session risk
# =============================================================================

@dataclass
class SessionAudit:
    """
    Score derived from a session's accumulated SessionRiskProfile.

    Weighting rationale: a release is the sum of everything the agent did
    in the session. If the agent violated policy repeatedly before
    preparing the release, that pattern matters more than the artifact
    itself — hence this carries 70% of the final release-gate score.
    """
    score: int
    policy_violations: int
    blocked_actions: int
    escalated_actions: int
    peak_score: int
    why: list[str]

    @classmethod
    def from_session(cls, session: AgentSession | None) -> "SessionAudit":
        if session is None:
            return cls(
                score=0,
                policy_violations=0,
                blocked_actions=0,
                escalated_actions=0,
                peak_score=0,
                why=["No session history available — treated as clean (score 0)."],
            )

        rp = session.risk_profile
        why: list[str] = []

        # Base score: cumulative average risk across the session
        score = int(round(rp.cumulative_score))
        why.append(f"Session cumulative average risk: {rp.cumulative_score:.1f}")

        # Penalty for policy violations — each violation adds weight
        violation_penalty = rp.policy_violations * 15
        if violation_penalty:
            score += violation_penalty
            why.append(
                f"{rp.policy_violations} policy violation(s) "
                f"-> +{violation_penalty} session penalty"
            )

        # Penalty for escalations — these are the most severe session events
        escalation_penalty = rp.escalated_actions * 20
        if escalation_penalty:
            score += escalation_penalty
            why.append(
                f"{rp.escalated_actions} escalated action(s) "
                f"-> +{escalation_penalty} session penalty"
            )

        # Peak score acts as a floor — a session that ever hit a high peak
        # carries that risk into the release decision.
        if rp.peak_score > score:
            why.append(
                f"Session peak risk score {rp.peak_score} exceeds running "
                f"total {score} -> using peak as floor"
            )
            score = rp.peak_score

        score = min(score, 100)

        return cls(
            score=score,
            policy_violations=rp.policy_violations,
            blocked_actions=rp.blocked_actions,
            escalated_actions=rp.escalated_actions,
            peak_score=rp.peak_score,
            why=why,
        )


# =============================================================================
# Artifact scan
# =============================================================================

@dataclass
class ArtifactScan:
    score: int
    secrets_found: bool
    why: list[str]

    @classmethod
    def from_payload(cls, payload: str, diff_summary: str | None) -> "ArtifactScan":
        text = payload + ("\n" + diff_summary if diff_summary else "")
        why: list[str] = []
        score = 0
        secrets_found = False

        for pattern in _ARTIFACT_SECRET_PATTERNS:
            if pattern.search(text):
                secrets_found = True
                why.append("Secret pattern detected in release artifact")
                break

        for name, weight, pattern in _ARTIFACT_RISK_PATTERNS:
            if pattern.search(text):
                score += weight
                why.append(f"Artifact signal matched: {name} (+{weight})")

        score = min(score, 100)

        if not why:
            why.append("No risk signals detected in artifact.")

        return cls(score=score, secrets_found=secrets_found, why=why)


# =============================================================================
# Risk band mapping (shared convention with infra_engine)
# =============================================================================

def _band_for_score(score: int) -> RiskBand:
    if score >= 85:
        return RiskBand.CRITICAL
    if score >= 60:
        return RiskBand.HIGH
    if score >= 30:
        return RiskBand.MEDIUM
    if score >= 10:
        return RiskBand.LOW
    return RiskBand.MINIMAL


# =============================================================================
# Primary entry point
# =============================================================================

def evaluate_release(
    change: AgentChange,
    session: AgentSession | None = None,
) -> GovernanceDecision:
    """
    Evaluate a RELEASE_PUBLISH / RELEASE_PROMOTE AgentChange.

    Weighting: 70% session audit + 30% artifact scan -> combined_score.
    Hard rules override the weighted score:
        - secrets in artifact            -> BLOCK
        - 3+ policy_violations in session -> BLOCK
        - production target               -> minimum REVIEW

    Strictest decision wins: BLOCK > ESCALATE > REVIEW > ALLOW.
    """
    why_chain: list[str] = []
    why_chain.append(
        f"Evaluating release: {change.change_type.value} "
        f"(artifact_ref={change.artifact_ref or 'n/a'})"
    )

    audit = SessionAudit.from_session(session)
    why_chain.extend(f"[session] {w}" for w in audit.why)

    scan = ArtifactScan.from_payload(change.payload, change.diff_summary)
    why_chain.extend(f"[artifact] {w}" for w in scan.why)

    combined_score = int(round(0.70 * audit.score + 0.30 * scan.score))
    why_chain.append(
        f"Combined score: 0.70 * session({audit.score}) + "
        f"0.30 * artifact({scan.score}) = {combined_score}"
    )

    candidates: list[tuple[Decision, int, str]] = []

    # ---- Hard rule: secrets in artifact -----------------------------------
    if scan.secrets_found:
        why_chain.append("Hard rule: secrets detected in artifact -> BLOCK")
        candidates.append((
            Decision.BLOCK,
            max(combined_score, 90),
            "Release artifact contains exposed secrets. Blocked unconditionally.",
        ))

    # ---- Hard rule: 3+ policy violations in session -----------------------
    if audit.policy_violations >= 3:
        why_chain.append(
            f"Hard rule: {audit.policy_violations} policy violations "
            f"(>=3) in session -> BLOCK"
        )
        candidates.append((
            Decision.BLOCK,
            max(combined_score, 85),
            (
                f"Session accumulated {audit.policy_violations} policy "
                f"violations before this release. Blocked unconditionally."
            ),
        ))

    # ---- Production target -> minimum REVIEW -------------------------------
    if change.impact.affects_production:
        why_chain.append("Production target -> minimum REVIEW")
        candidates.append((
            Decision.REVIEW,
            max(combined_score, 30),
            "Release targets production. Minimum REVIEW applies.",
        ))

    # ---- Threshold decision from combined score ----------------------------
    if combined_score >= 85:
        candidates.append((
            Decision.BLOCK,
            combined_score,
            f"Combined release risk score {combined_score}/100 exceeds BLOCK threshold (85).",
        ))
    elif combined_score >= 30:
        candidates.append((
            Decision.REVIEW,
            combined_score,
            f"Combined release risk score {combined_score}/100 exceeds REVIEW threshold (30).",
        ))
    else:
        candidates.append((
            Decision.ALLOW,
            combined_score,
            f"Combined release risk score {combined_score}/100 within acceptable bounds.",
        ))

    # ---- Strictest decision wins --------------------------------------------
    _STRICTNESS = {Decision.BLOCK: 3, Decision.ESCALATE: 2, Decision.REVIEW: 1, Decision.ALLOW: 0}
    final_decision, final_score, final_reason = max(
        candidates, key=lambda c: _STRICTNESS[c[0]]
    )

    why_chain.append(
        f"Strictest decision among {[c[0].value for c in candidates]} "
        f"-> {final_decision.value}"
    )

    return GovernanceDecision(
        action_id=change.action_id or str(uuid.uuid4()),
        decision=final_decision,
        risk_score=min(final_score, 100),
        band=_band_for_score(min(final_score, 100)),
        surface=change.surface,
        why_chain=why_chain,
        reason=final_reason,
        signals=[],
        escalate_to=None,
    )