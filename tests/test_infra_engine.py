"""
tests/test_infra_engine.py — DevMind Agent Governance
Invariant tests for the infrastructure governance engine.

These tests encode the behavioral guarantees of infra_engine.
If any of these fail, the infrastructure governance layer is broken.

Run: pytest tests/ -v (from devmind/ root with PYTHONPATH=devmind/devmind)
"""

import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "devmind"))

from core.types import (
    ActionSurface,
    AgentChange,
    ActionContext,
    BlastRadius,
    ChangeImpact,
    ChangeType,
    Decision,
    RiskBand,
)
from engines.infra_engine import evaluate_change
from engines.k8s_semantic import parse_k8s_manifest


# =============================================================================
# Helpers
# =============================================================================

def change(
    change_type: ChangeType = ChangeType.TERRAFORM_APPLY,
    surface: ActionSurface = ActionSurface.INFRASTRUCTURE,
    payload: str = "resource \"aws_s3_bucket\" \"safe\" {}",
    environment: str = "local",
    affects_production: bool = False,
    blast_radius: BlastRadius = BlastRadius.SERVICE,
    session_id: str | None = None,
) -> AgentChange:
    return AgentChange(
        action_id=str(uuid.uuid4()),
        session_id=session_id or str(uuid.uuid4()),
        agent="claude-code",
        change_type=change_type,
        surface=surface,
        payload=payload,
        timestamp=datetime.now(timezone.utc),
        impact=ChangeImpact(
            affects_production=affects_production,
            blast_radius=blast_radius,
        ),
        context=ActionContext(environment=environment),
    )


# =============================================================================
# INVARIANT 1: Hard blocks — critical signals always BLOCK regardless of env
# =============================================================================

class TestHardBlocks:
    """
    These payloads must produce BLOCK regardless of environment or blast radius.
    They represent non-overridable critical signals.
    """

    HARD_BLOCK_CASES = [
        # Hardcoded secrets
        ('password = "supersecret123"',           ChangeType.TERRAFORM_APPLY),
        ('api_key = "sk-abc123def456ghi789"',     ChangeType.TERRAFORM_APPLY),
        # IAM wildcard action
        ('Action = "*"',                           ChangeType.TERRAFORM_APPLY),
        ('Action = ["*"]',                         ChangeType.IAM_CHANGE),
        ('"Action": "*"',                          ChangeType.TERRAFORM_APPLY),
        # IAM wildcard resource
        ('Resource = "*"',                         ChangeType.TERRAFORM_APPLY),
        # IAM admin policy
        ('AdministratorAccess',                    ChangeType.IAM_CHANGE),
        ('arn:aws:iam::aws:policy/AdministratorAccess', ChangeType.TERRAFORM_APPLY),
    ]

    @pytest.mark.parametrize("payload,change_type", HARD_BLOCK_CASES)
    def test_always_blocked(self, payload: str, change_type: ChangeType) -> None:
        c = change(change_type=change_type, payload=payload, environment="local")
        decision = evaluate_change(c)
        assert decision.decision == Decision.BLOCK, (
            f"Expected BLOCK for payload={payload!r}, got {decision.decision}. "
            f"why_chain: {decision.why_chain}"
        )

    @pytest.mark.parametrize("payload,change_type", HARD_BLOCK_CASES)
    def test_hard_block_score_at_least_85(self, payload: str, change_type: ChangeType) -> None:
        c = change(change_type=change_type, payload=payload)
        decision = evaluate_change(c)
        assert decision.risk_score >= 85, (
            f"Hard block score should be >=85, got {decision.risk_score}"
        )

    @pytest.mark.parametrize("payload,change_type", HARD_BLOCK_CASES)
    def test_why_chain_never_empty(self, payload: str, change_type: ChangeType) -> None:
        c = change(change_type=change_type, payload=payload)
        decision = evaluate_change(c)
        assert len(decision.why_chain) > 0

    def test_hardcoded_secret_blocked_in_local(self) -> None:
        """Secrets are blocked even outside production — artifact is dangerous regardless."""
        c = change(
            payload='token = "ghp_abc123def456ghi789jkl"',
            environment="local",
            affects_production=False,
        )
        decision = evaluate_change(c)
        assert decision.decision == Decision.BLOCK


# =============================================================================
# INVARIANT 2: Blast radius gate — ORG/ACCOUNT always ESCALATE
# =============================================================================

class TestBlastRadiusGate:
    """
    ORG and ACCOUNT level changes must always ESCALATE — no score override.
    Even a safe-looking payload with ORG blast radius must be escalated.
    """

    @pytest.mark.parametrize("blast_radius", [BlastRadius.ORG, BlastRadius.ACCOUNT])
    def test_org_account_always_escalate(self, blast_radius: BlastRadius) -> None:
        c = change(
            payload="resource \"aws_s3_bucket\" \"safe\" {}",
            blast_radius=blast_radius,
            affects_production=False,
        )
        decision = evaluate_change(c)
        assert decision.decision == Decision.ESCALATE, (
            f"Expected ESCALATE for blast_radius={blast_radius}, got {decision.decision}"
        )

    @pytest.mark.parametrize("blast_radius", [BlastRadius.PROCESS, BlastRadius.SERVICE])
    def test_low_blast_radius_not_auto_escalated(self, blast_radius: BlastRadius) -> None:
        """PROCESS/SERVICE blast radius with safe payload should NOT escalate."""
        c = change(
            payload="resource \"aws_s3_bucket\" \"safe\" {}",
            blast_radius=blast_radius,
            affects_production=False,
        )
        decision = evaluate_change(c)
        assert decision.decision != Decision.ESCALATE

    def test_org_blast_radius_overrides_low_score(self) -> None:
        """ORG blast radius must ESCALATE even if risk score would be 0."""
        c = change(
            payload="resource \"aws_s3_bucket\" \"safe\" {}",
            blast_radius=BlastRadius.ORG,
        )
        decision = evaluate_change(c)
        assert decision.decision == Decision.ESCALATE
        assert decision.escalate_to is not None


# =============================================================================
# INVARIANT 3: Production escalation — critical signal + prod = BLOCK
# =============================================================================

class TestProductionEscalation:
    """
    Critical signal + affects_production must produce BLOCK unconditionally.
    No exceptions, no score threshold override.
    """

    CRITICAL_PROD_CASES = [
        # privileged container in prod
        ("privileged: true", ChangeType.K8S_MANIFEST, ActionSurface.KUBERNETES),
        # open security group in prod
        ('cidr_blocks = ["0.0.0.0/0"]', ChangeType.TERRAFORM_APPLY, ActionSurface.INFRASTRUCTURE),
        # public S3 in prod
        ('acl = "public-read"', ChangeType.TERRAFORM_APPLY, ActionSurface.INFRASTRUCTURE),
        # cluster-admin in prod
        ("cluster-admin", ChangeType.K8S_MANIFEST, ActionSurface.KUBERNETES),
    ]

    @pytest.mark.parametrize("payload,change_type,surface", CRITICAL_PROD_CASES)
    def test_critical_signal_plus_prod_is_block(
        self, payload: str, change_type: ChangeType, surface: ActionSurface
    ) -> None:
        c = change(
            change_type=change_type,
            surface=surface,
            payload=payload,
            affects_production=True,
            environment="production",
        )
        decision = evaluate_change(c)
        assert decision.decision == Decision.BLOCK, (
            f"Expected BLOCK for critical signal in prod, got {decision.decision}. "
            f"payload={payload!r}, why_chain={decision.why_chain}"
        )

    @pytest.mark.parametrize("payload,change_type,surface", CRITICAL_PROD_CASES)
    def test_critical_signal_without_prod_not_auto_blocked_by_prod_gate(
        self, payload: str, change_type: ChangeType, surface: ActionSurface
    ) -> None:
        """
        Critical signals without prod flag go through hard block check first.
        Those that are NOT in the hard-block list (e.g. privileged container,
        open security group) should still score high but via threshold, not prod gate.
        This test validates the prod gate is specifically conditional on affects_production.
        """
        c = change(
            change_type=change_type,
            surface=surface,
            payload=payload,
            affects_production=False,
            environment="staging",
        )
        decision = evaluate_change(c)
        # Still high risk but the prod escalation gate specifically didn't fire
        # (it may still BLOCK via threshold or hard block — that's fine)
        assert decision.decision in (Decision.BLOCK, Decision.REVIEW, Decision.ALLOW)
        # The important thing: if it's BLOCK, it's not due to "prod escalation"
        if decision.decision == Decision.BLOCK:
            prod_gate_fired = any("prod" in w.lower() and "escalation" in w.lower()
                                  for w in decision.why_chain)
            assert not prod_gate_fired, (
                f"Production escalation gate fired without affects_production=True"
            )


# =============================================================================
# INVARIANT 4: Production minimum REVIEW for SERVICE/CLUSTER blast radius
# =============================================================================

class TestProductionMinimumReview:
    """
    Production changes with SERVICE or CLUSTER blast radius must get at least REVIEW,
    even if the risk score would otherwise be low.
    """

    @pytest.mark.parametrize("blast_radius", [BlastRadius.SERVICE, BlastRadius.CLUSTER])
    def test_prod_service_cluster_minimum_review(self, blast_radius: BlastRadius) -> None:
        c = change(
            payload="resource \"aws_s3_bucket\" \"safe\" {}",
            affects_production=True,
            blast_radius=blast_radius,
            environment="production",
        )
        decision = evaluate_change(c)
        assert decision.decision in (Decision.REVIEW, Decision.BLOCK, Decision.ESCALATE), (
            f"Production {blast_radius.value} change must get at least REVIEW, "
            f"got {decision.decision}"
        )
        assert decision.decision != Decision.ALLOW

    def test_prod_process_blast_can_allow(self) -> None:
        """PROCESS blast radius in prod with safe payload may be ALLOW."""
        c = change(
            payload="resource \"aws_s3_bucket\" \"safe\" {}",
            affects_production=True,
            blast_radius=BlastRadius.PROCESS,
            environment="production",
        )
        decision = evaluate_change(c)
        # PROCESS blast radius has no minimum REVIEW — low score + no signals = ALLOW
        assert decision.decision in (Decision.ALLOW, Decision.REVIEW, Decision.BLOCK)


# =============================================================================
# INVARIANT 5: Safe Terraform/K8s/Helm payloads are ALLOW
# =============================================================================

class TestSafeChanges:
    """
    Benign infrastructure changes should not be blocked or reviewed.
    """

    SAFE_CASES = [
        ('resource "aws_s3_bucket" "logs" { bucket = "company-logs" }',
         ChangeType.TERRAFORM_APPLY, ActionSurface.INFRASTRUCTURE),
        ("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app",
         ChangeType.K8S_MANIFEST, ActionSurface.KUBERNETES),
        ("replicas: 2\nimage:\n  tag: v1.2.3",
         ChangeType.HELM_RELEASE, ActionSurface.KUBERNETES),
    ]

    @pytest.mark.parametrize("payload,change_type,surface", SAFE_CASES)
    def test_safe_change_is_allowed(
        self, payload: str, change_type: ChangeType, surface: ActionSurface
    ) -> None:
        c = change(
            change_type=change_type,
            surface=surface,
            payload=payload,
            affects_production=False,
            environment="local",
        )
        decision = evaluate_change(c)
        assert decision.decision == Decision.ALLOW, (
            f"Expected ALLOW for safe payload, got {decision.decision}. "
            f"why_chain={decision.why_chain}"
        )

    @pytest.mark.parametrize("payload,change_type,surface", SAFE_CASES)
    def test_safe_change_low_score(
        self, payload: str, change_type: ChangeType, surface: ActionSurface
    ) -> None:
        c = change(
            change_type=change_type,
            surface=surface,
            payload=payload,
            affects_production=False,
        )
        decision = evaluate_change(c)
        assert decision.risk_score < 30


# =============================================================================
# INVARIANT 6: Kubernetes-specific signals fire on K8s, not on Terraform
# =============================================================================

class TestSurfaceIsolation:
    """
    K8s signals must not fire on Terraform payloads and vice versa.
    Surface isolation prevents cross-surface false positives.
    """

    def test_privileged_container_fires_on_k8s(self) -> None:
        c = change(
            change_type=ChangeType.K8S_MANIFEST,
            surface=ActionSurface.KUBERNETES,
            payload="securityContext:\n  privileged: true",
        )
        decision = evaluate_change(c)
        signal_names = [s["name"] for s in decision.signals]
        assert "privileged_container" in signal_names

    def test_privileged_container_does_not_fire_on_terraform(self) -> None:
        c = change(
            change_type=ChangeType.TERRAFORM_APPLY,
            surface=ActionSurface.INFRASTRUCTURE,
            payload="securityContext:\n  privileged: true",
        )
        decision = evaluate_change(c)
        signal_names = [s["name"] for s in decision.signals]
        assert "privileged_container" not in signal_names

    def test_iam_wildcard_fires_on_terraform(self) -> None:
        c = change(
            change_type=ChangeType.TERRAFORM_APPLY,
            surface=ActionSurface.INFRASTRUCTURE,
            payload='Action = "*"',
        )
        decision = evaluate_change(c)
        signal_names = [s["name"] for s in decision.signals]
        assert "iam_wildcard_action" in signal_names

    def test_iam_wildcard_does_not_fire_on_k8s(self) -> None:
        c = change(
            change_type=ChangeType.K8S_MANIFEST,
            surface=ActionSurface.KUBERNETES,
            payload='Action = "*"',
        )
        decision = evaluate_change(c)
        signal_names = [s["name"] for s in decision.signals]
        assert "iam_wildcard_action" not in signal_names


# =============================================================================
# Kubernetes semantic parsing: structured PSS classification with regex fallback
# =============================================================================

class TestTerraformSemanticParsing:
    def test_compute_instance_delete_emits_compute_scope_signal(self) -> None:
        plan_json = json.dumps({
            "format_version": "1.2",
            "terraform_version": "1.9.8",
            "resource_changes": [
                {
                    "address": "aws_instance.payments_api",
                    "mode": "managed",
                    "type": "aws_instance",
                    "name": "payments_api",
                    "change": {"actions": ["delete"]},
                }
            ],
        })
        decision = evaluate_change(change(
            change_type=ChangeType.TERRAFORM_APPLY,
            surface=ActionSurface.INFRASTRUCTURE,
            payload=plan_json,
        ))
        signal = next(
            item for item in decision.signals
            if item["name"] == "semantic_compute_scope_delete"
        )
        assert 35 <= signal["severity"] <= 45

    def test_lambda_function_delete_emits_compute_scope_signal(self) -> None:
        plan_json = json.dumps({
            "format_version": "1.2",
            "terraform_version": "1.9.8",
            "resource_changes": [
                {
                    "address": "aws_lambda_function.payment_processor",
                    "mode": "managed",
                    "type": "aws_lambda_function",
                    "name": "payment_processor",
                    "change": {"actions": ["delete"]},
                }
            ],
        })
        decision = evaluate_change(change(
            change_type=ChangeType.TERRAFORM_APPLY,
            surface=ActionSurface.INFRASTRUCTURE,
            payload=plan_json,
        ))
        signal = next(
            item for item in decision.signals
            if item["name"] == "semantic_compute_scope_delete"
        )
        assert 35 <= signal["severity"] <= 45

    def test_unclassified_resource_still_uses_low_weight_fallback(self) -> None:
        plan_json = json.dumps({
            "format_version": "1.2",
            "terraform_version": "1.9.8",
            "resource_changes": [
                {
                    "address": "local_file.scratch",
                    "mode": "managed",
                    "type": "local_file",
                    "name": "scratch",
                    "change": {"actions": ["delete"]},
                }
            ],
        })
        decision = evaluate_change(change(
            change_type=ChangeType.TERRAFORM_APPLY,
            surface=ActionSurface.INFRASTRUCTURE,
            payload=plan_json,
        ))
        signal = next(
            item for item in decision.signals
            if item["name"] == "semantic_unclassified_delete"
        )
        assert signal["severity"] == 10


class TestKubernetesSemanticParsing:
    def test_privileged_container_emits_high_baseline_signal(self) -> None:
        payload = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: unsafe-app
spec:
  template:
    spec:
      containers:
        - name: app
          image: registry.example/app:v1
          securityContext:
            privileged: true
"""
        decision = evaluate_change(change(
            change_type=ChangeType.K8S_MANIFEST,
            surface=ActionSurface.KUBERNETES,
            payload=payload,
        ))

        signal = next(
            item for item in decision.signals
            if item["name"] == "semantic_k8s_baseline_privileged_container"
        )
        assert 35 <= signal["severity"] <= 45

    def test_clean_manifest_emits_no_semantic_signals(self) -> None:
        payload = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: clean-app
spec:
  template:
    spec:
      containers:
        - name: app
          image: registry.example/app:v1
          securityContext:
            allowPrivilegeEscalation: false
            runAsNonRoot: true
            runAsUser: 1000
            capabilities:
              drop:
                - ALL
            seccompProfile:
              type: RuntimeDefault
"""
        decision = evaluate_change(change(
            change_type=ChangeType.K8S_MANIFEST,
            surface=ActionSurface.KUBERNETES,
            payload=payload,
        ))

        assert not [
            item for item in decision.signals
            if item["name"].startswith("semantic_k8s_")
        ]

    def test_invalid_yaml_falls_back_silently_to_regex(self) -> None:
        payload = """\
apiVersion: v1
kind: Pod
metadata: [broken
spec:
  containers:
    - name: unsafe
      securityContext:
        privileged: true
"""
        assert parse_k8s_manifest(payload) is None

        decision = evaluate_change(change(
            change_type=ChangeType.K8S_MANIFEST,
            surface=ActionSurface.KUBERNETES,
            payload=payload,
        ))
        signal_names = [item["name"] for item in decision.signals]
        assert "privileged_container" in signal_names
        assert not any("Kubernetes Pod/Deployment YAML detected" in step for step in decision.why_chain)


# =============================================================================
# INVARIANT 7: Strictest decision wins / score bounds
# =============================================================================

class TestDecisionInvariants:
    """Structural guarantees on every GovernanceDecision from infra_engine."""

    def test_why_chain_never_empty(self) -> None:
        c = change(payload="resource \"aws_s3_bucket\" \"safe\" {}")
        decision = evaluate_change(c)
        assert len(decision.why_chain) > 0

    def test_score_always_in_bounds(self) -> None:
        payloads = [
            'resource "aws_s3_bucket" "safe" {}',
            'Action = "*"\nResource = "*"\nAdministratorAccess',
            'privileged: true\nhostNetwork: true\nrunAsUser: 0',
        ]
        for payload in payloads:
            c = change(payload=payload)
            decision = evaluate_change(c)
            assert 0 <= decision.risk_score <= 100, (
                f"Score out of bounds: {decision.risk_score} for payload={payload!r}"
            )

    def test_action_id_in_decision(self) -> None:
        c = change(payload="resource \"aws_s3_bucket\" \"safe\" {}")
        decision = evaluate_change(c)
        assert decision.action_id == c.action_id

    def test_block_band_is_critical_or_high(self) -> None:
        c = change(payload='Action = "*"')
        decision = evaluate_change(c)
        assert decision.decision == Decision.BLOCK
        assert decision.band in (RiskBand.CRITICAL, RiskBand.HIGH)

    def test_allow_band_is_low_or_minimal(self) -> None:
        c = change(payload='resource "aws_s3_bucket" "safe" {}')
        decision = evaluate_change(c)
        assert decision.decision == Decision.ALLOW
        assert decision.band in (RiskBand.LOW, RiskBand.MINIMAL)


# =============================================================================
# REGRESSION: 330962a — iam_service_wildcard_action in infra_engine.py.
# infra_engine.py maintains its own SEPARATE _SIGNALS tuple from
# policy_engine.py (undocumented duplication, tracked as tech debt) --
# this signal was independently missing here even after policy_engine.py's
# equivalent (iam_service_wildcard) was fixed, since this file never shared
# the fix. Service-scoped IAM wildcards (e.g. s3:*) previously had zero
# coverage in this engine.
# =============================================================================

class TestIamServiceWildcardActionRegression330962a:

    def test_service_scoped_wildcard_fires_on_terraform_json(self) -> None:
        c = change(
            change_type=ChangeType.TERRAFORM_APPLY,
            surface=ActionSurface.INFRASTRUCTURE,
            payload='"Action": "s3:*"',
        )
        decision = evaluate_change(c)
        signal_names = [s["name"] for s in decision.signals]
        assert "iam_service_wildcard_action" in signal_names, (
            f"REGRESSION: iam_service_wildcard_action did not fire, signals={decision.signals}"
        )
        assert decision.decision in (Decision.BLOCK, Decision.REVIEW), decision.decision

    def test_service_scoped_wildcard_fires_on_terraform_hcl(self) -> None:
        c = change(
            change_type=ChangeType.TERRAFORM_APPLY,
            surface=ActionSurface.INFRASTRUCTURE,
            payload='Action = "s3:*"',
        )
        decision = evaluate_change(c)
        signal_names = [s["name"] for s in decision.signals]
        assert "iam_service_wildcard_action" in signal_names, (
            f"REGRESSION: iam_service_wildcard_action did not fire, signals={decision.signals}"
        )

    def test_bare_wildcard_still_fires_iam_wildcard_action_not_confused_with_service_scoped(self) -> None:
        """A bare Action = "*" should still fire the pre-existing
        iam_wildcard_action signal (not silently replaced by the new one)."""
        c = change(
            change_type=ChangeType.TERRAFORM_APPLY,
            surface=ActionSurface.INFRASTRUCTURE,
            payload='Action = "*"',
        )
        decision = evaluate_change(c)
        signal_names = [s["name"] for s in decision.signals]
        assert "iam_wildcard_action" in signal_names
        assert "iam_service_wildcard_action" not in signal_names
