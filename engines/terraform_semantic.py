"""
engines/terraform_semantic.py -- DevMind Agent Governance
Semantic parser for `terraform plan -json` output.

This module is additive: it never replaces the existing regex-based
_SIGNALS in infra_engine.py. It runs BEFORE them, only activates when
change.payload is valid JSON matching Terraform's plan schema, and
produces the same (name, weight, surface, matched) signal shape so it
merges into the existing scoring path with zero changes to evaluate_change's
control flow.

Why this exists: regex over a payload string can't distinguish
"resource aws_ebs_volume production-db { destroy = true }" (a string
someone typed) from an actual `terraform plan -json` showing that
resource will genuinely be destroyed. This parser reads the real
plan structure Terraform itself produces, which cannot lie about
what actions it's about to take.

Reference: https://developer.hashicorp.com/terraform/internals/json-format
"""

from __future__ import annotations

import json
from typing import Any


# =============================================================================
# Resource type -> blast radius / severity implications
# Taxonomy informed by terraform-aws-eks-blueprints resource usage patterns.
# =============================================================================

# Resources holding persistent data. A "delete" action here is categorically
# more dangerous than a delete on a stateless resource (e.g. a security group
# rule) because data loss is often irreversible.
_DATA_PERSISTENCE_RESOURCES: frozenset[str] = frozenset({
    "aws_ebs_volume",
    "aws_efs_file_system",
    "aws_rds_cluster",
    "aws_rds_instance",
    "aws_db_instance",
    "aws_s3_bucket",
    "aws_dynamodb_table",
    "aws_elasticache_cluster",
    "aws_redshift_cluster",
    "google_sql_database_instance",
    "google_storage_bucket",
    "azurerm_storage_account",
    "azurerm_sql_database",
})

# Resources that define identity/access scope. Changes here can silently
# widen blast radius for everything else in the account.
_IAM_SCOPE_RESOURCES: frozenset[str] = frozenset({
    "aws_iam_role",
    "aws_iam_policy",
    "aws_iam_role_policy_attachment",
    "aws_iam_user",
    "aws_iam_group",
    "google_project_iam_binding",
    "google_project_iam_member",
    "azurerm_role_assignment",
})

# Resources defining network exposure boundaries.
_NETWORK_SCOPE_RESOURCES: frozenset[str] = frozenset({
    "aws_security_group",
    "aws_security_group_rule",
    "aws_vpc",
    "aws_subnet",
    "aws_route_table",
    "aws_internet_gateway",
    "google_compute_firewall",
    "azurerm_network_security_group",
})

# Resources defining cluster/compute scope (EKS, GKE, node groups).
_CLUSTER_SCOPE_RESOURCES: frozenset[str] = frozenset({
    "aws_eks_cluster",
    "aws_eks_node_group",
    "google_container_cluster",
    "azurerm_kubernetes_cluster",
    "helm_release",
})

# Resources representing individual compute or serverless workloads.
# A "delete" here can take a production service offline as decisively
# as deleting a database -- EC2 instances, Lambda functions, and ECS
# services running production traffic are not "safer to delete" just
# because they are not literally a database.
_COMPUTE_SCOPE_RESOURCES: frozenset[str] = frozenset({
    "aws_instance",
    "aws_lambda_function",
    "aws_ecs_service",
    "aws_ecs_task_definition",
    "aws_autoscaling_group",
    "google_compute_instance",
    "azurerm_linux_virtual_machine",
    "azurerm_virtual_machine",
})

# Terraform plan action verbs that indicate destructive intent.
_DESTRUCTIVE_ACTIONS: frozenset[str] = frozenset({"delete"})
_REPLACE_ACTIONS: frozenset[str] = frozenset({"create", "delete"})  # replace = both


def _resource_category(resource_type: str) -> str | None:
    """Classify a Terraform resource type into a risk category, or None if unclassified."""
    if resource_type in _DATA_PERSISTENCE_RESOURCES:
        return "data_persistence"
    if resource_type in _IAM_SCOPE_RESOURCES:
        return "iam_scope"
    if resource_type in _NETWORK_SCOPE_RESOURCES:
        return "network_scope"
    if resource_type in _CLUSTER_SCOPE_RESOURCES:
        return "cluster_scope"
    if resource_type in _COMPUTE_SCOPE_RESOURCES:
        return "compute_scope"
    return None


def parse_terraform_plan(payload: str) -> dict[str, Any] | None:
    """
    Attempt to parse payload as `terraform plan -json` output.

    Returns None if payload is not valid JSON or doesn't match the
    expected plan schema (no "resource_changes" key) -- signaling the
    caller to fall back to regex-based evaluation instead.
    """
    try:
        data = json.loads(payload)
    except (json.JSONDecodeError, TypeError):
        return None

    if not isinstance(data, dict) or "resource_changes" not in data:
        return None

    return data


def extract_semantic_signals(plan: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Walk a parsed terraform plan and produce signals with the same shape
    as infra_engine._SIGNALS matches: {"name", "severity", "surface"}.

    Unlike regex signals, these are derived from Terraform's own
    structured description of what it's about to do -- not from
    pattern-matching a string that might be typed by a human or an
    agent and might not reflect the real plan at all.
    """
    signals: list[dict[str, Any]] = []

    for rc in plan.get("resource_changes", []):
        resource_type = rc.get("type", "")
        actions = rc.get("change", {}).get("actions", [])
        address = rc.get("address", resource_type)
        category = _resource_category(resource_type)

        is_destructive = any(a in _DESTRUCTIVE_ACTIONS for a in actions)
        is_replace = set(actions) >= _REPLACE_ACTIONS

        if not is_destructive:
            continue

        if category == "data_persistence":
            signals.append({
                "name": "semantic_data_persistence_delete",
                "severity": 45,
                "surface": "terraform",
                "detail": f"{address} ({resource_type}) will be deleted -- persistent data resource",
            })
        elif category == "iam_scope":
            signals.append({
                "name": "semantic_iam_scope_delete",
                "severity": 35,
                "surface": "terraform",
                "detail": f"{address} ({resource_type}) will be deleted -- IAM scope resource",
            })
        elif category == "network_scope":
            signals.append({
                "name": "semantic_network_scope_delete",
                "severity": 25,
                "surface": "terraform",
                "detail": f"{address} ({resource_type}) will be deleted -- network boundary resource",
            })
        elif category == "cluster_scope":
            signals.append({
                "name": "semantic_cluster_scope_delete",
                "severity": 40,
                "surface": "terraform",
                "detail": f"{address} ({resource_type}) will be deleted -- cluster/compute scope resource",
            })
        elif category == "compute_scope":
            signals.append({
                "name": "semantic_compute_scope_delete",
                "severity": 40,
                "surface": "terraform",
                "detail": f"{address} ({resource_type}) will be deleted -- compute/serverless workload resource",
            })
        else:
            # Unclassified but still destructive -- lower-weight generic signal,
            # so unknown resource types aren't silently ignored.
            signals.append({
                "name": "semantic_unclassified_delete",
                "severity": 10,
                "surface": "terraform",
                "detail": f"{address} ({resource_type}) will be deleted -- unclassified resource type",
            })

        if is_replace and category in ("data_persistence", "cluster_scope", "compute_scope"):
            signals.append({
                "name": "semantic_replace_destructive",
                "severity": 15,
                "surface": "terraform",
                "detail": f"{address} will be replaced (destroy + recreate) -- brief but real downtime/data risk",
            })

    return signals


def infer_blast_radius_from_plan(plan: dict[str, Any]) -> str | None:
    """
    Best-effort inference of blast radius from plan contents, used only
    when the caller (AgentChange.impact.blast_radius) was left at the
    default and the plan itself gives us a stronger signal than "process".

    This NEVER overrides an explicitly declared blast_radius -- it only
    fills in when the caller didn't specify one, since the declared value
    is the caller's authoritative claim about impact scope.

    Returns a lowercase BlastRadius value string, or None if no inference
    can be made.
    """
    resource_changes = plan.get("resource_changes", [])
    destructive_categories: set[str] = set()

    for rc in resource_changes:
        actions = rc.get("change", {}).get("actions", [])
        if not any(a in _DESTRUCTIVE_ACTIONS for a in actions):
            continue
        category = _resource_category(rc.get("type", ""))
        if category:
            destructive_categories.add(category)

    # IAM scope changes can affect the entire account's permission boundary.
    if "iam_scope" in destructive_categories:
        return "account"

    # Cluster-scope deletion affects every workload running in that cluster.
    if "cluster_scope" in destructive_categories:
        return "cluster"

    # Data persistence or network scope deletion affects the owning service.
    if destructive_categories:
        return "service"

    return None