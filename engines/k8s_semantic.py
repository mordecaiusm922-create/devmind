"""
engines/k8s_semantic.py -- DevMind Agent Governance
Semantic parser for Kubernetes Pod and Deployment manifests.

This module is additive: it never replaces the regex-based _SIGNALS in
infra_engine.py. It only activates for a valid YAML Pod or Deployment and
returns the same signal shape as terraform_semantic.py, allowing the existing
scoring and decision path to remain unchanged.
"""

from __future__ import annotations

from typing import Any

import yaml


_POD_KINDS: frozenset[str] = frozenset({"Pod", "Deployment"})
# Privileged is intentionally unrestricted. Baseline begins the policy checks
# and permits this Kubernetes-defined capability set; Restricted narrows it to
# NET_BIND_SERVICE after requiring the container to drop ALL capabilities.
_BASELINE_ALLOWED_CAPABILITIES: frozenset[str] = frozenset({
    "AUDIT_WRITE",
    "CHOWN",
    "DAC_OVERRIDE",
    "FOWNER",
    "FSETID",
    "KILL",
    "MKNOD",
    "NET_BIND_SERVICE",
    "SETFCAP",
    "SETGID",
    "SETPCAP",
    "SETUID",
    "SYS_CHROOT",
})


def _pod_spec(manifest: dict[str, Any]) -> dict[str, Any] | None:
    """Return the effective Pod spec for a Pod or Deployment manifest."""
    spec = manifest.get("spec")
    if not isinstance(spec, dict):
        return None

    if manifest.get("kind") == "Pod":
        return spec

    if manifest.get("kind") == "Deployment":
        template = spec.get("template")
        if not isinstance(template, dict):
            return None
        template_spec = template.get("spec")
        return template_spec if isinstance(template_spec, dict) else None

    return None


def parse_k8s_manifest(payload: str) -> dict[str, Any] | None:
    """
    Attempt to parse payload as a Kubernetes Pod or Deployment YAML manifest.

    Returns None if payload is invalid YAML or does not contain the Pod spec
    structure needed for semantic analysis. This signals the caller to keep
    using the regex-based evaluator without raising an exception.
    """
    try:
        data = yaml.safe_load(payload)
    except (yaml.YAMLError, TypeError, AttributeError):
        return None

    if not isinstance(data, dict) or data.get("kind") not in _POD_KINDS:
        return None

    pod_spec = _pod_spec(data)
    if not isinstance(pod_spec, dict) or not isinstance(pod_spec.get("containers"), list):
        return None

    return data


def _signal(name: str, severity: int, detail: str) -> dict[str, Any]:
    """Build a signal in the shape consumed by infra_engine."""
    return {
        "name": name,
        "severity": severity,
        "surface": "kubernetes",
        "detail": detail,
    }


def _container_label(container: dict[str, Any], index: int) -> str:
    """Provide a stable label for signal detail even if name is absent."""
    name = container.get("name")
    return name if isinstance(name, str) and name else f"containers[{index}]"


def _capability_values(value: Any) -> set[str]:
    """Normalize a YAML capability list while ignoring malformed members."""
    if not isinstance(value, list):
        return set()
    return {item.upper() for item in value if isinstance(item, str)}


def _is_root_user(value: Any) -> bool:
    """True only for the numeric UID 0, not Python's bool subclass of int."""
    return isinstance(value, int) and not isinstance(value, bool) and value == 0


def extract_semantic_signals(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Classify explicit Pod Security Standards violations in a parsed manifest.

    Baseline violations have severity 35--45. Restricted-only violations have
    severity 15--25. Fields omitted from a manifest do not create a signal:
    the parser reports explicit unsafe intent and lets ordinary Kubernetes
    admission controls enforce a chosen profile's required defaults.
    """
    pod_spec = _pod_spec(manifest)
    if not isinstance(pod_spec, dict):
        return []

    containers = pod_spec.get("containers")
    if not isinstance(containers, list):
        return []

    signals: list[dict[str, Any]] = []

    # Pod-wide host namespace sharing is forbidden by the Baseline profile.
    for field, signal_name in (
        ("hostNetwork", "semantic_k8s_baseline_host_network"),
        ("hostPID", "semantic_k8s_baseline_host_pid"),
        ("hostIPC", "semantic_k8s_baseline_host_ipc"),
    ):
        if pod_spec.get(field) is True:
            signals.append(_signal(
                signal_name,
                35,
                f"Pod spec sets {field}=true, which violates Kubernetes Baseline",
            ))

    for index, container in enumerate(containers):
        if not isinstance(container, dict):
            continue

        security_context = container.get("securityContext")
        if not isinstance(security_context, dict):
            continue

        label = _container_label(container, index)

        # Baseline profile violations.
        if security_context.get("privileged") is True:
            signals.append(_signal(
                "semantic_k8s_baseline_privileged_container",
                45,
                f"Container {label!r} sets privileged=true, which violates Kubernetes Baseline",
            ))

        capabilities = security_context.get("capabilities")
        if isinstance(capabilities, dict):
            added_capabilities = _capability_values(capabilities.get("add"))
            disallowed_capabilities = added_capabilities - _BASELINE_ALLOWED_CAPABILITIES
            if disallowed_capabilities:
                listed = ", ".join(sorted(disallowed_capabilities))
                signals.append(_signal(
                    "semantic_k8s_baseline_added_capability",
                    40,
                    f"Container {label!r} adds {listed}, which violates Kubernetes Baseline",
                ))

        # Restricted-only violations. These fields are permitted by Baseline
        # but cannot meet Restricted when explicitly configured this way.
        if security_context.get("allowPrivilegeEscalation") is True:
            signals.append(_signal(
                "semantic_k8s_restricted_privilege_escalation",
                25,
                f"Container {label!r} sets allowPrivilegeEscalation=true, which violates Kubernetes Restricted",
            ))

        if security_context.get("runAsNonRoot") is False:
            signals.append(_signal(
                "semantic_k8s_restricted_run_as_non_root",
                20,
                f"Container {label!r} sets runAsNonRoot=false, which violates Kubernetes Restricted",
            ))

        if _is_root_user(security_context.get("runAsUser")):
            signals.append(_signal(
                "semantic_k8s_restricted_run_as_root",
                25,
                f"Container {label!r} sets runAsUser=0, which violates Kubernetes Restricted",
            ))

        seccomp_profile = security_context.get("seccompProfile")
        if isinstance(seccomp_profile, dict) and seccomp_profile.get("type") == "Unconfined":
            signals.append(_signal(
                "semantic_k8s_baseline_unconfined_seccomp",
                35,
                f"Container {label!r} sets seccompProfile.type=Unconfined, which violates Kubernetes Baseline",
            ))

        if isinstance(capabilities, dict) and "drop" in capabilities:
            dropped_capabilities = _capability_values(capabilities.get("drop"))
            if "ALL" not in dropped_capabilities:
                signals.append(_signal(
                    "semantic_k8s_restricted_missing_drop_all",
                    20,
                    f"Container {label!r} does not drop ALL capabilities, which violates Kubernetes Restricted",
                ))
    return signals
