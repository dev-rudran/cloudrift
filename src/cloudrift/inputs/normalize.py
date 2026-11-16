"""Canonical resource construction for Terraform and Kubernetes inputs."""

from __future__ import annotations

import re
from typing import Any

from cloudrift.models import Resource, SourceRef

CLUSTER_SCOPED_KINDS = {
    "APIService",
    "CSIDriver",
    "CSINode",
    "ClusterRole",
    "ClusterRoleBinding",
    "ComponentStatus",
    "CustomResourceDefinition",
    "IngressClass",
    "MutatingWebhookConfiguration",
    "Namespace",
    "Node",
    "PersistentVolume",
    "PodSecurityPolicy",
    "PriorityClass",
    "RuntimeClass",
    "StorageClass",
    "ValidatingWebhookConfiguration",
}

WORKLOAD_KINDS = {
    "Pod",
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "ReplicaSet",
    "ReplicationController",
    "Job",
    "CronJob",
}


def terraform_provider(type_name: str) -> str:
    """Derive the provider name from a Terraform resource type."""

    return type_name.split("_", 1)[0] if "_" in type_name else "unknown"


def terraform_address(module: str | None, type_name: str, name: str) -> str:
    base = f"{type_name}.{name}"
    return f"{module}.{base}" if module else base


def make_terraform_resource(
    *,
    type_name: str,
    name: str,
    address: str,
    values: dict[str, Any],
    module: str | None,
    source: SourceRef,
    refs: set[str] | None = None,
) -> Resource:
    return Resource(
        provider=terraform_provider(type_name),
        type=type_name,
        name=name,
        address=address,
        values=dict(values),
        module=module,
        namespace=None,
        source=source,
        refs=set(refs or ()),
    )


def kind_to_type(kind: str) -> str:
    """Convert a Kubernetes kind to a Terraform-style resource type."""

    step = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", kind)
    snake = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", step).lower()
    return f"kubernetes_{snake}"


def is_namespaced(kind: str) -> bool:
    return kind not in CLUSTER_SCOPED_KINDS


def make_kubernetes_resource(
    *,
    data: dict[str, Any],
    source: SourceRef,
    key_lines: dict[str, int] | None = None,
) -> Resource | None:
    """Build a normalized resource from a Kubernetes manifest."""

    kind = data.get("kind")
    if not isinstance(kind, str) or not kind.strip():
        return None
    metadata = data.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
    name = metadata.get("name")
    if not isinstance(name, str) or not name.strip():
        name = "unnamed"
    namespace = metadata.get("namespace")
    if not isinstance(namespace, str) or not namespace.strip():
        namespace = "default" if is_namespaced(kind) else None
    resource_type = kind_to_type(kind)

    values = dict(data)
    values["namespace"] = namespace
    pod_spec = extract_pod_spec(kind, data)
    values["pod_spec"] = pod_spec
    values["containers"] = extract_containers(pod_spec)
    values["init_containers"] = _typed_containers(pod_spec, "initContainers", "init")
    values["ephemeral_containers"] = _typed_containers(pod_spec, "ephemeralContainers", "ephemeral")

    address = (
        f"{resource_type}.{namespace}.{name}"
        if namespace is not None
        else f"{resource_type}.{name}"
    )
    return Resource(
        provider="kubernetes",
        type=resource_type,
        name=name,
        address=address,
        values=values,
        module=None,
        namespace=namespace,
        source=source,
        key_lines=dict(key_lines or {}),
        origin="kubernetes",
    )


def extract_pod_spec(kind: str, data: dict[str, Any]) -> dict[str, Any]:
    """Return the pod spec for workloads and bare pods."""

    spec = data.get("spec")
    if not isinstance(spec, dict):
        return {}
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        job_template = spec.get("jobTemplate")
        if isinstance(job_template, dict):
            job_spec = job_template.get("spec")
            if isinstance(job_spec, dict):
                template = job_spec.get("template")
                if isinstance(template, dict) and isinstance(template.get("spec"), dict):
                    return template["spec"]
        return {}
    template = spec.get("template")
    if isinstance(template, dict) and isinstance(template.get("spec"), dict):
        return template["spec"]
    return {}


def extract_containers(pod_spec: dict[str, Any]) -> list[dict[str, Any]]:
    containers: list[dict[str, Any]] = []
    containers.extend(_typed_containers(pod_spec, "containers", "main"))
    containers.extend(_typed_containers(pod_spec, "initContainers", "init"))
    containers.extend(_typed_containers(pod_spec, "ephemeralContainers", "ephemeral"))
    return containers


def _typed_containers(
    pod_spec: dict[str, Any], field: str, container_type: str
) -> list[dict[str, Any]]:
    value = pod_spec.get(field) if isinstance(pod_spec, dict) else None
    if not isinstance(value, list):
        return []
    result: list[dict[str, Any]] = []
    for entry in value:
        if not isinstance(entry, dict):
            continue
        item = dict(entry)
        item["container_type"] = container_type
        result.append(item)
    return result


def dedupe_addresses(resources: list[Resource]) -> list[Resource]:
    """Keep addresses unique when an input repeats a resource definition."""

    seen: dict[str, int] = {}
    for resource in resources:
        base = resource.address
        if base in seen:
            seen[base] += 1
            resource.address = f"{base}#{seen[base]}"
        else:
            seen[base] = 1
    return resources
