"""Normalization tests for Terraform and Kubernetes resources."""

from __future__ import annotations

from cloudrift.inputs.normalize import (
    dedupe_addresses,
    extract_containers,
    extract_pod_spec,
    is_namespaced,
    kind_to_type,
    make_kubernetes_resource,
    make_terraform_resource,
    terraform_address,
    terraform_provider,
)
from cloudrift.models import Resource, SourceRef


def test_terraform_provider_derivation() -> None:
    assert terraform_provider("aws_s3_bucket") == "aws"
    assert terraform_provider("google_storage_bucket") == "google"
    assert terraform_provider("azurerm_storage_account") == "azurerm"
    assert terraform_provider("random_pet") == "random"
    assert terraform_provider("no_provider_prefix") == "no"


def test_terraform_address_with_module() -> None:
    assert terraform_address(None, "aws_s3_bucket", "logs") == "aws_s3_bucket.logs"
    assert (
        terraform_address("module.storage", "aws_s3_bucket", "logs")
        == "module.storage.aws_s3_bucket.logs"
    )


def test_make_terraform_resource() -> None:
    resource = make_terraform_resource(
        type_name="aws_s3_bucket",
        name="logs",
        address="module.storage.aws_s3_bucket.logs",
        values={"acl": "private"},
        module="module.storage",
        source=SourceRef(file="plan.json"),
        refs={"aws_kms_key.main.id"},
    )
    assert resource.provider == "aws"
    assert resource.ref_key == "aws_s3_bucket.logs"
    assert resource.module == "module.storage"
    assert resource.values == {"acl": "private"}
    assert resource.refs == {"aws_kms_key.main.id"}


def test_kind_to_type_handles_camel_case() -> None:
    assert kind_to_type("Pod") == "kubernetes_pod"
    assert kind_to_type("NetworkPolicy") == "kubernetes_network_policy"
    assert kind_to_type("CronJob") == "kubernetes_cron_job"
    assert kind_to_type("CustomResourceDefinition") == "kubernetes_custom_resource_definition"


def test_namespaced_kinds() -> None:
    assert is_namespaced("Deployment")
    assert is_namespaced("Role")
    assert not is_namespaced("ClusterRole")
    assert not is_namespaced("Namespace")
    assert not is_namespaced("PersistentVolume")


def test_make_kubernetes_resource_defaults_namespace() -> None:
    resource = make_kubernetes_resource(
        data={
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "settings"},
            "data": {"a": "b"},
        },
        source=SourceRef(file="cm.yaml", line=4),
    )
    assert resource is not None
    assert resource.address == "kubernetes_config_map.default.settings"
    assert resource.namespace == "default"
    assert resource.provider == "kubernetes"
    assert resource.source.line == 4


def test_cluster_scoped_resource_has_no_namespace() -> None:
    resource = make_kubernetes_resource(
        data={"kind": "ClusterRole", "metadata": {"name": "reader"}},
        source=SourceRef(file="rbac.yaml"),
    )
    assert resource is not None
    assert resource.namespace is None
    assert resource.address == "kubernetes_cluster_role.reader"


def test_resource_without_name_and_kind() -> None:
    assert (
        make_kubernetes_resource(data={"metadata": {"name": "x"}}, source=SourceRef(file="x.yaml"))
        is None
    )
    unnamed = make_kubernetes_resource(
        data={"kind": "ConfigMap", "metadata": {}}, source=SourceRef(file="x.yaml")
    )
    assert unnamed is not None
    assert unnamed.name == "unnamed"


def test_pod_spec_extraction_per_workload() -> None:
    containers = [{"name": "app", "image": "app:1"}]
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "spec": {"containers": containers},
    }
    assert extract_pod_spec("Pod", pod)["containers"] == containers
    deployment = {
        "kind": "Deployment",
        "spec": {"template": {"spec": {"containers": containers}}},
    }
    assert extract_pod_spec("Deployment", deployment)["containers"] == containers
    statefulset = {
        "kind": "StatefulSet",
        "spec": {"template": {"spec": {"containers": containers}}},
    }
    assert extract_pod_spec("StatefulSet", statefulset)["containers"] == containers
    job = {"kind": "Job", "spec": {"template": {"spec": {"containers": containers}}}}
    assert extract_pod_spec("Job", job)["containers"] == containers
    cronjob = {
        "kind": "CronJob",
        "spec": {"jobTemplate": {"spec": {"template": {"spec": {"containers": containers}}}}},
    }
    assert extract_pod_spec("CronJob", cronjob)["containers"] == containers
    assert extract_pod_spec("Deployment", {"kind": "Deployment"}) == {}


def test_extract_containers_includes_init_and_ephemeral() -> None:
    pod_spec = {
        "containers": [{"name": "main"}],
        "initContainers": [{"name": "init"}],
        "ephemeralContainers": [{"name": "debug"}],
    }
    containers = extract_containers(pod_spec)
    assert [item["name"] for item in containers] == ["main", "init", "debug"]
    assert [item["container_type"] for item in containers] == ["main", "init", "ephemeral"]


def test_workload_values_expose_pod_spec_and_containers() -> None:
    resource = make_kubernetes_resource(
        data={
            "kind": "Deployment",
            "metadata": {"name": "web", "namespace": "prod"},
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{"name": "web", "image": "web:1"}],
                        "initContainers": [{"name": "init", "image": "init:1"}],
                    }
                }
            },
        },
        source=SourceRef(file="deploy.yaml", line=1),
    )
    assert resource is not None
    assert resource.values["pod_spec"]["containers"][0]["name"] == "web"
    assert len(resource.values["containers"]) == 2
    assert resource.values["containers"][1]["container_type"] == "init"


def test_dedupe_addresses() -> None:
    resources = [
        Resource(
            provider="kubernetes",
            type="kubernetes_config_map",
            name="x",
            address="kubernetes_config_map.prod.x",
            source=SourceRef(file="a.yaml"),
        ),
        Resource(
            provider="kubernetes",
            type="kubernetes_config_map",
            name="x",
            address="kubernetes_config_map.prod.x",
            source=SourceRef(file="b.yaml"),
        ),
    ]
    dedupe_addresses(resources)
    assert resources[0].address == "kubernetes_config_map.prod.x"
    assert resources[1].address == "kubernetes_config_map.prod.x#2"
