"""Kubernetes YAML ingestion tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from cloudrift.errors import InputError
from cloudrift.inputs.kubernetes import load_kubernetes

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_multi_document_and_list_expansion() -> None:
    text = (FIXTURES / "k8s" / "multi.yaml").read_text(encoding="utf-8")
    resources = load_kubernetes(text, "multi.yaml")
    assert [resource.address for resource in resources] == [
        "kubernetes_config_map.prod.app-config",
        "kubernetes_deployment.prod.web",
        "kubernetes_service.prod.web",
    ]


def test_line_numbers_for_multi_document_fixture() -> None:
    text = (FIXTURES / "k8s" / "multi.yaml").read_text(encoding="utf-8")
    loaded = load_kubernetes(text, "multi.yaml")
    resources = {resource.address: resource for resource in loaded}
    config = resources["kubernetes_config_map.prod.app-config"]
    assert config.source.line == 1
    assert config.key_lines["metadata.name"] == 4
    assert config.key_lines["data.LOG_LEVEL"] == 7
    deployment = resources["kubernetes_deployment.prod.web"]
    assert deployment.key_lines["metadata.name"] == 12
    assert deployment.key_lines["spec.template.spec.containers"] == 17
    assert deployment.key_lines["spec.template.spec.containers.0.image"] == 19
    service = resources["kubernetes_service.prod.web"]
    assert service.source.line == 27
    assert service.key_lines["metadata.name"] == 30
    assert service.key_lines["spec.type"] == 33


def test_workload_pod_specs_are_normalized() -> None:
    text = """
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: prod}
spec:
  template:
    spec:
      containers:
        - name: web
          image: web:1
      initContainers:
        - name: init
          image: init:1
---
apiVersion: batch/v1
kind: CronJob
metadata: {name: nightly, namespace: prod}
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: job
              image: job:1
"""
    resources = {resource.name: resource for resource in load_kubernetes(text, "workloads.yaml")}
    deployment = resources["web"]
    assert deployment.type == "kubernetes_deployment"
    assert deployment.values["pod_spec"]["containers"][0]["image"] == "web:1"
    assert [item["container_type"] for item in deployment.values["containers"]] == [
        "main",
        "init",
    ]
    cron = resources["nightly"]
    assert cron.values["pod_spec"]["containers"][0]["name"] == "job"


def test_bare_pod_and_job_and_statefulset() -> None:
    text = """
apiVersion: v1
kind: Pod
metadata: {name: debug}
spec:
  containers:
    - name: shell
      image: busybox:1.36
---
apiVersion: batch/v1
kind: Job
metadata: {name: migrate}
spec:
  template:
    spec:
      containers:
        - name: migrate
          image: migrate:1
---
apiVersion: apps/v1
kind: StatefulSet
metadata: {name: db}
spec:
  template:
    spec:
      containers:
        - name: db
          image: postgres:16
"""
    resources = load_kubernetes(text, "kinds.yaml")
    by_type = {resource.type: resource for resource in resources}
    assert by_type["kubernetes_pod"].namespace == "default"
    assert by_type["kubernetes_job"].values["pod_spec"]["containers"][0]["name"] == "migrate"
    assert by_type["kubernetes_stateful_set"].values["pod_spec"]["containers"][0]["name"] == "db"


def test_rbac_fields_are_preserved() -> None:
    text = """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: admin}
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: admin}
roleRef: {kind: ClusterRole, name: admin}
subjects:
  - {kind: User, name: alice}
"""
    resources = {resource.type: resource for resource in load_kubernetes(text, "rbac.yaml")}
    role = resources["kubernetes_cluster_role"]
    assert role.namespace is None
    assert role.values["rules"][0]["verbs"] == ["*"]
    binding = resources["kubernetes_cluster_role_binding"]
    assert binding.values["roleRef"]["name"] == "admin"
    assert binding.values["subjects"][0]["name"] == "alice"


def test_unknown_kind_is_kept_addressable() -> None:
    text = """
apiVersion: example.com/v1
kind: Widget
metadata: {name: fancy, namespace: prod}
spec:
  size: 3
"""
    resources = load_kubernetes(text, "custom.yaml")
    assert resources[0].type == "kubernetes_widget"
    assert resources[0].address == "kubernetes_widget.prod.fancy"
    assert resources[0].values["spec"]["size"] == 3
    assert resources[0].values["pod_spec"] == {}


def test_top_level_sequence_of_manifests() -> None:
    text = """
- apiVersion: v1
  kind: ConfigMap
  metadata: {name: one, namespace: prod}
- apiVersion: v1
  kind: ConfigMap
  metadata: {name: two, namespace: prod}
"""
    resources = load_kubernetes(text, "list.yaml")
    assert [resource.name for resource in resources] == ["one", "two"]


def test_empty_list_and_empty_documents() -> None:
    text = """
---
# comment only
---
apiVersion: v1
kind: List
items: []
"""
    with pytest.raises(InputError, match="no Kubernetes resources"):
        load_kubernetes(text, "empty.yaml")


def test_invalid_yaml_reports_location() -> None:
    with pytest.raises(InputError, match="invalid YAML"):
        load_kubernetes("kind: [unclosed\n", "broken.yaml")


def test_unsafe_yaml_tags_are_rejected() -> None:
    with pytest.raises(InputError):
        load_kubernetes("kind: !!python/object:os.system {}\n", "evil.yaml")


def test_duplicate_resources_receive_unique_addresses() -> None:
    text = """
apiVersion: v1
kind: ConfigMap
metadata: {name: same, namespace: prod}
---
apiVersion: v1
kind: ConfigMap
metadata: {name: same, namespace: prod}
"""
    resources = load_kubernetes(text, "dupes.yaml")
    assert [resource.address for resource in resources] == [
        "kubernetes_config_map.prod.same",
        "kubernetes_config_map.prod.same#2",
    ]


def test_namespace_fallback_and_cluster_scope() -> None:
    text = """
apiVersion: v1
kind: Service
metadata: {name: web}
spec: {type: ClusterIP}
---
apiVersion: v1
kind: Namespace
metadata: {name: prod}
"""
    resources = load_kubernetes(text, "scope.yaml")
    service = next(item for item in resources if item.type == "kubernetes_service")
    namespace = next(item for item in resources if item.type == "kubernetes_namespace")
    assert service.address == "kubernetes_service.default.web"
    assert namespace.address == "kubernetes_namespace.prod"
    assert namespace.namespace is None


def test_non_mapping_documents_are_skipped() -> None:
    text = """
hello
---
- 1
- 2
---
kind: ConfigMap
metadata: {name: valid, namespace: prod}
"""
    resources = load_kubernetes(text, "mixed.yaml")
    assert [resource.name for resource in resources] == ["valid"]
