"""Kubernetes YAML ingestion with source position tracking."""

from __future__ import annotations

from typing import Any

import yaml

from cloudrift.errors import InputError
from cloudrift.inputs.normalize import dedupe_addresses, make_kubernetes_resource
from cloudrift.models import Resource, SourceRef
from cloudrift.util.yamlpos import YamlPositionError, key_lines_for, load_documents


def load_kubernetes(text: str, source: str) -> list[Resource]:
    """Load resources from a multi-document Kubernetes YAML stream."""

    try:
        documents = load_documents(text, source)
    except YamlPositionError as exc:
        raise InputError(str(exc)) from exc
    resources: list[Resource] = []
    for document in documents:
        data = document.data
        if isinstance(data, dict) and data.get("kind") == "List":
            items = data.get("items")
            item_nodes = _value_sequence_node(document.node, "items")
            if not isinstance(items, list):
                continue
            for index, item in enumerate(items):
                if not isinstance(item, dict):
                    continue
                node = item_nodes[index] if index < len(item_nodes) else document.node
                _append(resources, item, source, node)
        elif isinstance(data, list):
            nodes = document.node.value if isinstance(document.node, yaml.SequenceNode) else []
            for index, item in enumerate(data):
                if not isinstance(item, dict):
                    continue
                node = nodes[index] if index < len(nodes) else document.node
                _append(resources, item, source, node)
        elif isinstance(data, dict):
            _append(resources, data, source, document.node)

    if not resources:
        raise InputError(f"{source}: no Kubernetes resources found")
    return dedupe_addresses(resources)


def _append(resources: list[Resource], data: dict[str, Any], source: str, node: yaml.Node) -> None:
    if not isinstance(data.get("kind"), str):
        return
    line = node.start_mark.line + 1
    key_lines = key_lines_for(node)
    resource = make_kubernetes_resource(
        data=data,
        source=SourceRef(file=source, line=line),
        key_lines=key_lines,
    )
    if resource is not None:
        resources.append(resource)


def _value_sequence_node(node: yaml.Node, key: str) -> list[yaml.Node]:
    if not isinstance(node, yaml.MappingNode):
        return []
    for key_node, value_node in node.value:
        if (
            isinstance(key_node, yaml.ScalarNode)
            and key_node.value == key
            and isinstance(value_node, yaml.SequenceNode)
        ):
            return list(value_node.value)
    return []
