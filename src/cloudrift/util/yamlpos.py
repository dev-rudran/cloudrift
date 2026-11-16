"""YAML loading with source line tracking.

Documents are composed into nodes with PyYAML's safe composer, then constructed
with the safe loader. Nothing outside the YAML 1.1 safe schema is ever
instantiated. Every mapping key and sequence item gets a dotted path mapped to
its 1-based source line, which lets reports point at a specific field when a
policy declares a ``location``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import yaml


class YamlPositionError(Exception):
    """Raised when a YAML stream cannot be parsed."""


@dataclass
class YamlDocument:
    data: Any
    node: yaml.Node
    line: int
    key_lines: dict[str, int] = field(default_factory=dict)


def _walk(node: yaml.Node, path: str, out: dict[str, int]) -> None:
    if isinstance(node, yaml.MappingNode):
        for key_node, value_node in node.value:
            if not isinstance(key_node, yaml.ScalarNode):
                continue
            key = str(key_node.value)
            child = f"{path}.{key}" if path else key
            out[child] = key_node.start_mark.line + 1
            _walk(value_node, child, out)
    elif isinstance(node, yaml.SequenceNode):
        for index, item in enumerate(node.value):
            child = f"{path}.{index}" if path else str(index)
            out[child] = item.start_mark.line + 1
            _walk(item, child, out)


def key_lines_for(node: yaml.Node) -> dict[str, int]:
    lines: dict[str, int] = {}
    _walk(node, "", lines)
    return lines


def node_info(node: yaml.Node, data: Any) -> tuple[int, dict[str, int]]:
    """Return the 1-based start line and key path map for a constructed node."""

    return node.start_mark.line + 1, key_lines_for(node)


def load_documents(text: str, file: str) -> list[YamlDocument]:
    """Parse a YAML stream into safe documents with positional metadata."""

    if not text.strip():
        return []
    try:
        nodes = list(yaml.compose_all(text, Loader=yaml.SafeLoader))
    except yaml.YAMLError as exc:
        raise YamlPositionError(f"{file}: invalid YAML: {_format_yaml_error(exc)}") from exc

    documents: list[YamlDocument] = []
    loader = yaml.SafeLoader("")
    try:
        for node in nodes:
            if node is None:
                continue
            try:
                data = loader.construct_document(node)
            except yaml.YAMLError as exc:
                raise YamlPositionError(f"{file}: invalid YAML: {_format_yaml_error(exc)}") from exc
            if data is None or data == "":
                continue
            line, key_lines = node_info(node, data)
            documents.append(YamlDocument(data=data, node=node, line=line, key_lines=key_lines))
    finally:
        loader.dispose()
    return documents


def _format_yaml_error(exc: yaml.YAMLError) -> str:
    problem = getattr(exc, "problem", None)
    mark = getattr(exc, "problem_mark", None)
    if problem and mark is not None:
        return f"{problem} (line {mark.line + 1}, column {mark.column + 1})"
    if problem:
        return str(problem)
    return str(exc).strip().splitlines()[0] if str(exc).strip() else "parse error"
