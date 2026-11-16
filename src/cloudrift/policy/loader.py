"""Policy pack loading and schema validation."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from cloudrift.models import Policy, RelationSpec, Severity
from cloudrift.policy.expr import ExpressionError, compile_expression

POLICY_ID_RE = re.compile(r"^CLDR-\d{4}$")
PROVIDERS = {"aws", "kubernetes"}
_POLICY_KEYS = {
    "id",
    "title",
    "description",
    "severity",
    "provider",
    "resource",
    "assert",
    "message",
    "remediation",
    "references",
    "tags",
    "relations",
    "location",
}
_RELATION_KEYS = {"type", "reference", "via", "target", "scope"}
_PATTERN_RE = re.compile(r"^[A-Za-z0-9_.*-]+$")


class PolicyError(Exception):
    """Raised when a policy pack is malformed."""


def load_bundled_policies() -> list[Policy]:
    """Load the policy pack shipped inside the package."""

    try:
        root = resources.files("cloudrift") / "policies"
    except (ModuleNotFoundError, TypeError) as exc:  # pragma: no cover - packaging failure
        raise PolicyError(f"bundled policy pack is unavailable: {exc}") from exc
    entries = sorted(
        (entry for entry in root.iterdir() if entry.name.endswith((".yml", ".yaml"))),
        key=lambda entry: entry.name,
    )
    if not entries:
        raise PolicyError("bundled policy pack is empty")
    policies: list[Policy] = []
    for entry in entries:
        try:
            text = entry.read_text(encoding="utf-8")
        except OSError as exc:  # pragma: no cover - packaging failure
            raise PolicyError(f"cannot read bundled policy {entry.name}: {exc}") from exc
        policies.extend(parse_policy_text(text, f"policies/{entry.name}"))
    return _check_unique(policies)


def load_policy_path(path: str | Path) -> list[Policy]:
    """Load policies from a single file or a directory of YAML files."""

    target = Path(path)
    if not target.exists():
        raise PolicyError(f"policy path does not exist: {target}")
    files: list[Path]
    if target.is_dir():
        files = sorted(entry for entry in target.iterdir() if entry.suffix in {".yml", ".yaml"})
    else:
        files = [target]
    if not files:
        raise PolicyError(f"no policy files found in {target}")
    policies: list[Policy] = []
    for file_path in files:
        try:
            text = file_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise PolicyError(f"cannot read policy file {file_path}: {exc}") from exc
        policies.extend(parse_policy_text(text, str(file_path)))
    return _check_unique(policies)


def parse_policy_text(text: str, source: str) -> list[Policy]:
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyError(f"{source}: invalid YAML: {exc}") from exc
    if document is None:
        raise PolicyError(f"{source}: file is empty")
    if isinstance(document, Mapping) and "policies" in document:
        entries = document["policies"]
    elif isinstance(document, Mapping):
        entries = [document]
    elif isinstance(document, list):
        entries = document
    else:
        raise PolicyError(f"{source}: expected a policy mapping or list of policies")
    if not isinstance(entries, list) or not entries:
        raise PolicyError(f"{source}: no policies defined")
    policies = []
    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, Mapping):
            raise PolicyError(f"{source}: policy #{index} must be a mapping")
        policies.append(_parse_policy(entry, source, index))
    return policies


def validate_policies(policies: Iterable[Policy]) -> list[str]:
    """Return human-readable validation issues for already-loaded policies."""

    issues: list[str] = []
    seen: set[str] = set()
    for policy in policies:
        if policy.id in seen:
            issues.append(f"duplicate policy id {policy.id}")
        seen.add(policy.id)
        if policy.provider not in PROVIDERS:
            issues.append(f"{policy.id}: unsupported provider {policy.provider!r}")
        if not policy.resource_patterns:
            issues.append(f"{policy.id}: no resource patterns")
        if not policy.assert_expr:
            issues.append(f"{policy.id}: empty assert expression")
    return issues


def _check_unique(policies: list[Policy]) -> list[Policy]:
    seen: dict[str, str] = {}
    for policy in policies:
        if policy.id in seen:
            raise PolicyError(
                f"duplicate policy id {policy.id} in {policy.source_file} "
                f"(already defined in {seen[policy.id]})"
            )
        seen[policy.id] = policy.source_file
    return sorted(policies, key=lambda item: item.id)


def _parse_policy(entry: Mapping[str, Any], source: str, index: int) -> Policy:
    label = f"{source}: policy #{index}"
    unknown = set(entry) - _POLICY_KEYS
    if unknown:
        raise PolicyError(f"{label}: unknown keys: {', '.join(sorted(map(str, unknown)))}")
    missing = [
        key
        for key in (
            "id",
            "title",
            "description",
            "severity",
            "provider",
            "resource",
            "assert",
            "message",
            "remediation",
        )
        if key not in entry
    ]
    if missing:
        raise PolicyError(f"{label}: missing required keys: {', '.join(missing)}")

    policy_id = _string(entry, "id", label)
    if not POLICY_ID_RE.match(policy_id):
        raise PolicyError(f"{label}: id {policy_id!r} must match CLDR-####")
    label = f"{source}: {policy_id}"

    title = _string(entry, "title", label)
    description = _string(entry, "description", label)
    message = _string(entry, "message", label)
    remediation = _string(entry, "remediation", label)
    assert_expr = _string(entry, "assert", label)

    try:
        severity = Severity.parse(entry["severity"])
    except ValueError as exc:
        raise PolicyError(f"{label}: {exc}") from exc
    provider = _string(entry, "provider", label).strip().lower()
    if provider not in PROVIDERS:
        raise PolicyError(f"{label}: provider must be one of: {', '.join(sorted(PROVIDERS))}")

    patterns = _string_list(entry["resource"], f"{label}: resource")
    if not patterns:
        raise PolicyError(f"{label}: resource must name at least one type")
    for pattern in patterns:
        if not _PATTERN_RE.match(pattern):
            raise PolicyError(f"{label}: invalid resource pattern {pattern!r}")

    try:
        expression = compile_expression(assert_expr)
    except ExpressionError as exc:
        raise PolicyError(f"{label}: invalid assert expression: {exc}") from exc

    references = _optional_string_list(entry.get("references"), f"{label}: references")
    tags = _optional_string_list(entry.get("tags"), f"{label}: tags")
    location = _optional_string_list(entry.get("location"), f"{label}: location")
    relations = _parse_relations(entry.get("relations"), label)

    return Policy(
        id=policy_id,
        title=title.strip(),
        description=description.strip(),
        severity=severity,
        provider=provider,
        resource_patterns=patterns,
        assert_expr=assert_expr.strip(),
        message=message.strip(),
        remediation=remediation.strip(),
        references=references,
        tags=tags,
        relations=relations,
        location=location,
        expression=expression,
        source_file=source,
    )


def _parse_relations(value: Any, label: str) -> list[RelationSpec]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise PolicyError(f"{label}: relations must be a list")
    relations: list[RelationSpec] = []
    for index, entry in enumerate(value, start=1):
        item_label = f"{label}: relation #{index}"
        if not isinstance(entry, Mapping):
            raise PolicyError(f"{item_label} must be a mapping")
        unknown = set(entry) - _RELATION_KEYS
        if unknown:
            raise PolicyError(f"{item_label}: unknown keys: {', '.join(sorted(map(str, unknown)))}")
        if "type" not in entry:
            raise PolicyError(f"{item_label}: missing required key: type")
        types = _string_list(entry["type"], f"{item_label}: type")
        if not types:
            raise PolicyError(f"{item_label}: type must name at least one resource type")
        for type_name in types:
            if not _PATTERN_RE.match(type_name):
                raise PolicyError(f"{item_label}: invalid resource type {type_name!r}")
        reference = entry.get("reference", False)
        if not isinstance(reference, bool):
            raise PolicyError(f"{item_label}: reference must be a boolean")
        via = _optional_string_list(entry.get("via"), f"{item_label}: via")
        target = entry.get("target", "id")
        if not isinstance(target, str) or not target.strip():
            raise PolicyError(f"{item_label}: target must be a non-empty string")
        scope = entry.get("scope")
        if scope not in (None, "namespace"):
            raise PolicyError(f"{item_label}: scope must be 'namespace' when set")
        if not reference and not via and scope is None:
            raise PolicyError(
                f"{item_label}: set reference, via, or scope to define how resources link"
            )
        relations.append(
            RelationSpec(
                types=types,
                reference=reference,
                via=via,
                target=target.strip(),
                scope=scope,
            )
        )
    return relations


def _string(entry: Mapping[str, Any], key: str, label: str) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value.strip():
        raise PolicyError(f"{label}: {key} must be a non-empty string")
    return value


def _string_list(value: Any, label: str) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not value:
        raise PolicyError(f"{label} must be a string or a non-empty list of strings")
    result: list[str] = []
    for entry in value:
        if not isinstance(entry, str) or not entry.strip():
            raise PolicyError(f"{label} must contain only non-empty strings")
        result.append(entry.strip())
    return result


def _optional_string_list(value: Any, label: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if not isinstance(value, list):
        raise PolicyError(f"{label} must be a string or a list of strings")
    result: list[str] = []
    for entry in value:
        if not isinstance(entry, str):
            raise PolicyError(f"{label} must contain only strings")
        if entry.strip():
            result.append(entry.strip())
    return result
