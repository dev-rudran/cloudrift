"""Terraform plan/state JSON ingestion.

Cloudrift consumes the JSON produced by ``terraform show -json``. It never
parses HCL. Planned values drive analysis; delete-only resource changes are
ignored. Configuration expressions are used to recover cross-resource
references such as ``${aws_security_group.web.id}``.
"""

from __future__ import annotations

import re
from typing import Any

from cloudrift.errors import InputError
from cloudrift.inputs.normalize import make_terraform_resource, terraform_address
from cloudrift.models import Resource, SourceRef

_REFERENCE_STRING = re.compile(r"\$\{([^}]+)\}")
_SAFE_REFERENCE = re.compile(r"^[A-Za-z0-9_.\[\]\"'-]+$")


def load_terraform(data: Any, source: str) -> list[Resource]:
    """Load resources from a plan or state JSON document."""

    if not isinstance(data, dict):
        raise InputError(f"{source}: Terraform input must be a JSON object")
    action_map = _action_map(data)
    refs_map = _configuration_refs(data)
    root = _root_module(data)
    origin = "terraform-plan" if "planned_values" in data else "terraform-state"
    source_ref = SourceRef(file=source)
    resources: list[Resource] = []

    if root is not None:
        _walk_module(
            root,
            module_address=None,
            source=source_ref,
            action_map=action_map,
            refs_map=refs_map,
            resources=resources,
        )
    else:
        _walk_changes(data, source_ref, action_map, refs_map, resources)

    if not resources and not _has_any_root(data):
        raise InputError(
            f"{source}: not a Terraform plan or state document "
            "(expected planned_values.root_module, values.root_module, or resource_changes)"
        )
    for resource in resources:
        resource.origin = origin
        resource.refs |= _value_refs(resource.values)
    return resources


def _root_module(data: dict[str, Any]) -> dict[str, Any] | None:
    candidates = [data.get("planned_values"), data.get("values")]
    prior = data.get("prior_state")
    if isinstance(prior, dict):
        candidates.append(prior.get("values"))
    for candidate in candidates:
        if isinstance(candidate, dict):
            root = candidate.get("root_module")
            if isinstance(root, dict):
                return root
    return None


def _has_any_root(data: dict[str, Any]) -> bool:
    return any(key in data for key in ("planned_values", "values", "resource_changes"))


def _walk_module(
    module: dict[str, Any],
    *,
    module_address: str | None,
    source: SourceRef,
    action_map: dict[str, list[str]],
    refs_map: dict[str, set[str]],
    resources: list[Resource],
) -> None:
    entries = module.get("resources")
    if isinstance(entries, list):
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if entry.get("mode", "managed") != "managed":
                continue
            type_name = entry.get("type")
            name = entry.get("name")
            if not isinstance(type_name, str) or not isinstance(name, str):
                continue
            address = entry.get("address")
            if not isinstance(address, str) or not address:
                address = terraform_address(module_address, type_name, name)
            if _is_deleted(address, action_map):
                continue
            values = entry.get("values")
            if not isinstance(values, dict):
                values = {}
            resources.append(
                make_terraform_resource(
                    type_name=type_name,
                    name=name,
                    address=address,
                    values=values,
                    module=module_address,
                    source=source,
                    refs=set(refs_map.get(address, set())) | _value_refs(values),
                )
            )
    children = module.get("child_modules")
    if isinstance(children, list):
        for child in children:
            if not isinstance(child, dict):
                continue
            child_address = child.get("address")
            if not isinstance(child_address, str):
                child_address = module_address
            _walk_module(
                child,
                module_address=child_address,
                source=source,
                action_map=action_map,
                refs_map=refs_map,
                resources=resources,
            )


def _walk_changes(
    data: dict[str, Any],
    source: SourceRef,
    action_map: dict[str, list[str]],
    refs_map: dict[str, set[str]],
    resources: list[Resource],
) -> None:
    changes = data.get("resource_changes")
    if not isinstance(changes, list):
        return
    for entry in changes:
        if not isinstance(entry, dict):
            continue
        if entry.get("mode", "managed") != "managed":
            continue
        address = entry.get("address")
        type_name = entry.get("type")
        name = entry.get("name")
        if not all(isinstance(value, str) for value in (address, type_name, name)):
            continue
        if _is_deleted(address, action_map):
            continue
        change = entry.get("change")
        after = change.get("after") if isinstance(change, dict) else None
        if not isinstance(after, dict):
            continue
        module = entry.get("module_address")
        if not isinstance(module, str):
            module = None
        resources.append(
            make_terraform_resource(
                type_name=type_name,
                name=name,
                address=address,
                values=after,
                module=module,
                source=source,
                refs=set(refs_map.get(address, set())) | _value_refs(after),
            )
        )


def _action_map(data: dict[str, Any]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    changes = data.get("resource_changes")
    if not isinstance(changes, list):
        return result
    for entry in changes:
        if not isinstance(entry, dict):
            continue
        address = entry.get("address")
        change = entry.get("change")
        if not isinstance(address, str) or not isinstance(change, dict):
            continue
        actions = change.get("actions")
        if isinstance(actions, list):
            result[address] = [action for action in actions if isinstance(action, str)]
    return result


def _is_deleted(address: str, action_map: dict[str, list[str]]) -> bool:
    actions = {action.lower() for action in action_map.get(address, [])}
    if not actions:
        return False
    if "delete" not in actions:
        return False
    return not ({"create", "update"} & actions)


def _configuration_refs(data: dict[str, Any]) -> dict[str, set[str]]:
    configuration = data.get("configuration")
    if not isinstance(configuration, dict):
        return {}
    root = configuration.get("root_module")
    if not isinstance(root, dict):
        return {}
    result: dict[str, set[str]] = {}
    _walk_configuration(root, None, result)
    return result


def _walk_configuration(
    module: dict[str, Any], prefix: str | None, result: dict[str, set[str]]
) -> None:
    entries = module.get("resources")
    if isinstance(entries, list):
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if entry.get("mode", "managed") != "managed":
                continue
            address = entry.get("address")
            if not isinstance(address, str) or not address:
                type_name = entry.get("type")
                name = entry.get("name")
                if not isinstance(type_name, str) or not isinstance(name, str):
                    continue
                address = f"{type_name}.{name}"
            full = f"{prefix}.{address}" if prefix else address
            refs = result.setdefault(full, set())
            _collect_references(entry.get("expressions"), refs)
    calls = module.get("module_calls")
    if isinstance(calls, dict):
        for call_name, call in calls.items():
            if not isinstance(call, dict):
                continue
            child = call.get("module")
            if not isinstance(child, dict):
                continue
            child_prefix = f"{prefix}.module.{call_name}" if prefix else f"module.{call_name}"
            _walk_configuration(child, child_prefix, result)


def _collect_references(value: Any, refs: set[str]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "references" and isinstance(item, list):
                for reference in item:
                    if isinstance(reference, str) and reference.strip():
                        refs.add(reference.strip())
            else:
                _collect_references(item, refs)
    elif isinstance(value, list):
        for item in value:
            _collect_references(item, refs)


def _value_refs(value: Any) -> set[str]:
    refs: set[str] = set()
    if isinstance(value, str):
        for match in _REFERENCE_STRING.finditer(value):
            inner = match.group(1).strip()
            if inner.startswith("var.") or inner.startswith("local."):
                continue
            if _SAFE_REFERENCE.match(inner):
                refs.add(inner)
    elif isinstance(value, dict):
        for item in value.values():
            refs |= _value_refs(item)
    elif isinstance(value, list):
        for item in value:
            refs |= _value_refs(item)
    return refs
