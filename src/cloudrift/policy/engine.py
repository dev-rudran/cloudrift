"""Policy evaluation against normalized resources."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Any

from cloudrift.models import (
    EvaluationError,
    Finding,
    Policy,
    Resource,
    SourceRef,
)
from cloudrift.policy.expr import EvaluationError as ExpressionEvaluationError
from cloudrift.policy.expr import evaluate_expression

_PLACEHOLDER = re.compile(r"\{(address|name|type|provider|module|namespace)\}")


@dataclass
class EngineResult:
    findings: list[Finding] = field(default_factory=list)
    errors: list[EvaluationError] = field(default_factory=list)
    evaluations: int = 0


def resource_view(resource: Resource) -> dict[str, Any]:
    """Build the mapping exposed to policy expressions as ``resource``.

    Resource attribute values take precedence over metadata keys so that
    resources with an attribute named ``type`` (for example
    ``aws_security_group_rule.type``) still expose the real value. Metadata is
    always available under ``resource_type``, ``resource_address`` and the
    other non-conflicting keys.
    """

    meta: dict[str, Any] = {
        "address": resource.address,
        "type": resource.type,
        "name": resource.name,
        "provider": resource.provider,
        "module": resource.module,
        "namespace": resource.namespace,
        "resource_type": resource.type,
        "resource_address": resource.address,
        "file": resource.source.file,
        "line": resource.source.line,
    }
    view = dict(resource.values)
    for key, value in meta.items():
        view.setdefault(key, value)
    view["resource_type"] = resource.type
    view["resource_address"] = resource.address
    return view


def evaluate_policies(policies: list[Policy], resources: list[Resource]) -> EngineResult:
    """Evaluate every policy against every matching resource."""

    result = EngineResult()
    ordered = sorted(resources, key=lambda item: item.sort_key)
    for policy in sorted(policies, key=lambda item: item.id):
        if policy.expression is None:  # pragma: no cover - loader guarantees an AST
            result.errors.append(
                EvaluationError(policy.id, "", "policy has no compiled expression")
            )
            continue
        for resource in ordered:
            if not policy.matches(resource):
                continue
            result.evaluations += 1
            related = _related_resources(policy, resource, ordered)
            context = {
                "resource": resource_view(resource),
                "related": [resource_view(item) for item in related],
            }
            try:
                outcome = evaluate_expression(policy.expression, context)
            except ExpressionEvaluationError as exc:
                result.errors.append(EvaluationError(policy.id, resource.address, str(exc)))
                continue
            except Exception as exc:  # noqa: BLE001 - keep one bad policy from aborting a scan
                result.errors.append(
                    EvaluationError(
                        policy.id,
                        resource.address,
                        f"internal evaluation error: {type(exc).__name__}: {exc}",
                    )
                )
                continue
            if not outcome:
                result.findings.append(_finding(policy, resource))
    result.findings.sort(key=lambda item: item.sort_key)
    return result


def _finding(policy: Policy, resource: Resource) -> Finding:
    return Finding(
        policy_id=policy.id,
        title=policy.title,
        severity=policy.severity,
        message=_render(policy.message, resource),
        remediation=_render(policy.remediation, resource),
        resource_address=resource.address,
        resource_type=resource.type,
        provider=resource.provider,
        source=SourceRef(file=resource.source.file, line=_location_line(policy, resource)),
        references=list(policy.references),
        tags=list(policy.tags),
    )


def _render(template: str, resource: Resource) -> str:
    values = {
        "address": resource.address,
        "name": resource.name,
        "type": resource.type,
        "provider": resource.provider,
        "module": resource.module or "",
        "namespace": resource.namespace or "",
    }

    def replace(match: re.Match[str]) -> str:
        value = values.get(match.group(1), "")
        return "" if value is None else str(value)

    return _PLACEHOLDER.sub(replace, template)


def _location_line(policy: Policy, resource: Resource) -> int | None:
    for path in policy.location:
        line = resource.key_lines.get(path)
        if line is not None:
            return line
    return resource.source.line


def _related_resources(
    policy: Policy, resource: Resource, resources: list[Resource]
) -> list[Resource]:
    if not policy.relations:
        return []
    related: list[Resource] = []
    seen: set[str] = {resource.address}
    for spec in policy.relations:
        for candidate in resources:
            if candidate.address in seen:
                continue
            if not any(fnmatchcase(candidate.type, pattern) for pattern in spec.types):
                continue
            if _linked(spec, resource, candidate):
                seen.add(candidate.address)
                related.append(candidate)
    return related


def _linked(spec: Any, source: Resource, candidate: Resource) -> bool:
    if spec.scope == "namespace":
        return (
            source.namespace is not None
            and candidate.namespace == source.namespace
            and source.namespace != ""
        )
    linked = False
    if spec.reference:
        linked = _matches_references(source.refs, candidate)
    if not linked and spec.via:
        linked = _matches_via(source, candidate, spec.via, spec.target)
    return linked


def _matches_references(refs: set[str], candidate: Resource) -> bool:
    for ref in refs:
        if ref == candidate.address or ref.startswith(candidate.address + "."):
            return True
        if ref.startswith(candidate.address + "["):
            return True
        # Bare type.name references only identify resources that are not inside a module.
        if candidate.module is None and (
            ref == candidate.ref_key or ref.startswith(candidate.ref_key + ".")
        ):
            return True
    return False


def _matches_via(source: Resource, candidate: Resource, via: list[str], target: str) -> bool:
    needles: list[str] = []
    for key in via:
        value = _dotted(source.values, key)
        _collect_strings(value, needles)
    if not needles:
        return False
    haystack: list[str] = []
    _collect_strings(_dotted(candidate.values, target), haystack)
    haystack.extend(
        [
            candidate.name,
            candidate.ref_key,
            candidate.address,
        ]
    )
    return any(needle == value for needle in needles for value in haystack if value)


def _dotted(values: Any, path: str) -> Any:
    current = values
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return current


def _collect_strings(value: Any, out: list[str]) -> None:
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            _collect_strings(item, out)
    elif isinstance(value, dict):
        for item in value.values():
            _collect_strings(item, out)
