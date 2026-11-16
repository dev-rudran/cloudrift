"""Pure helper functions available to policy expressions.

Every function here is total or raises a clear exception for bad input. They
operate only on JSON-compatible values supplied by the scanner. No function
touches the filesystem, environment, network, or subprocesses.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from datetime import date, datetime, timezone
from typing import Any

from cloudrift.util.cidr import cidr_contains as _cidr_contains
from cloudrift.util.cidr import is_public_cidr as _is_public_cidr

_REGEX_VALUE_LIMIT = 10_000
_REGEX_PATTERN_LIMIT = 500
_JSON_LIMIT = 200_000


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, Mapping):
        return list(value.values())
    if isinstance(value, (str, bytes, list, tuple, set, frozenset)):
        return list(value)
    return [value]


def length(value: Any) -> int:
    """Return the number of items in a string, list, tuple, set or mapping."""

    if value is None:
        return 0
    if isinstance(value, (str, bytes, list, tuple, set, frozenset, Mapping)):
        return len(value)
    return 0


def any_true(value: Any) -> bool:
    """Return True when at least one item in the collection is truthy."""

    if value is None:
        return False
    if isinstance(value, (str, bytes, list, tuple, set, frozenset, Mapping)):
        return any(bool(item) for item in _as_list(value))
    return bool(value)


def all_true(value: Any) -> bool:
    """Return True when every item in the collection is truthy."""

    if value is None:
        return True
    if isinstance(value, (str, bytes, list, tuple, set, frozenset, Mapping)):
        return all(bool(item) for item in _as_list(value))
    return bool(value)


def lower(value: Any) -> str:
    return value.lower() if isinstance(value, str) else ""


def upper(value: Any) -> str:
    return value.upper() if isinstance(value, str) else ""


def contains(haystack: Any, needle: Any) -> bool:
    """Membership test for strings, lists, tuples, sets and mappings."""

    if haystack is None:
        return False
    try:
        if isinstance(haystack, (str, list, tuple, set, frozenset, Mapping)):
            return needle in haystack
    except TypeError:
        return False
    return False


def startswith(value: Any, prefix: Any) -> bool:
    return isinstance(value, str) and isinstance(prefix, str) and value.startswith(prefix)


def endswith(value: Any, suffix: Any) -> bool:
    return isinstance(value, str) and isinstance(suffix, str) and value.endswith(suffix)


def cidr_contains(container: Any, candidate: Any) -> bool:
    """Return True when the candidate address or CIDR is inside the container."""

    return _cidr_contains(container, candidate)


def is_public_cidr(value: Any) -> bool:
    """Return True for internet-exposed ranges such as 0.0.0.0/0 and ::/0."""

    return _is_public_cidr(value)


def exists(value: Any) -> bool:
    """Return True when a value is present and not null."""

    return value is not None


def missing(value: Any) -> bool:
    """Return True when a value is absent or null."""

    return value is None


def get(obj: Any, key: Any, default: Any = None) -> Any:
    """Read a mapping key or dotted path, returning ``default`` when missing.

    ``get(resource, "spec.template.spec")`` traverses nested mappings and list
    indexes. Keys containing literal dots should use subscript syntax instead.
    """

    if obj is None or not isinstance(key, str):
        return default
    current: Any = obj
    for part in key.split("."):
        if isinstance(current, Mapping):
            if part not in current:
                return default
            current = current[part]
        elif isinstance(current, (list, tuple)):
            try:
                index = int(part)
                current = current[index]
            except (ValueError, IndexError):
                return default
        else:
            return default
    return current


def to_int(value: Any) -> int:
    """Coerce a value to an integer, returning 0 when it is not numeric."""

    if value is None or isinstance(value, bool) and not value:
        return 0
    if isinstance(value, bool):
        return 1
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        try:
            return int(text)
        except ValueError:
            try:
                return int(float(text))
            except ValueError:
                return 0
    return 0


def to_bool(value: Any) -> bool:
    """Coerce common true/false representations; unknown values are False."""

    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return False


def regex_match(value: Any, pattern: Any) -> bool:
    """Search a bounded string with a bounded regular expression."""

    if not isinstance(value, str) or not isinstance(pattern, str):
        return False
    if len(pattern) > _REGEX_PATTERN_LIMIT:
        raise ValueError(f"regular expression is longer than {_REGEX_PATTERN_LIMIT} characters")
    return re.search(pattern, value[:_REGEX_VALUE_LIMIT]) is not None


def json_parse(value: Any) -> Any:
    """Parse a JSON document embedded in a string; malformed input yields {}."""

    if isinstance(value, (dict, list)):
        return value
    if not isinstance(value, str):
        return {}
    text = value[:_JSON_LIMIT]
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return {}


def keys(value: Any) -> list[Any]:
    return list(value.keys()) if isinstance(value, Mapping) else []


def values(value: Any) -> list[Any]:
    return list(value.values()) if isinstance(value, Mapping) else []


def items(value: Any) -> list[list[Any]]:
    return [[key, item] for key, item in value.items()] if isinstance(value, Mapping) else []


def image_tag(image: Any) -> str:
    """Return the container image tag, ignoring registry ports.

    Digest references return the digest portion so they count as pinned.
    """

    if not isinstance(image, str):
        return ""
    reference = image.strip()
    if "@" in reference:
        return reference.split("@", 1)[1]
    last = reference.rsplit("/", 1)[-1]
    if ":" not in last:
        return ""
    return last.rsplit(":", 1)[1]


def age_days(timestamp: Any) -> float:
    """Return the age of an ISO-8601 timestamp in days, or 0 when unparsable."""

    if not isinstance(timestamp, str) or not timestamp.strip():
        return 0.0
    text = timestamp.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        if len(text) == 10:
            parsed = datetime.combine(date.fromisoformat(text), datetime.min.time())
        else:
            parsed = datetime.fromisoformat(text)
    except ValueError:
        return 0.0
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    delta = datetime.now(timezone.utc) - parsed
    return delta.total_seconds() / 86400.0


def _iam_statements(policy: Any) -> list[Mapping[str, Any]]:
    document = json_parse(policy) if isinstance(policy, str) else policy
    if not isinstance(document, Mapping):
        return []
    statement = document.get("Statement")
    if isinstance(statement, Mapping):
        return [statement]
    if isinstance(statement, list):
        return [entry for entry in statement if isinstance(entry, Mapping)]
    return []


def _lookup(statement: Mapping[str, Any], name: str) -> Any:
    if name in statement:
        return statement[name]
    lowered = name.lower()
    for key, value in statement.items():
        if isinstance(key, str) and key.lower() == lowered:
            return value
    return None


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [entry for entry in value if isinstance(entry, str)]
    return []


def _statement_allows(statement: Mapping[str, Any]) -> bool:
    effect = _lookup(statement, "Effect")
    return isinstance(effect, str) and effect.strip().lower() == "allow"


def _contains_star(value: Any) -> bool:
    if value == "*":
        return True
    if isinstance(value, list):
        return any(_contains_star(entry) for entry in value)
    if isinstance(value, Mapping):
        return any(_contains_star(entry) for entry in value.values())
    return False


def iam_actions(policy: Any) -> list[str]:
    actions: list[str] = []
    for statement in _iam_statements(policy):
        actions.extend(_strings(_lookup(statement, "Action")))
    return actions


def iam_resources(policy: Any) -> list[str]:
    resources: list[str] = []
    for statement in _iam_statements(policy):
        resources.extend(_strings(_lookup(statement, "Resource")))
    return resources


def iam_wildcard_action(policy: Any) -> bool:
    """Return True when an Allow statement contains a wildcard action."""

    for statement in _iam_statements(policy):
        if not _statement_allows(statement):
            continue
        if any("*" in action for action in _strings(_lookup(statement, "Action"))):
            return True
    return False


def iam_wildcard_resource(policy: Any) -> bool:
    """Return True when an Allow statement targets every resource (``*``)."""

    for statement in _iam_statements(policy):
        if not _statement_allows(statement):
            continue
        if "*" in _strings(_lookup(statement, "Resource")):
            return True
    return False


def iam_allow_all(policy: Any) -> bool:
    """Return True when an Allow statement grants every action on every resource."""

    for statement in _iam_statements(policy):
        if not _statement_allows(statement):
            continue
        actions = _strings(_lookup(statement, "Action"))
        resources = _strings(_lookup(statement, "Resource"))
        if "*" in actions and "*" in resources:
            return True
    return False


def iam_public_principal(policy: Any) -> bool:
    """Return True for an unconditional Allow to a wildcard principal."""

    for statement in _iam_statements(policy):
        if not _statement_allows(statement):
            continue
        if _lookup(statement, "Condition"):
            continue
        if _contains_star(_lookup(statement, "Principal")):
            return True
    return False


def sg_ingress_rules(resource: Any) -> list[dict[str, Any]]:
    """Return ingress rules from a security group or ingress rule resource."""

    if not isinstance(resource, Mapping):
        return []
    resource_type = resource.get("resource_type")
    if resource_type == "aws_security_group_rule":
        rule_type = resource.get("type")
        return [dict(resource)] if rule_type == "ingress" else []
    ingress = resource.get("ingress")
    if isinstance(ingress, Mapping):
        return [dict(ingress)]
    if isinstance(ingress, list):
        return [dict(rule) for rule in ingress if isinstance(rule, Mapping)]
    return []


FUNCTIONS: dict[str, Any] = {
    "len": length,
    "any": any_true,
    "all": all_true,
    "lower": lower,
    "upper": upper,
    "contains": contains,
    "startswith": startswith,
    "endswith": endswith,
    "cidr_contains": cidr_contains,
    "is_public_cidr": is_public_cidr,
    "exists": exists,
    "missing": missing,
    "get": get,
    "to_int": to_int,
    "to_bool": to_bool,
    "regex_match": regex_match,
    "json_parse": json_parse,
    "keys": keys,
    "values": values,
    "items": items,
    "image_tag": image_tag,
    "age_days": age_days,
    "iam_actions": iam_actions,
    "iam_resources": iam_resources,
    "iam_wildcard_action": iam_wildcard_action,
    "iam_wildcard_resource": iam_wildcard_resource,
    "iam_allow_all": iam_allow_all,
    "iam_public_principal": iam_public_principal,
    "sg_ingress_rules": sg_ingress_rules,
}


def function_names() -> Iterable[str]:
    return FUNCTIONS.keys()
