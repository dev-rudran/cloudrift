"""cloudrift.yaml configuration and inline ignore handling."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any

import yaml

from cloudrift.errors import ConfigError
from cloudrift.models import SEVERITIES, Finding

CONFIG_NAMES = ("cloudrift.yaml", "cloudrift.yml", ".cloudrift.yaml", ".cloudrift.yml")
_CONFIG_KEYS = {"fail_on", "severity", "exclude_paths", "ignore"}
_IGNORE_KEYS = {"id", "resource", "reason", "expires"}
_GATE_VALUES = set(SEVERITIES) | {"never"}


@dataclass
class IgnoreRule:
    id: str
    resource: str | None = None
    reason: str = ""
    expires: date | None = None

    def is_expired(self, today: date) -> bool:
        return self.expires is not None and self.expires < today

    def matches(self, finding: Finding) -> bool:
        if not fnmatch.fnmatchcase(finding.policy_id, self.id):
            return False
        return not self.resource or fnmatch.fnmatchcase(finding.resource_address, self.resource)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "resource": self.resource,
            "reason": self.reason,
            "expires": self.expires.isoformat() if self.expires else None,
        }


@dataclass
class Config:
    fail_on: str = "high"
    severity: str = "info"
    exclude_paths: list[str] = field(default_factory=list)
    ignore: list[IgnoreRule] = field(default_factory=list)
    source_file: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "fail_on": self.fail_on,
            "severity": self.severity,
            "exclude_paths": list(self.exclude_paths),
            "ignore": [rule.to_dict() for rule in self.ignore],
            "source_file": self.source_file,
        }


def load_config(path: str | Path | None = None, *, search: bool = True) -> Config:
    """Load configuration, optionally discovering cloudrift.yaml in the cwd."""

    target: Path | None
    if path is not None:
        target = Path(path)
        if not target.exists():
            raise ConfigError(f"config file does not exist: {target}")
    elif search:
        target = next((Path(name) for name in CONFIG_NAMES if Path(name).exists()), None)
    else:
        target = None
    if target is None:
        return Config()
    try:
        text = target.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read config {target}: {exc}") from exc
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"{target}: invalid YAML: {exc}") from exc
    if document is None:
        return Config(source_file=str(target))
    if not isinstance(document, dict):
        raise ConfigError(f"{target}: configuration must be a mapping")
    unknown = set(document) - _CONFIG_KEYS
    if unknown:
        raise ConfigError(f"{target}: unknown keys: {', '.join(sorted(map(str, unknown)))}")

    fail_on = document.get("fail_on", "high")
    if not isinstance(fail_on, str) or fail_on.lower() not in _GATE_VALUES:
        raise ConfigError(f"{target}: fail_on must be one of: {', '.join(sorted(_GATE_VALUES))}")
    severity = document.get("severity", "info")
    if not isinstance(severity, str) or severity.lower() not in set(SEVERITIES):
        raise ConfigError(f"{target}: severity must be one of: {', '.join(SEVERITIES)}")
    exclude_paths = _string_list(document.get("exclude_paths", []), f"{target}: exclude_paths")
    ignore = _parse_ignores(document.get("ignore", []), target)
    return Config(
        fail_on=fail_on.lower(),
        severity=severity.lower(),
        exclude_paths=exclude_paths,
        ignore=ignore,
        source_file=str(target),
    )


def _string_list(value: Any, label: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ConfigError(f"{label} must be a list of glob patterns")
    result = []
    for entry in value:
        if not isinstance(entry, str) or not entry.strip():
            raise ConfigError(f"{label} must contain only non-empty strings")
        result.append(entry.strip())
    return result


def _parse_ignores(value: Any, source: Path) -> list[IgnoreRule]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ConfigError(f"{source}: ignore must be a list")
    rules: list[IgnoreRule] = []
    for index, entry in enumerate(value, start=1):
        label = f"{source}: ignore #{index}"
        if not isinstance(entry, dict):
            raise ConfigError(f"{label} must be a mapping")
        unknown = set(entry) - _IGNORE_KEYS
        if unknown:
            raise ConfigError(f"{label}: unknown keys: {', '.join(sorted(map(str, unknown)))}")
        policy_id = entry.get("id")
        if not isinstance(policy_id, str) or not policy_id.strip():
            raise ConfigError(f"{label}: id must be a non-empty string")
        resource = entry.get("resource")
        if resource is not None and (not isinstance(resource, str) or not resource.strip()):
            raise ConfigError(f"{label}: resource must be a non-empty string")
        reason = entry.get("reason", "")
        if not isinstance(reason, str):
            raise ConfigError(f"{label}: reason must be a string")
        expires = _parse_expiry(entry.get("expires"), label)
        rules.append(
            IgnoreRule(
                id=policy_id.strip(),
                resource=resource.strip() if isinstance(resource, str) else None,
                reason=reason.strip(),
                expires=expires,
            )
        )
    return rules


def _parse_expiry(value: Any, label: str) -> date | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value.strip())
        except ValueError as exc:
            raise ConfigError(f"{label}: expires must be an ISO date (YYYY-MM-DD)") from exc
    raise ConfigError(f"{label}: expires must be an ISO date (YYYY-MM-DD)")


def apply_ignores(
    findings: list[Finding],
    config: Config,
    cli_ignores: list[str] | None = None,
    *,
    today: date | None = None,
) -> tuple[list[Finding], list[dict[str, Any]], list[dict[str, Any]]]:
    """Split findings into kept and suppressed lists, plus stale ignore rules.

    Expired rules never suppress. Ad-hoc ``--ignore`` identifiers are treated as
    non-expiring rules with an explanatory reason.
    """

    current = today or date.today()
    rules = list(config.ignore)
    for identifier in cli_ignores or []:
        rules.append(IgnoreRule(id=identifier, reason="suppressed by --ignore"))
    stale = [rule.to_dict() for rule in rules if rule.is_expired(current)]
    active = [rule for rule in rules if not rule.is_expired(current)]
    kept: list[Finding] = []
    suppressed: list[dict[str, Any]] = []
    for finding in findings:
        match = next((rule for rule in active if rule.matches(finding)), None)
        if match is None:
            kept.append(finding)
        else:
            record = finding.to_dict()
            record["suppressed_by"] = match.to_dict()
            suppressed.append(record)
    return kept, suppressed, stale
