"""Core data model for cloudrift scans, policies and findings."""

from __future__ import annotations

import ast
import enum
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info")


class Severity(str, enum.Enum):
    """Finding severity, ordered from most to least urgent."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return SEVERITIES.index(self.value)

    @property
    def label(self) -> str:
        return self.value.upper()

    @classmethod
    def parse(cls, value: object, *, field_name: str = "severity") -> Severity:
        if isinstance(value, cls):
            return value
        if not isinstance(value, str):
            raise ValueError(f"{field_name} must be a string, got {type(value).__name__}")
        try:
            return cls(value.strip().lower())
        except ValueError as exc:
            allowed = ", ".join(SEVERITIES)
            raise ValueError(f"invalid {field_name} {value!r}; expected one of: {allowed}") from exc

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


@dataclass(frozen=True)
class SourceRef:
    """Location of a resource or finding in the scanned input."""

    file: str
    line: int | None = None

    def display(self) -> str:
        if self.line is None:
            return self.file
        return f"{self.file}:{self.line}"

    def to_dict(self) -> dict[str, Any]:
        return {"file": self.file, "line": self.line}


@dataclass
class Resource:
    """A normalized infrastructure resource."""

    provider: str
    type: str
    name: str
    address: str
    values: dict[str, Any] = field(default_factory=dict)
    module: str | None = None
    namespace: str | None = None
    source: SourceRef = field(default_factory=lambda: SourceRef(file=""))
    refs: set[str] = field(default_factory=set)
    key_lines: dict[str, int] = field(default_factory=dict)
    origin: str = "terraform"

    @property
    def ref_key(self) -> str:
        """Reference key used by Terraform expression strings, e.g. ``aws_s3_bucket.logs``."""

        return f"{self.type}.{self.name}"

    @property
    def sort_key(self) -> tuple[str, str, str]:
        return (self.provider, self.address, self.source.file)

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "type": self.type,
            "name": self.name,
            "provider": self.provider,
            "module": self.module,
            "namespace": self.namespace,
            "file": self.source.file,
            "line": self.source.line,
            "origin": self.origin,
        }


def finding_fingerprint(policy_id: str, address: str, file: str) -> str:
    """Stable fingerprint used for baselines and SARIF partial fingerprints."""

    digest = hashlib.sha256(f"{policy_id}\x00{address}\x00{file}".encode()).hexdigest()
    return digest[:16]


@dataclass
class Finding:
    """A policy violation attached to one resource."""

    policy_id: str
    title: str
    severity: Severity
    message: str
    remediation: str
    resource_address: str
    resource_type: str
    provider: str
    source: SourceRef
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        if not self.fingerprint:
            self.fingerprint = finding_fingerprint(
                self.policy_id, self.resource_address, self.source.file
            )

    @property
    def location(self) -> str:
        return self.source.display()

    @property
    def sort_key(self) -> tuple[int, str, str, int]:
        return (
            self.severity.rank,
            self.policy_id,
            self.resource_address,
            self.source.line or 0,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "title": self.title,
            "severity": self.severity.value,
            "message": self.message,
            "remediation": self.remediation,
            "resource": self.resource_address,
            "resource_type": self.resource_type,
            "provider": self.provider,
            "file": self.source.file,
            "line": self.source.line,
            "location": self.location,
            "references": list(self.references),
            "tags": list(self.tags),
            "fingerprint": self.fingerprint,
        }


@dataclass
class RelationSpec:
    """Cross-resource lookup used to build the ``related`` list for a policy."""

    types: list[str]
    reference: bool = False
    via: list[str] = field(default_factory=list)
    target: str = "id"
    scope: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": list(self.types),
            "reference": self.reference,
            "via": list(self.via),
            "target": self.target,
            "scope": self.scope,
        }


@dataclass
class Policy:
    """A validated policy definition."""

    id: str
    title: str
    description: str
    severity: Severity
    provider: str
    resource_patterns: list[str]
    assert_expr: str
    message: str
    remediation: str
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    relations: list[RelationSpec] = field(default_factory=list)
    location: list[str] = field(default_factory=list)
    expression: ast.Expression | None = field(default=None, repr=False, compare=False)
    source_file: str = ""

    def matches(self, resource: Resource) -> bool:
        from fnmatch import fnmatchcase

        if resource.provider != self.provider:
            return False
        return any(fnmatchcase(resource.type, pattern) for pattern in self.resource_patterns)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "provider": self.provider,
            "resource": list(self.resource_patterns),
            "assert": self.assert_expr,
            "message": self.message,
            "remediation": self.remediation,
            "references": list(self.references),
            "tags": list(self.tags),
            "relations": [rel.to_dict() for rel in self.relations],
            "location": list(self.location),
            "source_file": self.source_file,
        }


@dataclass
class EvaluationError:
    """A policy that could not be evaluated for a resource."""

    policy_id: str
    resource_address: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "resource": self.resource_address,
            "message": self.message,
        }


@dataclass
class ScanContext:
    """Everything a report writer needs to render a scan."""

    targets: list[str]
    resources: list[Resource]
    policies: list[Policy]
    findings: list[Finding]
    started_at: datetime
    duration_ms: int = 0
    evaluations: int = 0
    errors: list[EvaluationError] = field(default_factory=list)
    suppressed: list[dict[str, Any]] = field(default_factory=list)
    stale_ignores: list[dict[str, Any]] = field(default_factory=list)
    baseline: dict[str, Any] | None = None
    gate: dict[str, Any] = field(default_factory=dict)

    @property
    def policy_count(self) -> int:
        return len(self.policies)

    def severity_counts(self) -> dict[str, int]:
        counts = {name: 0 for name in SEVERITIES}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    @property
    def exit_code(self) -> int:
        if self.errors:
            return 2
        return 1 if self.gate.get("status") == "fail" else 0
