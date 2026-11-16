"""Shared test fixtures and helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
import yaml

from cloudrift.inputs.normalize import make_kubernetes_resource
from cloudrift.models import Finding, Policy, Resource, ScanContext, Severity, SourceRef
from cloudrift.policy.loader import load_bundled_policies

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return ROOT


@pytest.fixture(scope="session")
def bundled_policies() -> list[Policy]:
    return load_bundled_policies()


@pytest.fixture(scope="session")
def policies_by_id(bundled_policies: list[Policy]) -> dict[str, Policy]:
    return {policy.id: policy for policy in bundled_policies}


def build_resource(entry: dict[str, Any], line: int = 1) -> Resource:
    """Build a resource from a policy-case entry."""

    if "manifest" in entry:
        resource = make_kubernetes_resource(
            data=entry["manifest"],
            source=SourceRef(file="policy_cases.yml", line=line),
            key_lines={},
        )
        assert resource is not None
        return resource
    provider = entry.get("provider", "aws")
    type_name = entry["type"]
    name = entry["name"]
    return Resource(
        provider=provider,
        type=type_name,
        name=name,
        address=f"{type_name}.{name}",
        values=dict(entry.get("values") or {}),
        refs=set(entry.get("refs") or []),
        source=SourceRef(file="policy_cases.yml", line=line),
    )


def load_policy_cases() -> dict[str, dict[str, list[dict[str, Any]]]]:
    return yaml.safe_load((FIXTURES / "policy_cases.yml").read_text(encoding="utf-8"))


def make_finding(
    policy_id: str = "CLDR-0001",
    severity: Severity = Severity.HIGH,
    address: str = "aws_s3_bucket.logs",
    file: str = "plan.json",
    line: int | None = None,
    message: str = "bucket is public",
) -> Finding:
    return Finding(
        policy_id=policy_id,
        title="Test finding",
        severity=severity,
        message=message,
        remediation="fix it",
        resource_address=address,
        resource_type="aws_s3_bucket",
        provider="aws",
        source=SourceRef(file=file, line=line),
        references=["https://example.com/rule"],
        tags=["s3"],
    )


def make_context(
    *,
    findings: list[Finding] | None = None,
    policies: list[Policy] | None = None,
    gate_status: str = "pass",
    fail_on: str = "high",
    errors: list | None = None,
    baseline: dict | None = None,
    suppressed: list[dict] | None = None,
    stale: list[dict] | None = None,
) -> ScanContext:
    policies = policies if policies is not None else load_bundled_policies()
    findings = findings or []
    return ScanContext(
        targets=["examples/test"],
        resources=[
            Resource(
                provider="aws",
                type="aws_s3_bucket",
                name="logs",
                address="aws_s3_bucket.logs",
                values={"acl": "public-read"},
                source=SourceRef(file="plan.json"),
            )
        ],
        policies=policies,
        findings=findings,
        started_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
        duration_ms=12,
        evaluations=7,
        errors=errors or [],
        suppressed=suppressed or [],
        stale_ignores=stale or [],
        baseline=baseline,
        gate={"fail_on": fail_on, "status": gate_status},
    )
