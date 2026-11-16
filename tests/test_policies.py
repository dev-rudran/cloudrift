"""Policy pack validation and per-policy vulnerable/compliant coverage."""

from __future__ import annotations

import re

import pytest

from cloudrift.models import SEVERITIES
from cloudrift.policy.engine import evaluate_policies
from cloudrift.policy.expr import compile_expression
from cloudrift.policy.loader import (
    PolicyError,
    parse_policy_text,
    validate_policies,
)
from tests.conftest import build_resource, load_policy_cases

CASES = load_policy_cases()


def test_policy_pack_has_at_least_35_rules(bundled_policies) -> None:
    assert len(bundled_policies) >= 35


def test_policy_ids_are_unique_and_well_formed(bundled_policies) -> None:
    ids = [policy.id for policy in bundled_policies]
    assert len(ids) == len(set(ids))
    assert all(policy.id.startswith("CLDR-") for policy in bundled_policies)


def test_every_policy_has_a_case(bundled_policies) -> None:
    assert set(CASES) == {policy.id for policy in bundled_policies}


def test_cases_only_reference_known_policies(bundled_policies) -> None:
    known = {policy.id for policy in bundled_policies}
    assert set(CASES) - known == set()


def test_policy_validation_is_clean(bundled_policies) -> None:
    assert validate_policies(bundled_policies) == []


def test_policy_severities_and_providers(bundled_policies) -> None:
    assert {policy.provider for policy in bundled_policies} == {"aws", "kubernetes"}
    severities = {policy.severity.value for policy in bundled_policies}
    assert severities <= set(SEVERITIES)
    assert {"critical", "high", "medium", "low", "info"} <= severities


def test_every_policy_assertion_compiles(bundled_policies) -> None:
    for policy in bundled_policies:
        assert policy.expression is not None
        assert policy.assert_expr
        compile_expression(policy.assert_expr)


def test_messages_use_only_supported_placeholders(bundled_policies) -> None:
    supported = {
        "{address}",
        "{name}",
        "{type}",
        "{provider}",
        "{module}",
        "{namespace}",
    }
    for policy in bundled_policies:
        for template in (policy.message, policy.remediation):
            for placeholder in re.findall(r"\{[A-Za-z_][A-Za-z0-9_.]*\}", template):
                assert placeholder in supported, (
                    f"{policy.id}: unsupported placeholder {placeholder} in {template!r}"
                )


@pytest.mark.parametrize("policy_id", sorted(CASES))
def test_policy_detects_vulnerable_case(policy_id, policies_by_id) -> None:
    policy = policies_by_id[policy_id]
    resources = [build_resource(entry) for entry in CASES[policy_id]["vulnerable"]]
    result = evaluate_policies([policy], resources)
    assert not result.errors, [error.message for error in result.errors]
    assert result.findings, f"{policy_id} did not trigger on its vulnerable case"


@pytest.mark.parametrize("policy_id", sorted(CASES))
def test_policy_accepts_compliant_case(policy_id, policies_by_id) -> None:
    policy = policies_by_id[policy_id]
    resources = [build_resource(entry) for entry in CASES[policy_id]["compliant"]]
    result = evaluate_policies([policy], resources)
    assert not result.errors, [error.message for error in result.errors]
    assert not result.findings, [
        f"{policy_id} flagged {finding.resource_address}: {finding.message}"
        for finding in result.findings
    ]


def test_parse_policy_requires_assert() -> None:
    text = """
policies:
  - id: CLDR-9999
    title: No assertion
    description: missing assert
    severity: high
    provider: aws
    resource: aws_s3_bucket
    message: never
    remediation: add it
"""
    with pytest.raises(PolicyError, match="assert"):
        parse_policy_text(text, "inline.yml")


def test_parse_policy_rejects_unknown_keys() -> None:
    text = """
policies:
  - id: CLDR-9999
    title: Unknown key
    description: nope
    severity: high
    provider: aws
    resource: aws_s3_bucket
    assert: "True"
    message: never
    remediation: add it
    surprise: true
"""
    with pytest.raises(PolicyError, match="unknown keys"):
        parse_policy_text(text, "inline.yml")


def test_parse_policy_rejects_bad_provider() -> None:
    text = """
policies:
  - id: CLDR-9999
    title: Bad provider
    description: nope
    severity: high
    provider: gcp
    resource: google_storage_bucket
    assert: "True"
    message: never
    remediation: add it
"""
    with pytest.raises(PolicyError, match="provider"):
        parse_policy_text(text, "inline.yml")


def test_parse_policy_rejects_unsafe_assert() -> None:
    text = """
policies:
  - id: CLDR-9999
    title: Unsafe
    description: nope
    severity: high
    provider: aws
    resource: aws_s3_bucket
    assert: "__import__('os').system('id') == 0"
    message: never
    remediation: add it
"""
    with pytest.raises(PolicyError, match="assert expression"):
        parse_policy_text(text, "inline.yml")
