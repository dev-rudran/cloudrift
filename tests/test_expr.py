"""Tests for the safe expression language."""

from __future__ import annotations

import pytest

from cloudrift.policy.builtins import FUNCTIONS
from cloudrift.policy.expr import (
    EvaluationError,
    UnsafeExpression,
    compile_expression,
    evaluate_expression,
)

CONTEXT = {
    "resource": {
        "acl": "public-read",
        "port": 443,
        "enabled": True,
        "tags": {"team": "platform", "env": "prod"},
        "ingress": [
            {"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"], "protocol": "tcp"},
            {"from_port": 443, "to_port": 443, "cidr_blocks": ["10.0.0.0/8"], "protocol": "tcp"},
        ],
        "containers": [
            {"name": "web", "image": "nginx:1.25.3"},
            {"name": "sidecar", "image": "busybox"},
        ],
        "nested": {"a": {"b": [10, 20]}},
    },
    "related": [
        {"name": "sg", "ingress": [{"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}]}
    ],
}


def run(source: str, context=None):
    return evaluate_expression(compile_expression(source), context or CONTEXT)


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("1 + 2 * 3", 7),
        ("10 / 4", 2.5),
        ("10 // 4", 2),
        ("10 % 4", 2),
        ("'a' + 'b'", "ab"),
        ("[1, 2] + [3]", [1, 2, 3]),
        ("-5 + 2", -3),
        ("not False", True),
        ("resource.port >= 443 and True", True),
        ("resource.port > 1000 or True", True),
        ("1 < 2 < 3", True),
        ("1 < 2 > 3", False),
        ("resource.acl in ('public-read', 'public-read-write')", True),
        ("'private' not in ('public-read', 'private')", False),
        ("resource.acl != 'private'", True),
        ("resource.enabled is True", True),
        ("resource.nope is None", True),
        ("'x' if resource.enabled else 'y'", "x"),
        ("{'a': 1, 'b': 2}['b']", 2),
        ("[10, 20, 30][-1]", 30),
        ("'hello'[1:3]", "el"),
        ("resource.tags['team']", "platform"),
        ("resource.nested.a.b[1]", 20),
        ("len(resource.containers)", 2),
        ("any(endswith(c.image, '3') for c in resource.containers)", True),
        (
            "all(c.image is not None for c in resource.containers)",
            True,
        ),
        (
            "[c.name for c in resource.containers if c.name == 'web']",
            ["web"],
        ),
        (
            "[(c.name, c.image) for c in resource.containers]",
            [("web", "nginx:1.25.3"), ("sidecar", "busybox")],
        ),
    ],
)
def test_expression_semantics(source: str, expected) -> None:
    assert run(source) == expected


def test_missing_attributes_are_none() -> None:
    assert run("resource.missing") is None
    assert run("resource.missing.deeper") is None
    assert run("resource['missing']") is None
    assert run("missing(resource.missing)") is True
    assert run("exists(resource.missing)") is False
    assert run("exists(resource.port)") is True


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("len(None)", 0),
        ("len('abc')", 3),
        ("len({'a': 1, 'b': 2})", 2),
        ("len(42)", 0),
        ("any([])", False),
        ("any([0, None, 1])", True),
        ("all([])", True),
        ("all([1, 2])", True),
        ("lower('AB')", "ab"),
        ("upper('ab')", "AB"),
        ("lower(None)", ""),
        ("contains('abc', 'b')", True),
        ("contains([1, 2], 2)", True),
        ("contains(None, 1)", False),
        ("startswith('abc', 'ab')", True),
        ("endswith('abc', 'bc')", True),
        ("startswith(None, 'a')", False),
        ("cidr_contains('10.0.0.0/8', '10.1.2.3')", True),
        ("cidr_contains('10.0.0.0/8', '11.0.0.1')", False),
        ("is_public_cidr('0.0.0.0/0')", True),
        ("is_public_cidr('::/0')", True),
        ("is_public_cidr('10.0.0.0/8')", False),
        ("is_public_cidr('8.8.8.0/24')", True),
        ("is_public_cidr('not-a-cidr')", False),
        ("get(resource, 'nested.a.b.0', 0)", 10),
        ("get(resource, 'nested.a.missing', 99)", 99),
        ("get(None, 'a', 1)", 1),
        ("to_int('42')", 42),
        ("to_int(4.9)", 4),
        ("to_int(None)", 0),
        ("to_int('nope')", 0),
        ("to_bool('true')", True),
        ("to_bool('false')", False),
        ("to_bool(0)", False),
        ("to_bool(None)", False),
        ("regex_match('DB_PASSWORD', '(?i)password')", True),
        ("regex_match('LOG_LEVEL', '(?i)password')", False),
        ("regex_match(None, 'x')", False),
        ("image_tag('nginx:1.25.3')", "1.25.3"),
        ("image_tag('nginx:latest')", "latest"),
        ("image_tag('nginx')", ""),
        ("image_tag('registry:5000/team/app:v1')", "v1"),
        ("image_tag('app@sha256:abc')", "sha256:abc"),
        ("json_parse('{\"a\": 1}').a", 1),
        ("json_parse('broken')", {}),
        ("keys({'a': 1, 'b': 2})", ["a", "b"]),
        ("values({'a': 1})", [1]),
        ("items({'a': 1})", [["a", 1]]),
        (
            'iam_wildcard_action(\'{"Statement": {"Effect": "Allow", "Action": "s3:*"}}\')',
            True,
        ),
        (
            "iam_wildcard_resource("
            '\'{"Statement": [{"Effect": "Allow", '
            '"Action": "s3:GetObject", "Resource": "*"}]}\''
            ")",
            True,
        ),
        (
            'iam_allow_all(\'{"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}\')',
            True,
        ),
        (
            "iam_public_principal("
            '\'{"Statement": {"Effect": "Allow", '
            '"Principal": "*", "Action": "s3:GetObject"}}\''
            ")",
            True,
        ),
    ],
)
def test_builtin_functions(source: str, expected) -> None:
    assert run(source) == expected


def test_iam_condition_suppresses_public_principal() -> None:
    policy = (
        '{"Statement": {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", '
        '"Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-123"}}}}'
    )
    assert run(f"iam_public_principal('{policy}')") is False


def test_sg_ingress_rules_normalizes_group_and_rule() -> None:
    assert run("len(sg_ingress_rules(resource))") == 2
    rule = {
        "resource": {
            "resource_type": "aws_security_group_rule",
            "type": "ingress",
            "from_port": 22,
            "to_port": 22,
            "cidr_blocks": ["0.0.0.0/0"],
        }
    }
    assert run("len(sg_ingress_rules(resource))", rule) == 1
    egress = {
        "resource": {
            "resource_type": "aws_security_group_rule",
            "type": "egress",
        }
    }
    assert run("len(sg_ingress_rules(resource))", egress) == 0


def test_age_days_handles_timestamps() -> None:
    assert run("age_days('2020-01-01T00:00:00Z') > 1000") is True
    assert run("age_days('not-a-date')") == 0
    assert run("age_days(None)") == 0


@pytest.mark.parametrize(
    "source",
    [
        "__import__('os').system('id')",
        "().__class__.__bases__",
        "open('/etc/passwd')",
        "resource.__class__",
        "resource['__class__']",
        "resource.tags.__dict__",
        "lambda: 1",
    ],
)
def test_safe_expression_allows_only_expected_constructs(source: str) -> None:
    with pytest.raises(UnsafeExpression):
        compile_expression(source)


def test_conditional_expression_is_supported() -> None:
    assert run("[x for x in [1, 2]] if False else 1") == 1


def test_unsafe_calls_and_names_are_rejected() -> None:
    for source in (
        "exec('1')",
        "eval('1')",
        "getattr(resource, 'acl')",
        "resource.get('acl')",
        "''.join(['a'])",
        "unknown_name",
        "resource.containers.pop()",
    ):
        with pytest.raises(UnsafeExpression):
            compile_expression(source)


def test_lambda_and_walrus_are_rejected() -> None:
    with pytest.raises(UnsafeExpression):
        compile_expression("(lambda: 1)()")
    with pytest.raises(UnsafeExpression):
        compile_expression("(x := 1) + x")


def test_giant_expression_is_rejected_by_node_limit() -> None:
    source = "[" + ", ".join(["1"] * 600) + "]"
    with pytest.raises(UnsafeExpression, match="maximum size"):
        compile_expression(source)


def test_deep_nesting_is_rejected() -> None:
    source = "not " * 60 + "True"
    with pytest.raises(UnsafeExpression, match="nesting"):
        compile_expression(source)


def test_invalid_syntax_is_reported() -> None:
    with pytest.raises(UnsafeExpression, match="syntax"):
        compile_expression("1 +")
    with pytest.raises(UnsafeExpression):
        compile_expression("")
    with pytest.raises(UnsafeExpression):
        compile_expression("   ")


def test_runtime_errors_are_wrapped() -> None:
    with pytest.raises(EvaluationError, match="division by zero"):
        run("1 / 0")
    with pytest.raises(EvaluationError, match="cannot apply"):
        run("resource.tags + 1")
    with pytest.raises(EvaluationError, match="too large"):
        run("'a' * 2000000")
    with pytest.raises(EvaluationError):
        run("len('a', 'b')")


def test_comprehension_targets_must_be_names() -> None:
    with pytest.raises(UnsafeExpression):
        compile_expression("[x for resource.acl in [1]]")
    with pytest.raises(UnsafeExpression):
        compile_expression("[x for (x, *y) in [[1, 2]]]")


def test_too_many_comprehension_generators_rejected() -> None:
    source = "[" + "x" + " for a in [1] for b in [1] for c in [1] for d in [1] for e in [1]]"
    with pytest.raises(UnsafeExpression, match="too many generators"):
        compile_expression(source)


def test_context_is_not_mutated() -> None:
    context = {"resource": {"a": 1}, "related": []}
    evaluate_expression(compile_expression("[x for x in [1, 2]]"), context)
    assert context == {"resource": {"a": 1}, "related": []}


def test_function_registry_contains_documented_functions() -> None:
    expected = {
        "len",
        "any",
        "all",
        "lower",
        "upper",
        "contains",
        "startswith",
        "endswith",
        "cidr_contains",
        "exists",
        "missing",
        "get",
        "to_int",
        "to_bool",
        "regex_match",
        "is_public_cidr",
    }
    assert expected <= set(FUNCTIONS)
