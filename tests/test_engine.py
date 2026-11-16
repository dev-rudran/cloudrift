"""Policy engine and cross-resource relation tests."""

from __future__ import annotations

from cloudrift.models import Policy, Resource, Severity, SourceRef
from cloudrift.policy.engine import evaluate_policies, resource_view
from cloudrift.policy.loader import parse_policy_text

CASE = """
policies:
  - id: CLDR-9000
    title: Test policy
    description: Test policy description
    severity: high
    provider: __PROVIDER__
    resource: __RESOURCE__
    assert: >-
      __ASSERT__
    message: >-
      __MESSAGE__
    remediation: >-
      remediate __NAME__
"""


def make_policy(
    assertion: str,
    resource: str = "aws_s3_bucket",
    provider: str = "aws",
    message: str = "bad resource {name} at {address}",
) -> Policy:
    text = (
        CASE.replace("__PROVIDER__", provider)
        .replace("__RESOURCE__", resource)
        .replace("__ASSERT__", assertion)
        .replace("__MESSAGE__", message)
        .replace("__NAME__", "resource")
    )
    return parse_policy_text(text, "inline.yml")[0]


def make_resource(
    type_name="aws_s3_bucket",
    name="logs",
    values=None,
    provider=None,
    refs=None,
    namespace=None,
    key_lines=None,
) -> Resource:
    provider = provider or type_name.split("_", 1)[0]
    return Resource(
        provider=provider,
        type=type_name,
        name=name,
        address=f"{type_name}.{name}" if namespace is None else f"{type_name}.{namespace}.{name}",
        values=values or {},
        refs=set(refs or []),
        namespace=namespace,
        key_lines=key_lines or {},
        source=SourceRef(file="test.yaml", line=10),
    )


def test_matching_and_findings() -> None:
    policy = make_policy("resource.acl == 'private'")
    public = make_resource(values={"acl": "public-read"})
    private = make_resource("aws_s3_bucket", "safe", {"acl": "private"})
    result = evaluate_policies([policy], [public, private])
    assert len(result.findings) == 1
    assert result.findings[0].resource_address == "aws_s3_bucket.logs"
    assert result.evaluations == 2


def test_provider_filtering() -> None:
    policy = make_policy("False", resource="aws_s3_bucket")
    other = make_resource("google_storage_bucket", "logs", provider="google")
    assert evaluate_policies([policy], [other]).findings == []


def test_wildcard_resource_matching() -> None:
    policy = make_policy("True", resource="aws_iam_*")
    resources = [
        make_resource("aws_iam_policy", "a"),
        make_resource("aws_iam_role", "b"),
        make_resource("aws_s3_bucket", "c"),
    ]
    result = evaluate_policies([policy], resources)
    assert result.evaluations == 2
    assert result.findings == []


def test_message_placeholders() -> None:
    finding = evaluate_policies(
        [make_policy("False")], [make_resource(values={"acl": "public-read"})]
    ).findings[0]
    assert finding.message == "bad resource logs at aws_s3_bucket.logs"
    assert finding.remediation == "remediate resource"


def test_bool_result_semantics() -> None:
    policy = make_policy("contains(resource.tags, 'env')")
    tagged = make_resource(values={"tags": {"env": "prod"}})
    untagged = make_resource("aws_s3_bucket", "untagged", {})
    result = evaluate_policies([policy], [tagged, untagged])
    assert [finding.resource_address for finding in result.findings] == ["aws_s3_bucket.untagged"]


def test_location_from_policy_key_path() -> None:
    text = """
policies:
  - id: CLDR-9001
    title: Use key line
    description: location test
    severity: low
    provider: kubernetes
    resource: kubernetes_deployment
    location:
      - spec.template.spec.containers
      - spec.containers
    assert: "False"
    message: bad
    remediation: fix
"""
    policy = parse_policy_text(text, "inline.yml")[0]
    resource = make_resource(
        "kubernetes_deployment",
        "web",
        {"metadata": {"name": "web"}},
        namespace="prod",
        key_lines={"spec.template.spec.containers": 17},
    )
    finding = evaluate_policies([policy], [resource]).findings[0]
    assert finding.source.line == 17
    assert finding.location == "test.yaml:17"


def test_location_falls_back_to_resource_line() -> None:
    text = """
policies:
  - id: CLDR-9001
    title: Fallback
    description: location test
    severity: low
    provider: aws
    resource: aws_s3_bucket
    location: ["absent.path"]
    assert: "False"
    message: bad
    remediation: fix
"""
    policy = parse_policy_text(text, "inline.yml")[0]
    finding = evaluate_policies([policy], [make_resource(key_lines={"other": 1})]).findings[0]
    assert finding.source.line == 10


def test_relation_by_reference(policies_by_id) -> None:
    policy = policies_by_id["CLDR-0031"]
    instance = make_resource(
        "aws_instance",
        "web",
        {"associate_public_ip_address": True, "vpc_security_group_ids": ["sg-1"]},
        refs={"aws_security_group.web.id"},
    )
    sg = make_resource(
        "aws_security_group",
        "web",
        {
            "id": "sg-1",
            "ingress": [
                {
                    "from_port": 22,
                    "to_port": 22,
                    "protocol": "tcp",
                    "cidr_blocks": ["0.0.0.0/0"],
                }
            ],
        },
    )
    result = evaluate_policies([policy], [instance, sg])
    assert len(result.findings) == 1
    assert result.findings[0].resource_address == "aws_instance.web"


def test_relation_does_not_link_unrelated_group(policies_by_id) -> None:
    policy = policies_by_id["CLDR-0031"]
    instance = make_resource(
        "aws_instance",
        "web",
        {"associate_public_ip_address": True, "vpc_security_group_ids": ["sg-1"]},
    )
    sg = make_resource(
        "aws_security_group",
        "other",
        {
            "id": "sg-2",
            "ingress": [
                {
                    "from_port": 22,
                    "to_port": 22,
                    "protocol": "tcp",
                    "cidr_blocks": ["0.0.0.0/0"],
                }
            ],
        },
    )
    assert evaluate_policies([policy], [instance, sg]).findings == []


def test_relation_via_attribute(policies_by_id) -> None:
    policy = policies_by_id["CLDR-0026"]
    vpc = make_resource("aws_vpc", "main", {"id": "vpc-1"})
    flow = make_resource("aws_flow_log", "main", {"vpc_id": "vpc-1"})
    assert evaluate_policies([policy], [vpc, flow]).findings == []
    other_flow = make_resource("aws_flow_log", "other", {"vpc_id": "vpc-2"})
    assert len(evaluate_policies([policy], [vpc, other_flow]).findings) == 1


def test_relation_namespace_scope(policies_by_id) -> None:
    policy = policies_by_id["CLDR-1017"]
    deployment = make_resource(
        "kubernetes_deployment", "web", {}, provider="kubernetes", namespace="prod"
    )
    network_policy = make_resource(
        "kubernetes_network_policy", "deny", {}, provider="kubernetes", namespace="prod"
    )
    other_policy = make_resource(
        "kubernetes_network_policy", "deny", {}, provider="kubernetes", namespace="dev"
    )
    assert evaluate_policies([policy], [deployment, network_policy]).findings == []
    assert len(evaluate_policies([policy], [deployment, other_policy]).findings) == 1


def test_security_group_rule_resource_is_normalized(policies_by_id) -> None:
    policy = policies_by_id["CLDR-0006"]
    rule = make_resource(
        "aws_security_group_rule",
        "ssh",
        {
            "type": "ingress",
            "from_port": 22,
            "to_port": 22,
            "protocol": "tcp",
            "cidr_blocks": ["0.0.0.0/0"],
        },
    )
    result = evaluate_policies([policy], [rule])
    assert len(result.findings) == 1
    view = resource_view(rule)
    assert view["type"] == "ingress"
    assert view["resource_type"] == "aws_security_group_rule"


def test_evaluation_errors_are_captured_not_raised() -> None:
    policy = make_policy("resource.port + 'x' == '1x'")
    resource = make_resource(values={"port": 22})
    result = evaluate_policies([policy], [resource])
    assert result.findings == []
    assert len(result.errors) == 1
    assert "cannot apply" in result.errors[0].message


def test_engine_sorts_findings() -> None:
    low = make_policy("False", resource="aws_s3_bucket", message="low")
    low.id = "CLDR-9002"
    low.severity = Severity.LOW
    high = make_policy("False", resource="aws_s3_bucket", message="high")
    high.id = "CLDR-9003"
    high.severity = Severity.HIGH
    resources = [make_resource("aws_s3_bucket", "b"), make_resource("aws_s3_bucket", "a")]
    result = evaluate_policies([low, high], resources)
    assert [(f.severity.value, f.resource_address) for f in result.findings] == [
        ("high", "aws_s3_bucket.a"),
        ("high", "aws_s3_bucket.b"),
        ("low", "aws_s3_bucket.a"),
        ("low", "aws_s3_bucket.b"),
    ]


def test_policy_without_match_does_not_evaluate() -> None:
    policy = make_policy("1 / 0 == 0")
    result = evaluate_policies([policy], [make_resource("aws_instance", "web")])
    assert result.evaluations == 0
    assert result.errors == []


def test_related_is_empty_without_relations() -> None:
    policy = make_policy("len(related) == 0")
    result = evaluate_policies([policy], [make_resource()])
    assert result.findings == []


def test_policy_that_uses_related_resources(policies_by_id) -> None:
    policy = policies_by_id["CLDR-0030"]
    secret = make_resource("aws_secretsmanager_secret", "db", {"name": "db-password"})
    rotation = make_resource(
        "aws_secretsmanager_secret_rotation", "db", {"secret_id": "db-password"}
    )
    assert evaluate_policies([policy], [secret, rotation]).findings == []
    assert len(evaluate_policies([policy], [secret]).findings) == 1


def test_missing_assert_ast_is_reported() -> None:
    policy = make_policy("True")
    policy.expression = None
    result = evaluate_policies([policy], [make_resource()])
    assert result.errors and "compiled expression" in result.errors[0].message
