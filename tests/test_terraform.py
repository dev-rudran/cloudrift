"""Terraform plan and state ingestion tests."""

from __future__ import annotations

import pytest

from cloudrift.errors import InputError
from cloudrift.inputs.terraform import load_terraform


def resource(type_name, name, values=None, address=None, mode="managed"):
    entry = {
        "mode": mode,
        "type": type_name,
        "name": name,
        "values": values or {},
    }
    if address is not None:
        entry["address"] = address
    return entry


def change(address, type_name, name, actions, after=None):
    return {
        "address": address,
        "mode": "managed",
        "type": type_name,
        "name": name,
        "change": {"actions": actions, "before": None, "after": after},
    }


def test_plan_root_resources() -> None:
    plan = {
        "format_version": "1.2",
        "planned_values": {
            "root_module": {
                "resources": [
                    resource("aws_s3_bucket", "logs", {"bucket": "logs"}),
                ]
            }
        },
    }
    resources = load_terraform(plan, "plan.json")
    assert len(resources) == 1
    bucket = resources[0]
    assert bucket.address == "aws_s3_bucket.logs"
    assert bucket.provider == "aws"
    assert bucket.module is None
    assert bucket.source.file == "plan.json"
    assert bucket.origin == "terraform-plan"


def test_plan_child_modules_recursion() -> None:
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [resource("aws_vpc", "main", {"cidr_block": "10.0.0.0/16"})],
                "child_modules": [
                    {
                        "address": "module.network",
                        "resources": [
                            resource(
                                "aws_subnet",
                                "public",
                                {"cidr_block": "10.0.1.0/24"},
                                address="module.network.aws_subnet.public",
                            )
                        ],
                        "child_modules": [
                            {
                                "address": "module.network.module.inner",
                                "resources": [
                                    resource(
                                        "aws_route_table",
                                        "main",
                                        {},
                                        address="module.network.module.inner.aws_route_table.main",
                                    )
                                ],
                            }
                        ],
                    }
                ],
            }
        }
    }
    resources = load_terraform(plan, "plan.json")
    addresses = {item.address for item in resources}
    assert addresses == {
        "aws_vpc.main",
        "module.network.aws_subnet.public",
        "module.network.module.inner.aws_route_table.main",
    }
    subnet = next(item for item in resources if item.name == "public")
    assert subnet.module == "module.network"
    inner = next(item for item in resources if item.name == "main" and "route" in item.type)
    assert inner.module == "module.network.module.inner"


def test_deleted_resources_are_ignored() -> None:
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [
                    resource("aws_s3_bucket", "kept"),
                    resource("aws_s3_bucket", "removed", {"acl": "public-read"}),
                ]
            }
        },
        "resource_changes": [
            change("aws_s3_bucket.kept", "aws_s3_bucket", "kept", ["create"], {}),
            change("aws_s3_bucket.removed", "aws_s3_bucket", "removed", ["delete"], None),
        ],
    }
    resources = load_terraform(plan, "plan.json")
    assert [item.name for item in resources] == ["kept"]


def test_replacement_and_update_are_kept() -> None:
    plan = {
        "resource_changes": [
            change("aws_instance.a", "aws_instance", "a", ["delete", "create"], {"ami": "x"}),
            change("aws_instance.b", "aws_instance", "b", ["update"], {"ami": "y"}),
            change("aws_instance.c", "aws_instance", "c", ["no-op"], {"ami": "z"}),
        ],
    }
    resources = load_terraform(plan, "plan.json")
    assert {item.name for item in resources} == {"a", "b", "c"}


def test_data_sources_are_ignored() -> None:
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [
                    resource("aws_ami", "ubuntu", {}, mode="data"),
                    resource("aws_instance", "web", {}),
                ]
            }
        }
    }
    resources = load_terraform(plan, "plan.json")
    assert [item.type for item in resources] == ["aws_instance"]


def test_resource_changes_fallback_when_planned_values_missing() -> None:
    plan = {
        "format_version": "1.2",
        "resource_changes": [
            change("aws_s3_bucket.logs", "aws_s3_bucket", "logs", ["create"], {"acl": "private"}),
            change("aws_s3_bucket.gone", "aws_s3_bucket", "gone", ["delete"], None),
        ],
    }
    resources = load_terraform(plan, "plan.json")
    assert [item.address for item in resources] == ["aws_s3_bucket.logs"]
    assert resources[0].values["acl"] == "private"


def test_state_document_uses_values_root_module() -> None:
    state = {
        "version": 4,
        "terraform_version": "1.9.8",
        "values": {
            "root_module": {
                "resources": [resource("aws_iam_policy", "app", {"policy": "{}"}, address=None)]
            }
        },
    }
    resources = load_terraform(state, "state.json")
    assert len(resources) == 1
    assert resources[0].origin == "terraform-state"


def test_prior_state_is_used_when_no_other_values() -> None:
    export = {
        "format_version": "1.0",
        "prior_state": {
            "values": {
                "root_module": {"resources": [resource("aws_s3_bucket", "old", {"acl": "private"})]}
            }
        },
    }
    resources = load_terraform(export, "export.json")
    assert [item.name for item in resources] == ["old"]


def test_configuration_references_are_attached() -> None:
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [
                    resource("aws_instance", "web", {"vpc_security_group_ids": ["sg-1"]}),
                    resource("aws_security_group", "web", {"id": "sg-1"}),
                ],
                "child_modules": [
                    {
                        "address": "module.storage",
                        "resources": [
                            resource(
                                "aws_s3_bucket",
                                "assets",
                                {},
                                address="module.storage.aws_s3_bucket.assets",
                            )
                        ],
                    }
                ],
            }
        },
        "configuration": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_instance.web",
                        "mode": "managed",
                        "type": "aws_instance",
                        "name": "web",
                        "expressions": {
                            "vpc_security_group_ids": {"references": ["aws_security_group.web.id"]}
                        },
                    }
                ],
                "module_calls": {
                    "storage": {
                        "module": {
                            "resources": [
                                {
                                    "address": "aws_s3_bucket.assets",
                                    "mode": "managed",
                                    "type": "aws_s3_bucket",
                                    "name": "assets",
                                    "expressions": {
                                        "kms_key_id": {"references": ["aws_kms_key.main.arn"]}
                                    },
                                }
                            ]
                        }
                    }
                },
            }
        },
    }
    resources = load_terraform(plan, "plan.json")
    instance = next(item for item in resources if item.type == "aws_instance")
    assert "aws_security_group.web.id" in instance.refs
    bucket = next(item for item in resources if item.type == "aws_s3_bucket")
    assert bucket.address == "module.storage.aws_s3_bucket.assets"
    assert "aws_kms_key.main.arn" in bucket.refs


def test_interpolation_references_are_collected() -> None:
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [
                    resource(
                        "aws_lb_target_group_attachment",
                        "web",
                        {
                            "target_group_arn": "${aws_lb_target_group.web.arn}",
                            "target_id": "${aws_instance.web.id}",
                        },
                    )
                ]
            }
        }
    }
    resources = load_terraform(plan, "plan.json")
    assert resources[0].refs == {
        "aws_lb_target_group.web.arn",
        "aws_instance.web.id",
    }


def test_variable_interpolations_are_not_refs() -> None:
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [
                    resource(
                        "aws_s3_bucket",
                        "logs",
                        {"bucket": "${var.name}-logs", "tags": {"env": "${local.env}"}},
                    )
                ]
            }
        }
    }
    resources = load_terraform(plan, "plan.json")
    assert resources[0].refs == set()


def test_missing_address_is_computed_from_module() -> None:
    plan = {
        "planned_values": {
            "root_module": {
                "child_modules": [
                    {
                        "address": "module.storage",
                        "resources": [
                            {
                                "mode": "managed",
                                "type": "aws_s3_bucket",
                                "name": "logs",
                                "values": {},
                            }
                        ],
                    }
                ]
            }
        }
    }
    resources = load_terraform(plan, "plan.json")
    assert resources[0].address == "module.storage.aws_s3_bucket.logs"
    assert resources[0].module == "module.storage"


def test_non_terraform_document_is_rejected() -> None:
    with pytest.raises(InputError, match="not a Terraform"):
        load_terraform({"hello": "world"}, "plan.json")
    with pytest.raises(InputError, match="JSON object"):
        load_terraform([], "plan.json")


def test_empty_plan_is_valid() -> None:
    plan = {"format_version": "1.2", "planned_values": {"root_module": {"resources": []}}}
    assert load_terraform(plan, "plan.json") == []


def test_duplicate_scanning_is_not_performed_for_data_sources() -> None:
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [
                    resource(
                        "aws_iam_policy",
                        "data_policy",
                        {"policy": "{}"},
                        mode="data",
                    )
                ]
            }
        }
    }
    assert load_terraform(plan, "plan.json") == []
