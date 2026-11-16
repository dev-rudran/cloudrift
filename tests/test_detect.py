"""Input discovery and classification tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cloudrift.errors import InputError
from cloudrift.inputs.detect import (
    detect_document,
    detect_text,
    discover,
    load_inputs,
)

PLAN = {
    "format_version": "1.2",
    "planned_values": {
        "root_module": {
            "resources": [
                {
                    "mode": "managed",
                    "type": "aws_s3_bucket",
                    "name": "logs",
                    "values": {"acl": "private"},
                }
            ]
        }
    },
}
STATE = {
    "version": 4,
    "terraform_version": "1.9.8",
    "values": {
        "root_module": {
            "resources": [
                {"mode": "managed", "type": "aws_s3_bucket", "name": "logs", "values": {}}
            ]
        }
    },
}
K8S = "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: config}\n"


def test_detect_document() -> None:
    assert detect_document(PLAN) == "terraform"
    assert detect_document(STATE) == "terraform"
    assert detect_document({"kind": "Pod", "metadata": {"name": "x"}}) == "kubernetes"
    assert detect_document([{"kind": "ConfigMap"}]) == "kubernetes"
    assert detect_document({"random": True}) is None
    assert detect_document([]) is None
    assert detect_document("text") is None


def test_detect_text_json_and_yaml() -> None:
    assert detect_text(json.dumps(PLAN), "plan.json", ".json") == "terraform"
    assert detect_text(K8S, "cm.yaml", ".yaml") == "kubernetes"
    assert detect_text("foo: bar", "unknown.yaml", ".yaml") is None
    assert detect_text('{"kind": "Pod"}', "<stdin>", "") == "kubernetes"
    assert detect_text(json.dumps(PLAN), "<stdin>", "") == "terraform"


def test_detect_text_invalid_json() -> None:
    with pytest.raises(InputError, match="invalid JSON"):
        detect_text("{oops", "plan.json", ".json")


def test_detect_text_without_suffix_prefers_json_then_yaml() -> None:
    with pytest.raises(InputError, match="invalid YAML"):
        detect_text("{not json", "<stdin>", "")


def test_discover_directory_and_skip_rules(tmp_path: Path) -> None:
    (tmp_path / "plan.json").write_text(json.dumps(PLAN), encoding="utf-8")
    (tmp_path / "k8s").mkdir()
    (tmp_path / "k8s" / "cm.yaml").write_text(K8S, encoding="utf-8")
    (tmp_path / "notes.txt").write_text("ignore", encoding="utf-8")
    for skipped in (".terraform", ".git", "node_modules", "__pycache__"):
        directory = tmp_path / skipped
        directory.mkdir()
        (directory / "plan.json").write_text(json.dumps(PLAN), encoding="utf-8")
    discovered = discover([str(tmp_path)])
    kinds = sorted((Path(item.path).name, item.kind) for item in discovered)
    assert kinds == [("cm.yaml", "kubernetes"), ("plan.json", "terraform")]


def test_discover_explicit_file_and_missing_path(tmp_path: Path) -> None:
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(PLAN), encoding="utf-8")
    [item] = discover([str(plan)])
    assert item.kind == "terraform" and item.explicit
    with pytest.raises(InputError, match="does not exist"):
        discover([str(tmp_path / "nope.json")])


def test_absolute_paths_inside_cwd_are_reported_relative(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(PLAN), encoding="utf-8")
    [item] = discover([str(plan)])
    assert item.path == "plan.json"
    resources = load_inputs([str(plan)])
    assert resources[0].source.file == "plan.json"


def test_discover_explicit_unsupported_file(tmp_path: Path) -> None:
    notes = tmp_path / "notes.txt"
    notes.write_text("hello", encoding="utf-8")
    with pytest.raises(InputError, match="unsupported input type"):
        discover([str(notes)])


def test_discover_unrecognized_json_is_an_error_when_explicit(tmp_path: Path) -> None:
    path = tmp_path / "package.json"
    path.write_text('{"name": "not-infra"}', encoding="utf-8")
    with pytest.raises(InputError, match="unrecognized input"):
        discover([str(path)])


def test_discover_empty_file_is_an_error_when_explicit(tmp_path: Path) -> None:
    path = tmp_path / "empty.yaml"
    path.write_text("\n", encoding="utf-8")
    with pytest.raises(InputError, match="empty"):
        discover([str(path)])


def test_discover_no_inputs(tmp_path: Path) -> None:
    (tmp_path / "readme.md").write_text("docs", encoding="utf-8")
    with pytest.raises(InputError, match="no supported input"):
        discover([str(tmp_path)])


def test_exclude_paths(tmp_path: Path) -> None:
    (tmp_path / "plan.json").write_text(json.dumps(PLAN), encoding="utf-8")
    ignored = tmp_path / "ignored"
    ignored.mkdir()
    (ignored / "plan.json").write_text(json.dumps(PLAN), encoding="utf-8")
    discovered = discover([str(tmp_path)], ["*/ignored/*"])
    assert len(discovered) == 1
    assert discovered[0].path.endswith("plan.json")
    assert "ignored" not in discovered[0].path


def test_load_inputs_stdin_plan() -> None:
    resources = load_inputs(["-"], stdin_text=json.dumps(PLAN))
    assert [resource.address for resource in resources] == ["aws_s3_bucket.logs"]
    assert resources[0].source.file == "<stdin>"


def test_load_inputs_stdin_yaml() -> None:
    resources = load_inputs(["-"], stdin_text=K8S)
    assert resources[0].address == "kubernetes_config_map.default.config"


def test_load_inputs_stdin_required() -> None:
    with pytest.raises(InputError, match="stdin was requested"):
        load_inputs(["-"], stdin_text=None)


def test_load_inputs_mixed_sources(tmp_path: Path) -> None:
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(PLAN), encoding="utf-8")
    manifest = tmp_path / "cm.yaml"
    manifest.write_text(K8S, encoding="utf-8")
    resources = load_inputs([str(tmp_path)])
    assert {resource.provider for resource in resources} == {"aws", "kubernetes"}
