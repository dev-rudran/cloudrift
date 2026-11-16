"""Baseline creation and drift tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cloudrift.baseline import SCHEMA, compare_baseline, load_baseline, write_baseline
from cloudrift.errors import BaselineError
from tests.conftest import make_finding


def test_write_and_load_baseline(tmp_path: Path) -> None:
    findings = [
        make_finding(policy_id="CLDR-0001", address="aws_s3_bucket.logs"),
        make_finding(policy_id="CLDR-0003", address="aws_s3_bucket.logs"),
    ]
    path = tmp_path / "baseline.json"
    baseline = write_baseline(path, findings)
    assert baseline.size == 2
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["schema"] == SCHEMA
    assert data["tool"]["name"] == "cloudrift"
    assert data["count"] == 2
    assert len(data["findings"]) == 2
    loaded = load_baseline(path)
    assert loaded.fingerprints == baseline.fingerprints
    assert loaded.entries[0]["fingerprint"]


def test_baseline_is_sorted_and_deterministic(tmp_path: Path) -> None:
    findings = [
        make_finding(policy_id="CLDR-0003", address="b"),
        make_finding(policy_id="CLDR-0001", address="a"),
    ]
    first = tmp_path / "one.json"
    second = tmp_path / "two.json"
    write_baseline(first, findings)
    write_baseline(second, list(reversed(findings)))
    left = json.loads(first.read_text())["findings"]
    right = json.loads(second.read_text())["findings"]
    assert left == right
    assert [entry["fingerprint"] for entry in left] == sorted(
        entry["fingerprint"] for entry in left
    )


def test_compare_baseline_new_existing_fixed(tmp_path: Path) -> None:
    old = make_finding(policy_id="CLDR-0001", address="aws_s3_bucket.old")
    existing = make_finding(policy_id="CLDR-0003", address="aws_s3_bucket.logs")
    new = make_finding(policy_id="CLDR-0005", address="aws_s3_bucket.logs")
    baseline = write_baseline(tmp_path / "baseline.json", [old, existing])
    diff = compare_baseline([existing, new], baseline)
    assert [finding.policy_id for finding in diff.new] == ["CLDR-0005"]
    assert [finding.policy_id for finding in diff.existing] == ["CLDR-0003"]
    assert len(diff.fixed) == 1
    assert diff.fixed[0]["policy_id"] == "CLDR-0001"
    payload = diff.to_dict()
    assert payload == {
        "enabled": True,
        "new": 1,
        "existing": 1,
        "fixed": 1,
        "fixed_findings": diff.fixed,
    }


def test_fingerprint_is_stable_and_scoped(tmp_path: Path) -> None:
    one = make_finding(policy_id="CLDR-0001", address="aws_s3_bucket.a", file="a.json")
    same = make_finding(policy_id="CLDR-0001", address="aws_s3_bucket.a", file="a.json")
    different_policy = make_finding(policy_id="CLDR-0002", address="aws_s3_bucket.a", file="a.json")
    different_file = make_finding(policy_id="CLDR-0001", address="aws_s3_bucket.a", file="b.json")
    assert one.fingerprint == same.fingerprint
    assert one.fingerprint != different_policy.fingerprint
    assert one.fingerprint != different_file.fingerprint
    assert len(one.fingerprint) == 16


def test_load_missing_baseline(tmp_path: Path) -> None:
    with pytest.raises(BaselineError, match="does not exist"):
        load_baseline(tmp_path / "missing.json")


def test_load_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{nope", encoding="utf-8")
    with pytest.raises(BaselineError, match="invalid JSON"):
        load_baseline(path)


def test_load_invalid_shape(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text('{"findings": "nope"}', encoding="utf-8")
    with pytest.raises(BaselineError, match="findings list"):
        load_baseline(path)
    path.write_text('{"findings": [{"policy_id": "x"}]}', encoding="utf-8")
    with pytest.raises(BaselineError, match="fingerprint"):
        load_baseline(path)
    path.write_text('{"findings": [1]}', encoding="utf-8")
    with pytest.raises(BaselineError, match="mapping"):
        load_baseline(path)


def test_load_baseline_deduplicates_fingerprints(tmp_path: Path) -> None:
    finding = make_finding()
    path = tmp_path / "baseline.json"
    write_baseline(path, [finding])
    data = json.loads(path.read_text())
    data["findings"].append(dict(data["findings"][0]))
    path.write_text(json.dumps(data), encoding="utf-8")
    baseline = load_baseline(path)
    assert baseline.size == 1
    assert len(baseline.entries) == 1


def test_write_baseline_creates_parent(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "dir" / "baseline.json"
    write_baseline(path, [make_finding()])
    assert path.exists()
