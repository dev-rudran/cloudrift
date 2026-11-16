"""Configuration and inline ignore tests."""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from cloudrift.config import Config, IgnoreRule, apply_ignores, load_config
from cloudrift.errors import ConfigError
from tests.conftest import make_finding


def write_config(tmp_path: Path, text: str, name: str = "cloudrift.yaml") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_default_config() -> None:
    config = load_config(None, search=False)
    assert config.fail_on == "high"
    assert config.severity == "info"
    assert config.exclude_paths == []
    assert config.ignore == []
    assert config.source_file is None


def test_full_config(tmp_path: Path) -> None:
    path = write_config(
        tmp_path,
        """
fail_on: critical
severity: medium
exclude_paths:
  - "**/vendor/**"
ignore:
  - id: CLDR-0005
    resource: "aws_s3_bucket.logs"
    reason: central logging
    expires: 2027-01-31
""",
    )
    config = load_config(path)
    assert config.fail_on == "critical"
    assert config.severity == "medium"
    assert config.exclude_paths == ["**/vendor/**"]
    assert len(config.ignore) == 1
    rule = config.ignore[0]
    assert rule.id == "CLDR-0005"
    assert rule.resource == "aws_s3_bucket.logs"
    assert rule.reason == "central logging"
    assert rule.expires == date(2027, 1, 31)
    assert config.source_file == str(path)


def test_auto_discovery(tmp_path: Path, monkeypatch) -> None:
    write_config(tmp_path, "fail_on: never\n")
    monkeypatch.chdir(tmp_path)
    config = load_config()
    assert config.fail_on == "never"
    assert config.source_file == "cloudrift.yaml"


def test_missing_explicit_config(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="does not exist"):
        load_config(tmp_path / "missing.yaml")


def test_unknown_config_key(tmp_path: Path) -> None:
    path = write_config(tmp_path, "fail_on: high\nsurprise: true\n")
    with pytest.raises(ConfigError, match="unknown keys"):
        load_config(path)


def test_invalid_fail_on(tmp_path: Path) -> None:
    path = write_config(tmp_path, "fail_on: sometimes\n")
    with pytest.raises(ConfigError, match="fail_on"):
        load_config(path)


def test_invalid_severity(tmp_path: Path) -> None:
    path = write_config(tmp_path, "severity: urgent\n")
    with pytest.raises(ConfigError, match="severity"):
        load_config(path)


def test_invalid_ignore_structures(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="ignore must be a list"):
        load_config(write_config(tmp_path, "ignore: nope\n", "a.yaml"))
    with pytest.raises(ConfigError, match="unknown keys"):
        load_config(write_config(tmp_path, "ignore:\n  - {id: CLDR-0001, bad: 1}\n", "b.yaml"))
    with pytest.raises(ConfigError, match="id must be"):
        load_config(write_config(tmp_path, "ignore:\n  - {resource: x}\n", "c.yaml"))
    with pytest.raises(ConfigError, match="ISO date"):
        load_config(
            write_config(tmp_path, "ignore:\n  - {id: CLDR-0001, expires: someday}\n", "d.yaml")
        )
    with pytest.raises(ConfigError, match="exclude_paths"):
        load_config(write_config(tmp_path, "exclude_paths: nope\n", "e.yaml"))


def test_non_mapping_config(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="mapping"):
        load_config(write_config(tmp_path, "- a\n- b\n"))


def test_empty_config(tmp_path: Path) -> None:
    config = load_config(write_config(tmp_path, ""))
    assert config.fail_on == "high"


def test_ignore_suppresses_matching_finding() -> None:
    finding = make_finding(policy_id="CLDR-0005", address="aws_s3_bucket.logs")
    config = Config(ignore=[IgnoreRule(id="CLDR-0005", reason="accepted")])
    kept, suppressed, stale = apply_ignores([finding], config, today=date(2026, 6, 1))
    assert kept == []
    assert suppressed[0]["policy_id"] == "CLDR-0005"
    assert suppressed[0]["suppressed_by"]["reason"] == "accepted"
    assert stale == []


def test_ignore_resource_glob_and_id_glob() -> None:
    finding = make_finding(policy_id="CLDR-0005", address="aws_s3_bucket.logs")
    config = Config(ignore=[IgnoreRule(id="CLDR-*", resource="aws_s3_bucket.*")])
    kept, suppressed, _ = apply_ignores([finding], config, today=date(2026, 6, 1))
    assert kept == [] and len(suppressed) == 1
    config = Config(ignore=[IgnoreRule(id="CLDR-0005", resource="aws_s3_bucket.other")])
    kept, suppressed, _ = apply_ignores([finding], config, today=date(2026, 6, 1))
    assert len(kept) == 1 and suppressed == []


def test_expired_ignore_is_stale_and_does_not_suppress() -> None:
    finding = make_finding(policy_id="CLDR-0005", address="aws_s3_bucket.logs")
    config = Config(
        ignore=[
            IgnoreRule(
                id="CLDR-0005",
                reason="temporary",
                expires=date(2026, 1, 1),
            )
        ]
    )
    kept, suppressed, stale = apply_ignores([finding], config, today=date(2026, 6, 1))
    assert len(kept) == 1
    assert suppressed == []
    assert stale[0]["id"] == "CLDR-0005"
    assert stale[0]["expires"] == "2026-01-01"


def test_ignore_expires_today_is_active() -> None:
    finding = make_finding(policy_id="CLDR-0005")
    config = Config(ignore=[IgnoreRule(id="CLDR-0005", expires=date(2026, 6, 1))])
    kept, suppressed, stale = apply_ignores([finding], config, today=date(2026, 6, 1))
    assert kept == [] and len(suppressed) == 1 and stale == []


def test_cli_ignores() -> None:
    findings = [
        make_finding(policy_id="CLDR-0001"),
        make_finding(policy_id="CLDR-0002"),
    ]
    kept, suppressed, _ = apply_ignores(findings, Config(), ["CLDR-0001"], today=date(2026, 6, 1))
    assert [finding.policy_id for finding in kept] == ["CLDR-0002"]
    assert suppressed[0]["suppressed_by"]["reason"] == "suppressed by --ignore"


def test_ignore_does_not_touch_unrelated_policy() -> None:
    finding = make_finding(policy_id="CLDR-0001")
    config = Config(ignore=[IgnoreRule(id="CLDR-0002")])
    kept, suppressed, _ = apply_ignores([finding], config, today=date(2026, 6, 1))
    assert kept == [finding] and suppressed == []
