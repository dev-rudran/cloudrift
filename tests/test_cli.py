"""End-to-end tests for the command line interface."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from cloudrift import __version__
from cloudrift.cli import main

ROOT = Path(__file__).resolve().parents[1]
VULNERABLE = ROOT / "examples" / "vulnerable"
COMPLIANT = ROOT / "examples" / "compliant"


@pytest.fixture(autouse=True)
def isolated_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Keep config auto-discovery from picking up a developer's file."""

    monkeypatch.chdir(tmp_path)
    return tmp_path


def run(capsys: pytest.CaptureFixture[str], *args: str) -> tuple[int, str, str]:
    code = main(list(args))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def write_policy(directory: Path, body: str) -> Path:
    directory.mkdir(exist_ok=True)
    path = directory / "custom.yml"
    path.write_text(body, encoding="utf-8")
    return path


SINGLE_POLICY = """
policies:
  - id: CLDR-9001
    title: Bucket must be private
    description: Test-only policy used to check custom policy loading.
    severity: high
    provider: aws
    resource: aws_s3_bucket
    assert: resource.acl == "private"
    message: Bucket {name} is not private.
    remediation: Set acl = "private".
"""


def test_version_command(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = run(capsys, "version")
    assert code == 0
    assert out == f"cloudrift {__version__}\n"
    assert err == ""


def test_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_rules_list(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "rules", "list")
    lines = out.splitlines()
    assert code == 0
    assert lines[0].startswith("ID")
    assert len(lines) == 50
    assert any(line.startswith("CLDR-0001") for line in lines)
    assert any(line.startswith("CLDR-1018") for line in lines)


def test_rules_show(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "rules", "show", "CLDR-0001")
    assert code == 0
    assert "CLDR-0001" in out
    assert "Assertion (true means compliant):" in out
    assert "Severity:    critical" in out
    assert "Remediation:" in out


def test_rules_show_unknown_id(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = run(capsys, "rules", "show", "CLDR-9999")
    assert code == 2
    assert out == ""
    assert "policy not found: CLDR-9999" in err


def test_rules_validate_bundled(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = run(capsys, "rules", "validate")
    assert code == 0
    assert out == "49 policies valid\n"
    assert err == ""


def test_rules_validate_custom_pack(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    path = write_policy(tmp_path / "pack", SINGLE_POLICY)
    code, out, _ = run(capsys, "rules", "validate", str(path))
    assert code == 0
    assert out == "1 policies valid\n"


def test_rules_validate_rejects_broken_pack(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    path = write_policy(
        tmp_path / "pack",
        "policies:\n  - id: CLDR-9001\n    title: Missing fields\n",
    )
    code, out, err = run(capsys, "rules", "validate", str(path))
    assert code == 2
    assert out == ""
    assert "error:" in err


def test_explain(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "explain", "CLDR-0002")
    assert code == 0
    assert "CLDR-0002" in out
    assert "Evaluation" in out
    assert "Cross-resource relations:" not in out


def test_explain_unknown_id(capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = run(capsys, "explain", "nope")
    assert code == 2
    assert "policy not found: nope" in err


def test_scan_vulnerable_console(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = run(capsys, "scan", str(VULNERABLE), "--no-color")
    assert code == 1
    assert "Summary  51 findings (critical 8, high 19, medium 16, low 7, info 1)" in out
    assert "Result   FAIL (gate: high)" in out
    assert "CLDR-0001" in out
    assert "CLDR-1018" in out
    assert err == ""


def test_scan_compliant_console(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "scan", str(COMPLIANT), "--no-color")
    assert code == 0
    assert "No findings." in out
    assert "Result   PASS (gate: high)" in out


def test_scan_json_report(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "scan", str(VULNERABLE), "-f", "json")
    assert code == 1
    document = json.loads(out)
    assert document["tool"]["name"] == "cloudrift"
    assert document["summary"]["findings"] == 51
    assert document["summary"]["by_severity"]["critical"] == 8
    assert document["summary"]["gate"]["status"] == "fail"
    assert len(document["findings"]) == 51
    assert all(finding["policy_id"].startswith("CLDR-") for finding in document["findings"])


def test_scan_markdown_and_alias(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "scan", str(VULNERABLE), "-f", "md", "--quiet")
    assert code == 1
    assert out.startswith("# cloudrift scan report")
    assert "| Critical | 8 |" in out
    code_alias, alias_out, _ = run(
        capsys, "scan", str(VULNERABLE), "--format", "markdown", "--quiet"
    )
    assert code_alias == 1
    assert alias_out == out


def test_scan_sarif_report(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "scan", str(VULNERABLE), "-f", "sarif")
    assert code == 1
    document = json.loads(out)
    assert document["version"] == "2.1.0"
    run_info = document["runs"][0]
    assert run_info["tool"]["driver"]["name"] == "cloudrift"
    assert len(run_info["results"]) == 51
    assert run_info["results"][0]["ruleId"].startswith("CLDR-")


def test_scan_writes_output_file(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    target = tmp_path / "reports" / "cloudrift.json"
    target.parent.mkdir()
    code, out, err = run(capsys, "scan", str(COMPLIANT), "-f", "json", "-o", str(target))
    assert code == 0
    assert out == ""
    assert f"wrote {target}" in err
    assert json.loads(target.read_text(encoding="utf-8"))["summary"]["findings"] == 0


def test_scan_reports_unwritable_output(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist" / "report.json"
    code, _, err = run(capsys, "scan", str(COMPLIANT), "-o", str(missing))
    assert code == 2
    assert "cannot write" in err


def test_scan_from_stdin(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = (VULNERABLE / "plan.json").read_text(encoding="utf-8")
    monkeypatch.setattr("sys.stdin", io.StringIO(plan))
    code, out, _ = run(capsys, "scan", "-", "-f", "json")
    assert code == 1
    document = json.loads(out)
    assert document["scan"]["targets"] == ["-"]
    assert document["summary"]["findings"] > 0


def test_scan_custom_policy_dir(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    pack = write_policy(tmp_path / "pack", SINGLE_POLICY)
    code, out, _ = run(
        capsys,
        "scan",
        str(VULNERABLE / "plan.json"),
        "--policy-dir",
        str(pack),
        "-f",
        "json",
    )
    assert code == 1
    document = json.loads(out)
    assert document["summary"]["policies"] == 1
    assert document["findings"]
    assert {finding["policy_id"] for finding in document["findings"]} == {"CLDR-9001"}


def test_scan_list_rules(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "scan", "--list-rules")
    assert code == 0
    assert out.count("\n") == 50
    assert "CLDR-0001" in out


def test_scan_requires_path(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = run(capsys, "scan")
    assert code == 2
    assert out == ""
    assert "scan requires at least one path" in err


def test_scan_missing_path(capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = run(capsys, "scan", "no-such-file.json")
    assert code == 2
    assert "does not exist" in err


def test_scan_invalid_file_contents(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    junk = tmp_path / "plan.json"
    junk.write_text('{"not": "a plan"}', encoding="utf-8")
    code, _, err = run(capsys, "scan", str(junk))
    assert code == 2
    assert "error:" in err


def test_scan_fail_on_never(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "scan", str(VULNERABLE), "--fail-on", "never", "--no-color")
    assert code == 0
    assert "Result   PASS (gate: never)" in out


def test_scan_fail_on_critical_passes_with_high_only(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    directory = tmp_path / "high-only"
    directory.mkdir()
    (directory / "plan.json").write_text(
        json.dumps(
            {
                "format_version": "1.2",
                "terraform_version": "1.7.0",
                "resource_changes": [
                    {
                        "address": "aws_s3_bucket.logs",
                        "mode": "managed",
                        "type": "aws_s3_bucket",
                        "name": "logs",
                        "change": {
                            "actions": ["create"],
                            "before": None,
                            "after": {"acl": "private", "bucket": "logs"},
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    code, out, _ = run(capsys, "scan", str(directory), "--fail-on", "critical", "-f", "json")
    assert code == 0
    assert json.loads(out)["summary"]["gate"]["status"] == "pass"


def test_scan_severity_filter(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(
        capsys,
        "scan",
        str(VULNERABLE),
        "--severity",
        "critical",
        "-f",
        "json",
    )
    assert code == 1
    document = json.loads(out)
    assert document["summary"]["findings"] == 8
    assert {finding["severity"] for finding in document["findings"]} == {"critical"}

    code_pass, out_pass, _ = run(
        capsys,
        "scan",
        str(VULNERABLE),
        "--severity",
        "critical",
        "--fail-on",
        "critical",
        "-f",
        "json",
    )
    assert code_pass == 1
    assert json.loads(out_pass)["summary"]["findings"] == 8


def test_scan_inline_ignore(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(
        capsys,
        "scan",
        str(VULNERABLE),
        "--ignore",
        "CLDR-*",
        "--fail-on",
        "never",
        "-f",
        "json",
    )
    assert code == 0
    document = json.loads(out)
    assert document["summary"]["findings"] == 0
    assert document["summary"]["suppressed"] == 51


def test_scan_config_ignore_and_gate(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    (tmp_path / "cloudrift.yaml").write_text(
        "fail_on: never\n"
        "ignore:\n"
        "  - id: CLDR-0001\n"
        "    resource: aws_s3_bucket.*\n"
        "    reason: accepted risk\n",
        encoding="utf-8",
    )
    code, out, _ = run(capsys, "scan", str(VULNERABLE), "-f", "json")
    assert code == 0
    document = json.loads(out)
    assert document["summary"]["findings"] == 50
    assert document["summary"]["suppressed"] == 1
    assert document["summary"]["gate"]["fail_on"] == "never"


def test_scan_expired_ignore_is_stale(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    (tmp_path / "cloudrift.yaml").write_text(
        "fail_on: never\n"
        "ignore:\n"
        "  - id: CLDR-*\n"
        "    expires: 2020-01-01\n"
        "    reason: old exception\n",
        encoding="utf-8",
    )
    code, out, err = run(capsys, "scan", str(VULNERABLE), "-f", "json")
    assert code == 0
    document = json.loads(out)
    assert document["summary"]["findings"] == 51
    assert document["summary"]["suppressed"] == 0
    assert document["stale_ignores"]
    assert "expired 2020-01-01" in err


def test_scan_missing_config(capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = run(capsys, "scan", str(COMPLIANT), "--config", "missing.yaml")
    assert code == 2
    assert "config file does not exist" in err


def test_scan_invalid_config(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    config = tmp_path / "bad.yaml"
    config.write_text("fail_on: sometimes\n", encoding="utf-8")
    code, _, err = run(capsys, "scan", str(COMPLIANT), "--config", str(config))
    assert code == 2
    assert "fail_on must be one of" in err


def test_scan_baseline_write_then_gate(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    code, _, err = run(
        capsys,
        "scan",
        str(VULNERABLE),
        "--write-baseline",
        str(baseline),
        "-f",
        "json",
    )
    assert code == 1
    assert f"baseline written to {baseline} (51 findings)" in err
    assert json.loads(baseline.read_text(encoding="utf-8"))["findings"]

    code_clean, out, _ = run(
        capsys, "scan", str(VULNERABLE), "--baseline", str(baseline), "-f", "json"
    )
    assert code_clean == 0
    document = json.loads(out)
    assert document["summary"]["findings"] == 51
    assert document["summary"]["baseline"] == {
        "new": 0,
        "existing": 51,
        "fixed": 0,
        "enabled": True,
        "fixed_findings": [],
    }
    assert document["summary"]["gate"]["status"] == "pass"


def test_scan_baseline_reports_new_findings(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    baseline = tmp_path / "baseline.json"
    code, _, _ = run(
        capsys,
        "scan",
        str(COMPLIANT),
        "--write-baseline",
        str(baseline),
        "-f",
        "json",
    )
    assert code == 0
    code_scan, out, _ = run(
        capsys, "scan", str(VULNERABLE), "--baseline", str(baseline), "-f", "json"
    )
    assert code_scan == 1
    document = json.loads(out)
    assert document["summary"]["baseline"]["new"] == 51
    assert document["summary"]["baseline"]["existing"] == 0


def test_scan_rejects_baseline_combination(capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = run(
        capsys,
        "scan",
        str(COMPLIANT),
        "--baseline",
        "a.json",
        "--write-baseline",
        "b.json",
    )
    assert code == 2
    assert "cannot be combined" in err


def test_scan_quiet_and_stats(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "scan", str(COMPLIANT), "--no-color", "--stats", "--quiet")
    assert code == 0
    assert "cloudrift " not in out
    assert "No findings." not in out
    assert out.endswith("Result PASS\n")

    code_full, full_out, _ = run(capsys, "scan", str(COMPLIANT), "--no-color", "--stats")
    assert code_full == 0
    assert "Stats    " in full_out
    assert "policy-resource evaluations" in full_out
