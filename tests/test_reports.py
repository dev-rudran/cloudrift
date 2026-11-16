"""Report writer tests: JSON, Markdown, SARIF, console."""

from __future__ import annotations

import json
from dataclasses import replace

from cloudrift.models import EvaluationError, Severity
from cloudrift.report.console import render_console
from cloudrift.report.json_report import build_json, render_json
from cloudrift.report.markdown import render_markdown
from cloudrift.report.sarif import build_sarif, render_sarif
from tests.conftest import make_context, make_finding


def test_json_schema_and_content() -> None:
    finding = make_finding()
    context = make_context(findings=[finding], gate_status="fail")
    data = build_json(context)
    assert data["schema_version"] == "1.0"
    assert data["tool"] == {"name": "cloudrift", "version": "0.1.0"}
    assert set(data["scan"]) == {
        "targets",
        "started_at",
        "duration_ms",
        "resource_count",
        "policy_count",
    }
    summary = data["summary"]
    assert summary["findings"] == 1
    assert summary["by_severity"]["high"] == 1
    assert summary["resources"] == 1
    assert summary["policies"] == 49
    assert summary["gate"] == {"fail_on": "high", "status": "fail"}
    assert summary["exit_code"] == 1
    assert data["findings"][0]["policy_id"] == "CLDR-0001"
    assert data["findings"][0]["location"] == "plan.json"
    assert data["resources"][0]["address"] == "aws_s3_bucket.logs"
    assert json.loads(render_json(context))["findings"][0]["severity"] == "high"


def test_json_baseline_and_suppressed() -> None:
    baseline = {"enabled": True, "new": 1, "existing": 2, "fixed": 3, "fixed_findings": []}
    context = make_context(
        findings=[make_finding()],
        baseline=baseline,
        suppressed=[{"policy_id": "CLDR-0002"}],
        stale=[{"id": "CLDR-0005", "expires": "2026-01-01"}],
    )
    data = build_json(context)
    assert data["summary"]["baseline"] == baseline
    assert data["summary"]["suppressed"] == 1
    assert data["summary"]["stale_ignores"] == 1
    assert data["suppressed"][0]["policy_id"] == "CLDR-0002"


def test_json_is_deterministic_except_timestamp() -> None:
    context = make_context(findings=[make_finding()])
    first = build_json(context)
    second = build_json(context)
    assert first == second


def test_markdown_report() -> None:
    context = make_context(findings=[make_finding(line=12)], gate_status="fail")
    text = render_markdown(context)
    assert "# cloudrift scan report" in text
    assert "**Result:** FAIL (gate: high)" in text
    assert "| High | 1 |" in text
    assert "CLDR-0001: Test finding" in text
    assert "`plan.json:12`" in text
    assert "fix it" in text


def test_markdown_escapes_html_and_pipes() -> None:
    finding = replace(
        make_finding(),
        resource_address="<img src=x onerror=alert(1)>",
        message="public | <script>alert(1)</script>",
        remediation="choose <b>private</b>",
    )
    text = render_markdown(make_context(findings=[finding]))
    assert "<script>" not in text
    assert "<img" not in text
    assert "&lt;script&gt;" in text
    assert "&lt;img" in text
    assert "public \\|" in text


def test_markdown_no_findings() -> None:
    text = render_markdown(make_context())
    assert "No findings." in text
    assert "**Result:** PASS (gate: high)" in text


def test_markdown_sections_for_stale_and_errors() -> None:
    context = make_context(
        stale=[{"id": "CLDR-0001", "expires": "2026-01-01"}],
        suppressed=[
            {
                "policy_id": "CLDR-0002",
                "resource": "aws_s3_bucket.x",
                "suppressed_by": {"reason": "ok"},
            }
        ],
        errors=[EvaluationError("CLDR-0099", "x", "boom")],
        baseline={"enabled": True, "new": 0, "existing": 1, "fixed": 2},
    )
    text = render_markdown(context)
    assert "## Stale ignores" in text
    assert "## Suppressed findings" in text
    assert "## Evaluation errors" in text
    assert "## Baseline drift" in text


def test_sarif_top_level_shape() -> None:
    context = make_context(findings=[make_finding(line=12)], gate_status="fail")
    sarif = build_sarif(context)
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-2.1.0.json")
    [run] = sarif["runs"]
    driver = run["tool"]["driver"]
    assert driver["name"] == "cloudrift"
    assert driver["version"] == "0.1.0"
    assert len(driver["rules"]) == 49
    assert driver["rules"][0]["id"] == "CLDR-0001"
    assert driver["rules"][0]["defaultConfiguration"]["level"] == "error"
    [result] = run["results"]
    assert result["ruleId"] == "CLDR-0001"
    assert result["ruleIndex"] == 0
    assert result["level"] == "error"
    assert result["partialFingerprints"]["cloudrift/v1"]
    assert result["properties"]["severity"] == "high"
    assert run["invocations"][0]["exitCode"] == 1


def test_sarif_locations_and_levels() -> None:
    findings = [
        make_finding(policy_id="CLDR-0001", severity=Severity.CRITICAL, line=3),
        make_finding(policy_id="CLDR-0003", severity=Severity.HIGH, line=None),
        make_finding(policy_id="CLDR-0004", severity=Severity.MEDIUM, line=8),
        make_finding(policy_id="CLDR-0005", severity=Severity.LOW, line=1),
        make_finding(policy_id="CLDR-1018", severity=Severity.INFO, line=1),
    ]
    sarif = build_sarif(make_context(findings=findings, gate_status="fail"))
    results = sarif["runs"][0]["results"]
    assert [result["level"] for result in results] == [
        "error",
        "error",
        "warning",
        "note",
        "note",
    ]
    physical = results[0]["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == "plan.json"
    assert physical["region"]["startLine"] == 3
    assert "region" not in results[1]["locations"][0]["physicalLocation"]
    logical = results[0]["locations"][0]["logicalLocations"][0]
    assert logical["fullyQualifiedName"] == "aws_s3_bucket.logs"
    assert logical["kind"] == "resource"


def test_sarif_uri_encoding() -> None:
    finding = make_finding(file="examples/vulnerable/k8s/app file.yaml", line=1)
    sarif = build_sarif(make_context(findings=[finding]))
    uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ]
    assert uri == "examples/vulnerable/k8s/app%20file.yaml"


def test_sarif_error_notifications() -> None:
    context = make_context(
        errors=[EvaluationError("CLDR-9999", "aws_s3_bucket.x", "boom")],
        gate_status="fail",
    )
    sarif = build_sarif(context)
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["notifications"][0]["level"] == "error"
    assert "boom" in driver["notifications"][0]["message"]["text"]
    assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] is False
    assert json.loads(render_sarif(context))["version"] == "2.1.0"


def test_console_color_and_grouping() -> None:
    findings = [
        make_finding(policy_id="CLDR-0001", severity=Severity.CRITICAL),
        make_finding(policy_id="CLDR-0003", severity=Severity.HIGH),
    ]
    text = render_console(make_context(findings=findings, gate_status="fail"), color=True)
    assert "\x1b[" in text
    assert text.index("CRITICAL (1)") < text.index("HIGH (1)")
    assert "Result" in text and "FAIL" in text
    plain = render_console(make_context(findings=findings, gate_status="fail"), color=False)
    assert "\x1b[" not in plain
    assert "CRITICAL (1)" in plain


def test_console_no_findings() -> None:
    text = render_console(make_context(), color=False)
    assert "No findings." in text
    assert "Result   PASS (gate: high)" in text


def test_console_quiet_is_compact() -> None:
    finding = make_finding()
    text = render_console(
        make_context(findings=[finding], gate_status="fail"), color=False, quiet=True
    )
    assert "cloudrift 0.1.0" not in text
    assert "Summary" not in text
    assert "CLDR-0001 high aws_s3_bucket.logs plan.json Test finding" in text
    assert text.strip().endswith("PASS") is False
    assert "Result FAIL" in text


def test_console_stats() -> None:
    text = render_console(make_context(), color=False, stats=True)
    assert "Stats" in text
    assert "aws 1" in text


def test_console_sanitizes_control_characters() -> None:
    finding = replace(
        make_finding(),
        resource_address="aws_s3_bucket.logs\nEVIL",
        message="bad\x1b[31m red",
    )
    text = render_console(make_context(findings=[finding]), color=False)
    assert "\x1b[31m red" not in text
    assert "logs EVIL" in text


def test_console_stale_and_errors() -> None:
    context = make_context(
        stale=[{"id": "CLDR-0005", "expires": "2026-01-01"}],
        errors=[EvaluationError("CLDR-9999", "aws_s3_bucket.x", "boom")],
        gate_status="fail",
    )
    text = render_console(context, color=False)
    assert "Stale ignores" in text
    assert "not applied" in text
    assert "Errors" in text
    assert "ERROR (policy evaluation failed)" in text
