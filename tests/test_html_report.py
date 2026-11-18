"""Tests for the self-contained HTML report."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from cloudrift.cli import main
from cloudrift.models import Severity
from cloudrift.report.html import render_html
from tests.conftest import make_context, make_finding

ROOT = Path(__file__).resolve().parents[1]
VULNERABLE = ROOT / "examples" / "vulnerable"


def test_html_report_is_self_contained() -> None:
    finding = replace(make_finding(), references=[])
    text = render_html(make_context(findings=[finding], gate_status="fail"))
    assert text.startswith("<!doctype html>")
    assert "<style>" in text
    assert "<script>" in text
    assert "<script src" not in text
    assert "<link " not in text
    assert "@import" not in text
    assert "url(http" not in text
    assert "http://" not in text
    assert "https://" not in text


def test_html_report_header_and_summary_counts() -> None:
    findings = [
        make_finding(policy_id="CLDR-0001", severity=Severity.CRITICAL),
        make_finding(policy_id="CLDR-0002", severity=Severity.HIGH),
        make_finding(policy_id="CLDR-0003", severity=Severity.HIGH),
    ]
    text = render_html(make_context(findings=findings, gate_status="fail"))
    assert "<h1>test</h1>" in text
    assert "2026-01-02 03:04:05 UTC" in text
    assert "FAIL" in text
    assert "threshold: high" in text
    assert 'id="fact-resources">1<' in text
    assert 'id="fact-policies">49<' in text
    assert 'id="fact-evaluations">7<' in text
    assert 'id="count-critical">1<' in text
    assert 'id="count-high">2<' in text
    assert 'id="count-medium">0<' in text
    assert 'id="count-low">0<' in text
    assert 'id="count-info">0<' in text
    assert 'id="count-total">3<' in text
    assert 'class="distribution"' in text
    assert "seg-critical" in text


def test_html_report_contains_finding_details() -> None:
    finding = make_finding(line=12)
    text = render_html(make_context(findings=[finding], gate_status="fail"))
    assert "CLDR-0001" in text
    assert "Test finding" in text
    assert "aws_s3_bucket.logs" in text
    assert "plan.json:12" in text
    assert "bucket is public" in text
    assert "fix it" in text
    assert "https://example.com/rule" in text
    assert 'href="https://example.com/rule"' in text


def test_html_report_escapes_untrusted_content() -> None:
    finding = replace(
        make_finding(),
        title="<script>alert(1)</script>",
        message="<script>alert(1)</script>",
        remediation="<b>private</b>",
    )
    text = render_html(make_context(findings=[finding]))
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text
    assert "&lt;b&gt;private&lt;/b&gt;" in text


def test_html_report_only_links_http_and_https() -> None:
    finding = replace(
        make_finding(),
        references=[
            "https://example.com/rule?a=1&b=2",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
        ],
    )
    text = render_html(make_context(findings=[finding]))
    assert 'href="https://example.com/rule?a=1&amp;b=2"' in text
    assert 'href="javascript:' not in text
    assert 'href="data:' not in text
    assert "javascript:alert(1)" in text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text


def test_html_report_no_findings() -> None:
    text = render_html(make_context())
    assert "No findings." in text
    assert 'id="count-total">0<' in text
    assert "PASS" in text
    assert 'class="distribution"' in text
    assert "Group by severity" not in text


def test_cli_html_format(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "cloudrift.html"
    code = main(["scan", str(VULNERABLE), "--format", "html", "--output", str(target)])
    assert code == 1
    text = target.read_text(encoding="utf-8")
    assert text.startswith("<!doctype html>")
    assert "CLDR-0001" in text
    assert "aws_s3_bucket.logs" in text


def test_cli_infers_html_from_output_extension(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "cloudrift.htm"
    code = main(["scan", str(VULNERABLE), "--output", str(target)])
    assert code == 1
    assert target.read_text(encoding="utf-8").startswith("<!doctype html>")
