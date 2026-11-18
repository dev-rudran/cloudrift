"""Command line interface for cloudrift."""

from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from cloudrift import __version__
from cloudrift.baseline import compare_baseline, load_baseline, write_baseline
from cloudrift.config import apply_ignores, load_config
from cloudrift.errors import CloudriftError
from cloudrift.inputs.detect import load_inputs
from cloudrift.models import SEVERITIES, Policy, ScanContext, Severity
from cloudrift.policy.engine import evaluate_policies
from cloudrift.policy.loader import (
    PolicyError,
    load_bundled_policies,
    load_policy_path,
    validate_policies,
)
from cloudrift.report.console import render_console
from cloudrift.report.html import render_html
from cloudrift.report.json_report import render_json
from cloudrift.report.markdown import render_markdown
from cloudrift.report.sarif import render_sarif
from cloudrift.util.text import clean

EXIT_OK = 0
EXIT_GATE = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloudrift",
        description=(
            "Policy-as-code misconfiguration scanner for Terraform plan/state JSON "
            "and Kubernetes YAML."
        ),
    )
    parser.add_argument("--version", action="version", version=f"cloudrift {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser(
        "scan",
        help="scan Terraform and Kubernetes inputs",
        description="Scan files or directories. Use '-' to read from stdin.",
    )
    scan.add_argument("paths", nargs="*", help="files, directories, or '-' for stdin")
    scan.add_argument(
        "--format",
        "-f",
        choices=("console", "json", "md", "markdown", "sarif", "html"),
        default=None,
        help="report format (default: console, or html when --output ends in .html)",
    )
    scan.add_argument("-o", "--output", help="write the report to a file")
    scan.add_argument(
        "--severity",
        choices=SEVERITIES,
        default=None,
        help="minimum severity to report and gate on (default: info, or config)",
    )
    scan.add_argument(
        "--fail-on",
        choices=SEVERITIES + ("never",),
        default=None,
        help="exit 1 when a finding at or above this severity exists (default: high, or config)",
    )
    scan.add_argument(
        "--policy-dir",
        help="load policies from this file or directory instead of the bundled pack",
    )
    scan.add_argument("--config", help="path to cloudrift.yaml (auto-detected by default)")
    scan.add_argument(
        "--ignore",
        action="append",
        default=[],
        metavar="ID",
        help="suppress a policy id for this run (repeatable, supports globs)",
    )
    scan.add_argument(
        "--baseline",
        metavar="FILE",
        help="only fail on findings not in the baseline",
    )
    scan.add_argument(
        "--write-baseline",
        metavar="FILE",
        help="write current findings (after ignores) as a baseline and continue",
    )
    scan.add_argument(
        "--list-rules",
        action="store_true",
        help="print the loaded policy pack and exit without scanning",
    )
    scan.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    scan.add_argument("--quiet", "-q", action="store_true", help="compact output")
    scan.add_argument("--stats", action="store_true", help="print scan statistics")

    rules = subparsers.add_parser("rules", help="inspect and validate policies")
    rules_sub = rules.add_subparsers(dest="rules_command", required=True)
    for name, help_text in (
        ("list", "list policies"),
        ("show", "show one policy"),
        ("validate", "validate a policy pack"),
    ):
        child = rules_sub.add_parser(name, help=help_text)
        child.add_argument("--policy-dir", help="policy file or directory (default: bundled pack)")
        if name == "show":
            child.add_argument("id", help="policy id, for example CLDR-0001")
        if name == "validate":
            child.add_argument(
                "path",
                nargs="?",
                help="policy file or directory (default: bundled pack or --policy-dir)",
            )

    explain = subparsers.add_parser("explain", help="explain a policy")
    explain.add_argument("id", help="policy id, for example CLDR-0001")
    explain.add_argument("--policy-dir", help="policy file or directory")

    subparsers.add_parser("version", help="print the version")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "version":
            print(f"cloudrift {__version__}")
            return EXIT_OK
        if args.command == "rules":
            return _run_rules(args)
        if args.command == "explain":
            return _run_explain(args)
        if args.command == "scan":
            return _run_scan(args, parser)
    except (CloudriftError, PolicyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_ERROR


def _run_scan(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    args.format = _resolve_format(args.format, args.output)

    if args.list_rules:
        policies = _load_policies(args.policy_dir)
        _print_rule_table(policies)
        return EXIT_OK

    if not args.paths:
        print("error: scan requires at least one path ('-' for stdin)", file=sys.stderr)
        return EXIT_ERROR
    if args.baseline and args.write_baseline:
        print("error: --baseline and --write-baseline cannot be combined", file=sys.stderr)
        return EXIT_ERROR

    config = load_config(args.config)
    fail_on = args.fail_on or config.fail_on
    severity_name = args.severity or config.severity
    minimum = Severity.parse(severity_name)

    policies = _load_policies(args.policy_dir)
    stdin_text = sys.stdin.read() if "-" in args.paths else None

    started_at = datetime.now(timezone.utc)
    start = time.perf_counter()
    resources = load_inputs(args.paths, config.exclude_paths, stdin_text)
    result = evaluate_policies(policies, resources)

    kept, suppressed, stale = apply_ignores(result.findings, config, args.ignore)
    if args.write_baseline:
        written = write_baseline(args.write_baseline, kept)
        if not args.quiet:
            print(
                f"baseline written to {written.path} ({written.size} findings)",
                file=sys.stderr,
            )

    baseline_info = None
    gate_pool = kept
    if args.baseline:
        baseline = load_baseline(args.baseline)
        diff = compare_baseline(kept, baseline)
        baseline_info = diff.to_dict()
        gate_pool = diff.new

    reported = [finding for finding in kept if finding.severity.rank <= minimum.rank]
    gated = [finding for finding in gate_pool if finding.severity.rank <= minimum.rank]
    gate_failed = _gate_failed(gated, fail_on)
    gate = {
        "fail_on": fail_on,
        "status": "fail" if gate_failed else "pass",
        "above_gate": len(gated) if gate_failed else 0,
    }

    duration_ms = int((time.perf_counter() - start) * 1000)
    context = ScanContext(
        targets=list(args.paths),
        resources=resources,
        policies=policies,
        findings=reported,
        started_at=started_at,
        duration_ms=duration_ms,
        evaluations=result.evaluations,
        errors=result.errors,
        suppressed=suppressed,
        stale_ignores=stale,
        baseline=baseline_info,
        gate=gate,
    )

    color = (
        not args.no_color
        and args.output is None
        and sys.stdout.isatty()
        and "NO_COLOR" not in os.environ
    )
    text = _render(context, args.format, color=color, quiet=args.quiet, stats=args.stats)

    if args.output:
        target = Path(args.output)
        try:
            target.write_text(text, encoding="utf-8")
        except OSError as exc:
            print(f"error: cannot write {target}: {exc}", file=sys.stderr)
            return EXIT_ERROR
        if not args.quiet:
            print(f"wrote {target}", file=sys.stderr)
    else:
        sys.stdout.write(text)

    if stale and not args.quiet:
        for rule in stale:
            print(
                f"warning: ignore {rule.get('id')} expired {rule.get('expires')}; "
                "findings are reported",
                file=sys.stderr,
            )
    if context.errors and not args.quiet:
        for error in context.errors:
            print(
                f"warning: {error.policy_id} could not evaluate "
                f"{error.resource_address}: {error.message}",
                file=sys.stderr,
            )
    return context.exit_code


def _resolve_format(output_format: str | None, output: str | None) -> str:
    if output_format == "markdown":
        return "md"
    if output_format:
        return output_format
    if output:
        suffix = Path(output).suffix.lower()
        if suffix in {".html", ".htm"}:
            return "html"
    return "console"


def _render(
    context: ScanContext,
    output_format: str,
    *,
    color: bool,
    quiet: bool,
    stats: bool,
) -> str:
    if output_format == "json":
        return render_json(context)
    if output_format == "md":
        return render_markdown(context)
    if output_format == "sarif":
        return render_sarif(context)
    if output_format == "html":
        return render_html(context)
    return render_console(context, color=color, quiet=quiet, stats=stats)


def _gate_failed(findings: list, fail_on: str) -> bool:
    if fail_on == "never":
        return False
    threshold = Severity.parse(fail_on, field_name="fail_on")
    return any(finding.severity.rank <= threshold.rank for finding in findings)


def _run_rules(args: argparse.Namespace) -> int:
    policy_dir = getattr(args, "policy_dir", None)
    if args.rules_command == "validate":
        path = getattr(args, "path", None) or policy_dir
        policies = _load_policies(path)
        issues = validate_policies(policies)
        if issues:
            for issue in issues:
                print(f"error: {issue}", file=sys.stderr)
            return EXIT_ERROR
        print(f"{len(policies)} policies valid")
        return EXIT_OK
    policies = _load_policies(policy_dir)
    if args.rules_command == "list":
        _print_rule_table(policies)
        return EXIT_OK
    policy = _find_policy(policies, args.id)
    _print_policy(policy)
    return EXIT_OK


def _run_explain(args: argparse.Namespace) -> int:
    policies = _load_policies(args.policy_dir)
    policy = _find_policy(policies, args.id)
    _print_policy(policy)
    print()
    print("Evaluation")
    print("  The policy is compliant when the assertion evaluates to true.")
    print("  A finding is produced when the assertion evaluates to false.")
    print("  Unknown or null attributes read as None; use exists() or get() to guard.")
    if policy.relations:
        print("  Cross-resource relations:")
        for relation in policy.relations:
            parts = [f"type={'/'.join(relation.types)}"]
            if relation.scope:
                parts.append(f"scope={relation.scope}")
            if relation.reference:
                parts.append("reference=true")
            if relation.via:
                parts.append(f"via={','.join(relation.via)}")
            parts.append(f"target={relation.target}")
            print(f"    - {' '.join(parts)}")
    return EXIT_OK


def _load_policies(path: str | None) -> list[Policy]:
    if path:
        return load_policy_path(path)
    return load_bundled_policies()


def _find_policy(policies: list[Policy], policy_id: str) -> Policy:
    for policy in policies:
        if policy.id == policy_id:
            return policy
    raise PolicyError(f"policy not found: {policy_id}")


def _print_rule_table(policies: list[Policy]) -> None:
    print(f"{'ID':<12} {'SEVERITY':<9} {'PROVIDER':<11} TITLE")
    for policy in policies:
        print(
            f"{policy.id:<12} {policy.severity.value:<9} {policy.provider:<11} "
            f"{clean(policy.title, 100)}"
        )


def _print_policy(policy: Policy) -> None:
    print(f"{policy.id}  {policy.title}")
    print(f"Severity:    {policy.severity.value}")
    print(f"Provider:    {policy.provider}")
    print(f"Resources:   {', '.join(policy.resource_patterns)}")
    if policy.tags:
        print(f"Tags:        {', '.join(policy.tags)}")
    print()
    print(f"Description: {policy.description}")
    print()
    print("Assertion (true means compliant):")
    print(f"  {policy.assert_expr}")
    print()
    print(f"Message:     {policy.message}")
    print(f"Remediation: {policy.remediation}")
    if policy.references:
        print("References:")
        for reference in policy.references:
            print(f"  - {reference}")
    if policy.source_file:
        print(f"Source:      {policy.source_file}")


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
