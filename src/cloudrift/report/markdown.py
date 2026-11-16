"""Markdown report generation."""

from __future__ import annotations

from cloudrift.models import SEVERITIES, ScanContext
from cloudrift.util.text import md_code, md_escape


def render_markdown(context: ScanContext) -> str:
    counts = context.severity_counts()
    total = len(context.findings)
    gate = context.gate or {}
    status = "ERROR" if context.errors else "FAIL" if gate.get("status") == "fail" else "PASS"
    lines = [
        "# cloudrift scan report",
        "",
        f"**Result:** {status} (gate: {md_escape(gate.get('fail_on', 'high'))})",
        "",
        f"**Targets:** {', '.join(md_code(target) for target in context.targets)}",
        "",
        f"**Resources scanned:** {len(context.resources)} | "
        f"**Policies:** {context.policy_count} | "
        f"**Findings:** {total} | **Suppressed:** {len(context.suppressed)}",
        "",
        "## Summary",
        "",
        "| Severity | Findings |",
        "| --- | ---: |",
    ]
    for severity in SEVERITIES:
        lines.append(f"| {severity.capitalize()} | {counts[severity]} |")
    lines.append(f"| **Total** | **{total}** |")
    lines.append("")

    if not context.findings:
        lines.extend(["## Findings", "", "No findings.", ""])
    else:
        lines.extend(["## Findings", ""])
        for severity in SEVERITIES:
            group = [finding for finding in context.findings if finding.severity.value == severity]
            if not group:
                continue
            lines.extend(
                [
                    f"### {severity.capitalize()} ({len(group)})",
                    "",
                    "| Policy | Resource | Location | Message | Remediation |",
                    "| --- | --- | --- | --- | --- |",
                ]
            )
            for finding in group:
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            md_escape(f"{finding.policy_id}: {finding.title}"),
                            md_code(finding.resource_address),
                            md_code(finding.location),
                            md_escape(finding.message),
                            md_escape(finding.remediation),
                        ]
                    )
                    + " |"
                )
            lines.append("")

    if context.stale_ignores:
        lines.extend(["## Stale ignores", "", "Expired rules do not suppress findings.", ""])
        for rule in context.stale_ignores:
            lines.append(f"- {md_code(rule.get('id'))} expired {md_escape(rule.get('expires'))}")
        lines.append("")

    if context.suppressed:
        lines.extend(["## Suppressed findings", ""])
        for record in context.suppressed:
            rule = record.get("suppressed_by") or {}
            lines.append(
                f"- {md_code(record.get('policy_id'))} "
                f"{md_code(record.get('resource'))} - {md_escape(rule.get('reason'))}"
            )
        lines.append("")

    if context.errors:
        lines.extend(["## Evaluation errors", ""])
        for error in context.errors:
            lines.append(
                f"- {md_code(error.policy_id)} "
                f"{md_code(error.resource_address)}: {md_escape(error.message)}"
            )
        lines.append("")

    baseline = context.baseline or {}
    if baseline.get("enabled"):
        lines.extend(
            [
                "## Baseline drift",
                "",
                f"- New: {baseline.get('new', 0)}",
                f"- Existing: {baseline.get('existing', 0)}",
                f"- Fixed: {baseline.get('fixed', 0)}",
                "",
            ]
        )

    return "\n".join(lines).rstrip() + "\n"
