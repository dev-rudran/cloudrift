"""Human-readable console report."""

from __future__ import annotations

from collections import Counter

from cloudrift.models import SEVERITIES, ScanContext
from cloudrift.util.text import clean

_COLORS = {
    "critical": "\033[1;91m",
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[96m",
    "info": "\033[90m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "green": "\033[92m",
    "red": "\033[91m",
    "reset": "\033[0m",
}


def _paint(text: str, key: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{_COLORS[key]}{text}{_COLORS['reset']}"


def render_console(
    context: ScanContext,
    *,
    color: bool = True,
    quiet: bool = False,
    stats: bool = False,
) -> str:
    lines: list[str] = []
    if not quiet:
        lines.append(f"{_paint('cloudrift', 'bold', color)} {_paint(_version(), 'dim', color)}")
        lines.append(f"Targets: {', '.join(clean(t, 200) for t in context.targets)}")
        lines.append(f"Policies: {context.policy_count}   Resources: {len(context.resources)}")
        lines.append("")

    if not context.findings:
        if not quiet:
            lines.append("No findings.")
    else:
        if quiet:
            for finding in context.findings:
                lines.append(
                    " ".join(
                        [
                            finding.policy_id,
                            finding.severity.value,
                            clean(finding.resource_address, 200),
                            clean(finding.location, 200),
                            clean(finding.title, 160),
                        ]
                    )
                )
        else:
            for severity in SEVERITIES:
                group = [f for f in context.findings if f.severity.value == severity]
                if not group:
                    continue
                header = f"{severity.upper()} ({len(group)})"
                lines.append(_paint(header, severity, color))
                for finding in group:
                    lines.append(
                        f"  {_paint(finding.policy_id, 'bold', color)}  {clean(finding.title, 160)}"
                    )
                    lines.append(f"    resource: {clean(finding.resource_address, 200)}")
                    lines.append(f"    location: {clean(finding.location, 200)}")
                    lines.append(f"    {clean(finding.message, 600)}")
                    lines.append(f"    fix: {clean(finding.remediation, 400)}")
                    lines.append("")

    if context.stale_ignores and not quiet:
        lines.append(_paint("Stale ignores", "bold", color))
        for rule in context.stale_ignores:
            lines.append(
                f"  {clean(rule.get('id'), 40)} expired {clean(rule.get('expires'), 40)}"
                " - not applied"
            )
        lines.append("")

    if context.errors and not quiet:
        lines.append(_paint("Errors", "bold", color))
        for error in context.errors:
            lines.append(
                f"  {clean(error.policy_id, 20)} {clean(error.resource_address, 200)}: "
                f"{clean(error.message, 300)}"
            )
        lines.append("")

    if not quiet:
        counts = context.severity_counts()
        total = len(context.findings)
        breakdown = ", ".join(f"{name} {counts[name]}" for name in SEVERITIES)
        lines.append(f"Summary  {total} {'finding' if total == 1 else 'findings'} ({breakdown})")
        lines.append(
            f"         resources {len(context.resources)} | policies {context.policy_count}"
            f" | evaluations {context.evaluations} | suppressed {len(context.suppressed)}"
        )
        baseline = context.baseline or {}
        if baseline.get("enabled"):
            lines.append(
                f"         baseline new {baseline.get('new', 0)} | "
                f"existing {baseline.get('existing', 0)} | fixed {baseline.get('fixed', 0)}"
            )
        if stats:
            providers = Counter(resource.provider for resource in context.resources)
            provider_text = ", ".join(
                f"{name} {count}" for name, count in sorted(providers.items())
            )
            lines.append(
                f"Stats    {context.evaluations} policy-resource evaluations in "
                f"{context.duration_ms} ms"
            )
            lines.append(f"         {provider_text or 'no resources'}")
        gate = context.gate or {}
        fail_on = gate.get("fail_on", "high")
        if context.errors:
            result = _paint("ERROR", "red", color) + " (policy evaluation failed)"
        elif gate.get("status") == "fail":
            result = _paint("FAIL", "red", color) + f" (gate: {fail_on})"
        else:
            result = _paint("PASS", "green", color) + f" (gate: {fail_on})"
        lines.append(f"Result   {result}")
    else:
        gate = context.gate or {}
        status = "ERROR" if context.errors else "FAIL" if gate.get("status") == "fail" else "PASS"
        lines.append(f"Result {status}")

    return "\n".join(lines).rstrip() + "\n"


def _version() -> str:
    from cloudrift import __version__

    return __version__
