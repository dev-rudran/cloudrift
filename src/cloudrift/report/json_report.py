"""Stable machine-readable JSON report."""

from __future__ import annotations

import json
from typing import Any

from cloudrift import __version__
from cloudrift.models import ScanContext

SCHEMA_VERSION = "1.0"


def build_json(context: ScanContext) -> dict[str, Any]:
    baseline = context.baseline or {"enabled": False}
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "cloudrift", "version": __version__},
        "scan": {
            "targets": list(context.targets),
            "started_at": context.started_at.isoformat(),
            "duration_ms": context.duration_ms,
            "resource_count": len(context.resources),
            "policy_count": context.policy_count,
        },
        "summary": {
            "findings": len(context.findings),
            "by_severity": context.severity_counts(),
            "resources": len(context.resources),
            "policies": context.policy_count,
            "evaluations": context.evaluations,
            "suppressed": len(context.suppressed),
            "stale_ignores": len(context.stale_ignores),
            "errors": len(context.errors),
            "gate": dict(context.gate),
            "baseline": baseline,
            "exit_code": context.exit_code,
        },
        "findings": [finding.to_dict() for finding in context.findings],
        "resources": [
            resource.to_dict()
            for resource in sorted(context.resources, key=lambda item: item.sort_key)
        ],
        "suppressed": list(context.suppressed),
        "stale_ignores": list(context.stale_ignores),
        "errors": [error.to_dict() for error in context.errors],
    }


def render_json(context: ScanContext) -> str:
    return json.dumps(build_json(context), indent=2, sort_keys=False) + "\n"
