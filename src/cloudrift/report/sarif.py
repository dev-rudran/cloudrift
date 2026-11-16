"""SARIF 2.1.0 report for CI code scanning."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote

from cloudrift import __version__
from cloudrift.models import Policy, ScanContext, Severity

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_INFORMATION_URI = "https://github.com/dev-rudran/cloudrift"
_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}


def build_sarif(context: ScanContext) -> dict[str, Any]:
    rules = [policy_to_rule(policy) for policy in context.policies]
    rule_index = {policy.id: index for index, policy in enumerate(context.policies)}
    results = [finding_to_result(finding, rule_index) for finding in context.findings]
    tool: dict[str, Any] = {
        "driver": {
            "name": "cloudrift",
            "version": __version__,
            "informationUri": _INFORMATION_URI,
            "rules": rules,
        }
    }
    run: dict[str, Any] = {
        "tool": tool,
        "invocations": [
            {
                "executionSuccessful": not context.errors,
                "exitCode": context.exit_code,
                "endTimeUtc": context.started_at.isoformat() + "Z",
            }
        ],
        "results": results,
        "properties": {
            "targets": list(context.targets),
            "policies": context.policy_count,
            "resources": len(context.resources),
            "gate": dict(context.gate),
        },
    }
    if context.errors:
        run["tool"]["driver"]["notifications"] = [
            {
                "id": "cloudrift/evaluation-error",
                "level": "error",
                "message": {"text": f"{error.policy_id}: {error.message}"},
            }
            for error in context.errors
        ]
    return {"$schema": _SCHEMA, "version": "2.1.0", "runs": [run]}


def policy_to_rule(policy: Policy) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "id": policy.id,
        "name": _rule_name(policy),
        "shortDescription": {"text": policy.title},
        "fullDescription": {"text": policy.description},
        "defaultConfiguration": {"level": _LEVELS[policy.severity]},
        "help": {"text": policy.remediation},
        "properties": {
            "severity": policy.severity.value,
            "provider": policy.provider,
            "tags": list(policy.tags),
            "security-severity": _SECURITY_SEVERITY[policy.severity],
            "resource": list(policy.resource_patterns),
        },
    }
    if policy.references:
        rule["helpUri"] = policy.references[0]
    return rule


def finding_to_result(finding: Any, rule_index: dict[str, int]) -> dict[str, Any]:
    uri = _artifact_uri(finding.source.file)
    physical: dict[str, Any] = {"artifactLocation": {"uri": uri}}
    if finding.source.line is not None and finding.source.line > 0:
        physical["region"] = {"startLine": finding.source.line}
    result: dict[str, Any] = {
        "ruleId": finding.policy_id,
        "level": _LEVELS[finding.severity],
        "message": {"text": finding.message},
        "locations": [
            {
                "physicalLocation": physical,
                "logicalLocations": [
                    {
                        "fullyQualifiedName": finding.resource_address,
                        "kind": "resource",
                    }
                ],
            }
        ],
        "partialFingerprints": {"cloudrift/v1": finding.fingerprint},
        "properties": {
            "severity": finding.severity.value,
            "provider": finding.provider,
            "resourceType": finding.resource_type,
            "remediation": finding.remediation,
            "tags": list(finding.tags),
        },
    }
    index = rule_index.get(finding.policy_id)
    if index is not None:
        result["ruleIndex"] = index
    return result


def _artifact_uri(file: str) -> str:
    if not file:
        return "unknown"
    normalized = file.replace("\\", "/")
    if normalized == "<stdin>":
        return normalized
    return quote(normalized, safe="/:@!$&'()*+,;=-._~[]")


def _rule_name(policy: Policy) -> str:
    name = "".join(character if character.isalnum() else "-" for character in policy.title.lower())
    return "-".join(part for part in name.split("-") if part)[:80]


def render_sarif(context: ScanContext) -> str:
    return json.dumps(build_sarif(context), indent=2, sort_keys=False) + "\n"
