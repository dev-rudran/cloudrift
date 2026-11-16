"""Baseline creation and drift comparison."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cloudrift import __version__
from cloudrift.errors import BaselineError
from cloudrift.models import Finding

SCHEMA = "cloudrift-baseline/1"


@dataclass
class Baseline:
    path: str
    fingerprints: set[str] = field(default_factory=set)
    entries: list[dict[str, Any]] = field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self.fingerprints)


@dataclass
class BaselineDiff:
    new: list[Finding] = field(default_factory=list)
    existing: list[Finding] = field(default_factory=list)
    fixed: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": True,
            "new": len(self.new),
            "existing": len(self.existing),
            "fixed": len(self.fixed),
            "fixed_findings": self.fixed,
        }


def load_baseline(path: str | Path) -> Baseline:
    target = Path(path)
    if not target.exists():
        raise BaselineError(f"baseline file does not exist: {target}")
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except OSError as exc:
        raise BaselineError(f"cannot read baseline {target}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise BaselineError(f"{target}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise BaselineError(f"{target}: baseline must contain a findings list")
    entries: list[dict[str, Any]] = []
    fingerprints: set[str] = set()
    for index, entry in enumerate(data["findings"], start=1):
        if not isinstance(entry, dict):
            raise BaselineError(f"{target}: finding #{index} must be a mapping")
        fingerprint = entry.get("fingerprint")
        if not isinstance(fingerprint, str) or not fingerprint:
            raise BaselineError(f"{target}: finding #{index} is missing a fingerprint")
        if fingerprint not in fingerprints:
            fingerprints.add(fingerprint)
            entries.append(entry)
    return Baseline(path=str(target), fingerprints=fingerprints, entries=entries)


def write_baseline(path: str | Path, findings: list[Finding]) -> Baseline:
    target = Path(path)
    ordered = sorted(findings, key=lambda item: item.fingerprint)
    data = {
        "schema": SCHEMA,
        "tool": {"name": "cloudrift", "version": __version__},
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "count": len(ordered),
        "findings": [
            {
                "fingerprint": finding.fingerprint,
                "policy_id": finding.policy_id,
                "resource": finding.resource_address,
                "file": finding.source.file,
                "line": finding.source.line,
                "severity": finding.severity.value,
                "title": finding.title,
            }
            for finding in ordered
        ],
    }
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    except OSError as exc:
        raise BaselineError(f"cannot write baseline {target}: {exc}") from exc
    return Baseline(
        path=str(target),
        fingerprints={finding.fingerprint for finding in ordered},
        entries=data["findings"],
    )


def compare_baseline(findings: list[Finding], baseline: Baseline) -> BaselineDiff:
    diff = BaselineDiff()
    current: set[str] = set()
    for finding in findings:
        current.add(finding.fingerprint)
        if finding.fingerprint in baseline.fingerprints:
            diff.existing.append(finding)
        else:
            diff.new.append(finding)
    diff.fixed = [entry for entry in baseline.entries if entry.get("fingerprint") not in current]
    diff.new.sort(key=lambda item: item.sort_key)
    diff.existing.sort(key=lambda item: item.sort_key)
    return diff
