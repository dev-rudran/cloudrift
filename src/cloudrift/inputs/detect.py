"""Input discovery and classification."""

from __future__ import annotations

import contextlib
import json
import os
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

from cloudrift.errors import InputError
from cloudrift.inputs.kubernetes import load_kubernetes
from cloudrift.inputs.terraform import load_terraform
from cloudrift.models import Resource
from cloudrift.util.yamlpos import YamlPositionError, load_documents

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".terraform",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    "node_modules",
    "dist",
    "build",
    "htmlcov",
    "site-packages",
}
INPUT_SUFFIXES = {".json", ".yaml", ".yml"}


@dataclass
class DiscoveredInput:
    path: str
    kind: str
    explicit: bool = False


def detect_document(data: Any) -> str | None:
    """Classify a parsed document as terraform, kubernetes, or unknown."""

    if isinstance(data, dict):
        if "planned_values" in data or "resource_changes" in data:
            return "terraform"
        values = data.get("values")
        if isinstance(values, dict) and isinstance(values.get("root_module"), dict):
            return "terraform"
        if isinstance(data.get("kind"), str):
            return "kubernetes"
    if isinstance(data, list):
        items = [
            item for item in data if isinstance(item, dict) and isinstance(item.get("kind"), str)
        ]
        if items:
            return "kubernetes"
    return None


def detect_text(text: str, source: str, suffix: str = "") -> str | None:
    """Classify input text without constructing resources."""

    if suffix == ".json" or (not suffix and text.lstrip().startswith(("{", "["))):
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            if suffix == ".json":
                raise InputError(
                    f"{source}: invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
                ) from exc
        else:
            return detect_document(data)
    try:
        documents = load_documents(text, source)
    except YamlPositionError as exc:
        raise InputError(str(exc)) from exc
    if any(
        isinstance(document.data, (dict, list)) and detect_document(document.data) == "kubernetes"
        for document in documents
    ):
        return "kubernetes"
    return None


def discover(
    targets: list[str], exclude_patterns: list[str] | None = None
) -> list[DiscoveredInput]:
    """Expand files and directories into supported inputs."""

    patterns = list(exclude_patterns or [])
    discovered: list[DiscoveredInput] = []
    seen: set[str] = set()
    for target in targets:
        if target == "-":
            discovered.append(DiscoveredInput(path="-", kind="stdin", explicit=True))
            continue
        path = Path(target)
        if not path.exists():
            raise InputError(f"input path does not exist: {target}")
        if path.is_dir():
            _discover_directory(path, patterns, discovered, seen)
        else:
            if _excluded(path, patterns):
                continue
            kind = _classify_file(path, explicit=True)
            key = str(path.resolve())
            if key not in seen:
                seen.add(key)
                discovered.append(DiscoveredInput(path=_display(path), kind=kind, explicit=True))
    if not discovered:
        raise InputError(
            "no supported input files found; expected Terraform plan/state JSON or Kubernetes YAML"
        )
    return discovered


def _discover_directory(
    root: Path,
    patterns: list[str],
    discovered: list[DiscoveredInput],
    seen: set[str],
) -> None:
    for current, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            name
            for name in dirnames
            if name not in SKIP_DIRS and not _excluded(Path(current) / name, patterns)
        )
        for filename in sorted(filenames):
            path = Path(current) / filename
            if path.suffix.lower() not in INPUT_SUFFIXES:
                continue
            if _excluded(path, patterns):
                continue
            key = str(path.resolve())
            if key in seen:
                continue
            try:
                kind = _classify_file(path, explicit=False)
            except InputError:
                continue
            if not kind:
                continue
            seen.add(key)
            discovered.append(DiscoveredInput(path=_display(path), kind=kind, explicit=False))


def _classify_file(path: Path, *, explicit: bool) -> str | None:
    if path.suffix.lower() not in INPUT_SUFFIXES:
        if explicit:
            raise InputError(
                f"{path}: unsupported input type {path.suffix!r}; "
                "expected Terraform plan/state JSON or Kubernetes YAML"
            )
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise InputError(f"{path}: input is not valid UTF-8: {exc}") from exc
    if not text.strip():
        if explicit:
            raise InputError(f"{path}: file is empty")
        return None
    kind = detect_text(text, str(path), path.suffix.lower())
    if kind is None:
        if explicit:
            raise InputError(
                f"{path}: unrecognized input; expected a Terraform plan/state JSON "
                "document or a Kubernetes manifest"
            )
        return None
    return kind


def load_inputs(
    targets: list[str],
    exclude_patterns: list[str] | None = None,
    stdin_text: str | None = None,
) -> list[Resource]:
    """Discover and load every resource from the requested inputs."""

    discovered = discover(targets, exclude_patterns)
    resources: list[Resource] = []
    stdin_used = False
    for item in discovered:
        if item.kind == "stdin":
            if stdin_used:
                raise InputError("stdin ('-') may only be used once")
            if stdin_text is None:
                raise InputError("stdin was requested but no input was provided")
            stdin_used = True
            kind = detect_text(stdin_text, "<stdin>", "")
            if kind is None:
                raise InputError(
                    "<stdin>: unrecognized input; expected a Terraform plan/state JSON "
                    "document or a Kubernetes manifest"
                )
            resources.extend(_load_text(stdin_text, "<stdin>", kind))
            continue
        path = Path(item.path)
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise InputError(f"cannot read {item.path}: {exc}") from exc
        resources.extend(_load_text(text, item.path, item.kind))
    return resources


def _load_text(text: str, source: str, kind: str) -> list[Resource]:
    if kind == "terraform":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise InputError(
                f"{source}: invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
            ) from exc
        return load_terraform(data, source)
    if kind == "kubernetes":
        return load_kubernetes(text, source)
    raise InputError(f"{source}: unsupported input kind {kind!r}")


def _excluded(path: Path, patterns: list[str]) -> bool:
    if not patterns:
        return False
    candidates = {path.name, str(path), path.as_posix()}
    with contextlib.suppress(ValueError, OSError):
        candidates.add(path.resolve().relative_to(Path.cwd().resolve()).as_posix())
    for pattern in patterns:
        if any(fnmatchcase(candidate, pattern) for candidate in candidates):
            return True
    return False


def _display(path: Path) -> str:
    """Return a stable path for reports and baseline fingerprints.

    Paths inside the working directory are shown relative to it so the same
    scan produces the same source location regardless of whether the caller
    passed a relative or absolute path. Paths outside the working directory
    keep their normalized absolute form.
    """

    try:
        relative = path.resolve().relative_to(Path.cwd().resolve())
    except (OSError, ValueError):
        return os.path.normpath(str(path))
    return relative.as_posix() or "."
