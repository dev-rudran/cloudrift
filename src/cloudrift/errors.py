"""Shared exception types."""

from __future__ import annotations


class CloudriftError(Exception):
    """Base class for expected, user-facing errors."""


class InputError(CloudriftError):
    """Raised when an input file cannot be read or understood."""


class ConfigError(CloudriftError):
    """Raised when cloudrift.yaml is malformed."""


class BaselineError(CloudriftError):
    """Raised when a baseline file is malformed."""
