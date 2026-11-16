"""Small text helpers shared by report writers."""

from __future__ import annotations

import re

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WHITESPACE = re.compile(r"\s+")


def clean(value: object, limit: int = 500) -> str:
    """Make an untrusted value safe for single-line terminal output."""

    text = "" if value is None else str(value)
    text = _CONTROL.sub("", text)
    text = _WHITESPACE.sub(" ", text).strip()
    if limit > 0 and len(text) > limit:
        text = text[: max(limit - 3, 0)] + "..."
    return text


def md_escape(value: object) -> str:
    """Escape a value embedded in a Markdown table cell or HTML context."""

    text = clean(value, limit=0)
    text = text.replace("&", "&amp;")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    text = text.replace("|", "\\|")
    text = text.replace("\n", " ")
    return text


def md_code(value: object) -> str:
    """Render a value as an inline code span without allowing markup injection.

    Backticks are replaced because they would terminate the span. HTML
    metacharacters and pipes are escaped as well: not every Markdown renderer
    treats a code span as opaque, and a raw pipe would split a table cell.
    """

    text = clean(value, limit=0).replace("`", "'")
    text = text.replace("&", "&amp;")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    text = text.replace("|", "\\|")
    return f"`{text}`"


def location_text(file: str, line: int | None) -> str:
    if not file:
        return "unknown"
    return f"{file}:{line}" if line is not None else file


def plural(count: int, singular: str, plural_form: str | None = None) -> str:
    if count == 1:
        return singular
    return plural_form if plural_form is not None else singular + "s"


def truncate(value: str, width: int) -> str:
    if width <= 0 or len(value) <= width:
        return value
    return value[: max(width - 3, 0)] + "..."
