"""Tests for shared utility helpers."""

from __future__ import annotations

import pytest

from cloudrift.util.cidr import cidr_contains, is_public_cidr, parse_network
from cloudrift.util.text import clean, location_text, md_code, md_escape, plural, truncate
from cloudrift.util.yamlpos import YamlPositionError, key_lines_for, load_documents


def test_clean_strips_control_characters_and_collapses_whitespace() -> None:
    assert clean("a\x00b\tc\n\nd\x7f") == "ab c d"
    assert clean(None) == ""
    assert clean(12) == "12"


def test_clean_truncates_with_ellipsis() -> None:
    assert clean("x" * 20, limit=10) == "xxxxxxx..."
    assert clean("x" * 20, limit=3) == "..."
    assert clean("x" * 20, limit=0) == "x" * 20


def test_md_escape_neutralizes_markup_and_tables() -> None:
    assert md_escape('<b>&</b> | "q"') == '&lt;b&gt;&amp;&lt;/b&gt; \\| "q"'


def test_md_code_neutralizes_markup() -> None:
    assert md_code("a`b <c> | d") == "`a'b &lt;c&gt; \\| d`"
    assert md_code(None) == "``"


def test_location_text() -> None:
    assert location_text("plan.json", 12) == "plan.json:12"
    assert location_text("plan.json", None) == "plan.json"
    assert location_text("", 4) == "unknown"


def test_plural_and_truncate() -> None:
    assert plural(1, "finding") == "finding"
    assert plural(0, "finding") == "findings"
    assert plural(2, "policy", "policies") == "policies"
    assert truncate("abcdef", 6) == "abcdef"
    assert truncate("abcdef", 5) == "ab..."
    assert truncate("abcdef", 0) == "abcdef"


def test_parse_network_accepts_hosts_and_cidrs() -> None:
    assert str(parse_network("10.0.0.5")) == "10.0.0.5/32"
    assert str(parse_network("10.0.0.0/8")) == "10.0.0.0/8"
    assert parse_network("not-a-network") is None
    assert parse_network("  ") is None
    assert parse_network(10) is None


def test_cidr_contains() -> None:
    assert cidr_contains("10.0.0.0/8", "10.1.2.3")
    assert cidr_contains("10.0.0.0/8", "10.2.0.0/16")
    assert not cidr_contains("10.0.0.0/8", "192.168.0.1")
    assert not cidr_contains("10.0.0.0/8", "::1")
    assert not cidr_contains("bogus", "10.0.0.1")


@pytest.mark.parametrize(
    ("value", "public"),
    [
        ("0.0.0.0/0", True),
        ("::/0", True),
        ("8.8.8.8/32", True),
        ("1.1.1.0/24", True),
        ("10.0.0.0/8", False),
        ("172.16.0.0/12", False),
        ("192.168.1.0/24", False),
        ("127.0.0.1/32", False),
        ("169.254.0.0/16", False),
        ("::1/128", False),
        ("fd00::/8", False),
        ("not-a-cidr", False),
        (None, False),
    ],
)
def test_is_public_cidr(value: object, public: bool) -> None:
    assert is_public_cidr(value) is public


def test_load_documents_tracks_lines_and_paths() -> None:
    text = """
apiVersion: v1
kind: ConfigMap
metadata:
  name: demo
data:
  key: value
---
apiVersion: v1
kind: Service
metadata:
  name: web
spec:
  ports:
    - port: 80
"""
    documents = load_documents(text, "multi.yaml")
    assert len(documents) == 2
    first, second = documents
    assert first.line == 2
    assert first.key_lines["kind"] == 3
    assert first.key_lines["metadata.name"] == 5
    assert first.key_lines["data.key"] == 7
    assert second.key_lines["spec.ports.0.port"] == 15


def test_load_documents_ignores_empty_documents() -> None:
    documents = load_documents("---\n---\n", "empty.yaml")
    assert documents == []
    assert load_documents("   \n", "blank.yaml") == []


def test_load_documents_reports_syntax_errors() -> None:
    with pytest.raises(YamlPositionError, match="multi.yaml: invalid YAML"):
        load_documents("kind: [unclosed\n", "multi.yaml")


def test_load_documents_rejects_unsafe_tags() -> None:
    # The safe constructor rejects the tag before any object is built.
    with pytest.raises(YamlPositionError, match="could not determine a constructor"):
        load_documents("value: !!python/object/apply:os.system ['true']\n", "x.yaml")


def test_key_lines_for_rejects_non_scalar_keys() -> None:
    import yaml

    node = yaml.compose("? [a, b]\n: value\n")
    assert key_lines_for(node) == {}


def test_key_lines_for_sequence_root() -> None:
    import yaml

    node = yaml.compose("- one\n- two\n")
    assert key_lines_for(node) == {"0": 1, "1": 2}
