"""Self-contained HTML report with inline CSS and JavaScript."""

from __future__ import annotations

import html
from datetime import timezone
from pathlib import Path
from urllib.parse import urlsplit

from cloudrift import __version__
from cloudrift.models import SEVERITIES, Finding, ScanContext
from cloudrift.util.text import clean

_LABELS = {severity: severity.capitalize() for severity in SEVERITIES}

_STYLE = """
:root {
  --bg: #f5f7fa;
  --surface: #ffffff;
  --border: #d8dee8;
  --text: #17202e;
  --muted: #5b6779;
  --critical: #b42318;
  --high: #d92d20;
  --medium: #b54708;
  --low: #026aa2;
  --info: #475467;
  --pass: #087443;
  --fail: #b42318;
  --error: #7a2e0e;
}
* { box-sizing: border-box; }
html { color-scheme: light; }
body {
  margin: 0;
  padding: 2rem clamp(1rem, 4vw, 3rem) 3rem;
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  font-size: 15px;
  line-height: 1.5;
}
h1, h2, p { margin: 0; }
code {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 0.9em;
}
.report-header {
  display: flex;
  flex-wrap: wrap;
  gap: 1.25rem;
  align-items: flex-start;
  justify-content: space-between;
  margin: 0 auto 1.25rem;
  max-width: 1400px;
}
.eyebrow {
  color: var(--muted);
  font-size: 0.75rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}
h1 { font-size: clamp(1.4rem, 3vw, 2rem); line-height: 1.2; margin-top: 0.15rem; }
.meta { color: var(--muted); margin-top: 0.35rem; }
.gate {
  min-width: 180px;
  padding: 0.8rem 1rem;
  border: 1px solid currentColor;
  border-radius: 10px;
  background: var(--surface);
}
.gate-label { display: block; color: var(--muted); font-size: 0.75rem; text-transform: uppercase; }
.gate strong { display: block; font-size: 1.35rem; letter-spacing: 0.04em; }
.gate-fail { color: var(--fail); }
.gate-pass { color: var(--pass); }
.gate-error { color: var(--error); }
.gate small { color: var(--muted); }
.facts {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 0.75rem;
  max-width: 1400px;
  margin: 0 auto 1.25rem;
}
.fact {
  padding: 0.7rem 0.9rem;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--surface);
}
.fact-label { display: block; color: var(--muted); font-size: 0.75rem; text-transform: uppercase; }
.fact-value { font-size: 1.05rem; font-weight: 700; overflow-wrap: anywhere; }
.cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
  gap: 0.75rem;
  max-width: 1400px;
  margin: 0 auto 1rem;
}
.card {
  padding: 0.8rem 1rem;
  border: 1px solid var(--border);
  border-top: 4px solid var(--muted);
  border-radius: 8px;
  background: var(--surface);
}
.card-label { display: block; color: var(--muted); font-size: 0.8rem; text-transform: uppercase; }
.card-count { font-size: 1.6rem; line-height: 1.2; }
.card-critical { border-top-color: var(--critical); }
.card-high { border-top-color: var(--high); }
.card-medium { border-top-color: var(--medium); }
.card-low { border-top-color: var(--low); }
.card-info { border-top-color: var(--info); }
.card-total { border-top-color: var(--text); }
.distribution {
  display: flex;
  height: 18px;
  max-width: 1400px;
  margin: 0 auto 1.5rem;
  overflow: hidden;
  border: 1px solid var(--border);
  border-radius: 999px;
  background: var(--surface);
}
.segment { display: block; height: 100%; }
.seg-critical { background: var(--critical); }
.seg-high { background: var(--high); }
.seg-medium { background: var(--medium); }
.seg-low { background: var(--low); }
.seg-info { background: var(--info); }
.distribution-empty {
  display: block;
  padding: 0 0.75rem;
  color: var(--muted);
  font-size: 0.75rem;
  line-height: 16px;
}
.controls {
  display: flex;
  flex-wrap: wrap;
  gap: 1rem 1.5rem;
  align-items: flex-end;
  max-width: 1400px;
  margin: 0 auto 1rem;
  padding: 0.9rem 1rem;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--surface);
}
.severity-filter {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  margin: 0;
  padding: 0;
  border: 0;
}
.severity-filter legend, .control-label {
  display: block;
  padding: 0;
  color: var(--muted);
  font-size: 0.75rem;
  font-weight: 700;
  text-transform: uppercase;
}
.severity-filter legend { width: 100%; margin-bottom: 0.35rem; }
.filter-pill {
  display: inline-flex;
  gap: 0.35rem;
  align-items: center;
  padding: 0.25rem 0.6rem;
  border: 1px solid var(--border);
  border-radius: 999px;
  font-size: 0.85rem;
  cursor: pointer;
  user-select: none;
}
.filter-pill b { color: var(--muted); }
.search { flex: 1 1 280px; }
.search input {
  width: 100%;
  margin-top: 0.35rem;
  padding: 0.45rem 0.6rem;
  border: 1px solid var(--border);
  border-radius: 6px;
  color: inherit;
  font: inherit;
}
.group-toggle { display: inline-flex; gap: 0.4rem; align-items: center; padding-bottom: 0.4rem; }
.table-wrap {
  max-width: 1400px;
  margin: 0 auto;
  overflow-x: auto;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--surface);
}
.findings { width: 100%; border-collapse: collapse; }
.findings th, .findings td {
  padding: 0.6rem 0.7rem;
  border-bottom: 1px solid var(--border);
  text-align: left;
  vertical-align: top;
}
.findings thead th {
  color: var(--muted);
  font-size: 0.72rem;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  white-space: nowrap;
}
.findings tr.group th {
  padding: 0.5rem 0.7rem;
  background: #eef2f7;
  font-size: 0.8rem;
  letter-spacing: 0.05em;
  text-transform: uppercase;
}
.findings tbody tr:last-child td { border-bottom: 0; }
.findings tbody tr.finding:hover td { background: #fafbfd; }
.badge {
  display: inline-block;
  padding: 0.1rem 0.45rem;
  border-radius: 999px;
  color: #ffffff;
  font-size: 0.72rem;
  font-weight: 700;
  text-transform: uppercase;
}
.badge-critical { background: var(--critical); }
.badge-high { background: var(--high); }
.badge-medium { background: var(--medium); }
.badge-low { background: var(--low); }
.badge-info { background: var(--info); }
.policy { white-space: nowrap; }
.title { min-width: 160px; font-weight: 600; }
.resource code { overflow-wrap: anywhere; }
.location { white-space: nowrap; }
.references { max-width: 220px; overflow-wrap: anywhere; }
.no-findings {
  max-width: 1400px;
  margin: 0 auto;
  padding: 1.5rem;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--surface);
  font-size: 1.05rem;
}
[hidden] { display: none !important; }
.visually-hidden {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}
@media (max-width: 720px) {
  body { padding: 1rem; }
  .findings { min-width: 900px; }
}
@media print {
  body { padding: 0; background: #ffffff; }
  .controls { display: none; }
  .table-wrap { overflow: visible; }
}
"""

_SCRIPT = """
(function () {
  "use strict";
  var table = document.getElementById("findings");
  if (!table) {
    return;
  }
  var body = table.tBodies[0];
  var rows = Array.prototype.slice.call(body.querySelectorAll("tr.finding"));
  var checkboxes = Array.prototype.slice.call(
    document.querySelectorAll('input[name="severity"]')
  );
  var search = document.getElementById("search");
  var group = document.getElementById("group");
  var empty = document.getElementById("filter-empty");
  var labels = {
    critical: "Critical",
    high: "High",
    medium: "Medium",
    low: "Low",
    info: "Info"
  };
  var rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

  function visibleSeverity(row) {
    for (var index = 0; index < checkboxes.length; index += 1) {
      if (checkboxes[index].value === row.dataset.severity) {
        return checkboxes[index].checked;
      }
    }
    return true;
  }

  function matches(row) {
    if (!visibleSeverity(row)) {
      return false;
    }
    var query = search ? search.value.trim().toLowerCase() : "";
    if (!query) {
      return true;
    }
    return row.dataset.search.indexOf(query) !== -1;
  }

  function compare(left, right) {
    if (group && group.checked) {
      var difference = rank[left.dataset.severity] - rank[right.dataset.severity];
      if (difference !== 0) {
        return difference;
      }
    }
    var policy = left.dataset.policy.localeCompare(right.dataset.policy);
    if (policy !== 0) {
      return policy;
    }
    return left.dataset.resource.localeCompare(right.dataset.resource);
  }

  function render() {
    Array.prototype.slice.call(body.querySelectorAll("tr.group")).forEach(function (header) {
      header.remove();
    });
    var shown = rows.filter(matches);
    shown.sort(compare);
    rows.forEach(function (row) {
      row.hidden = true;
    });
    shown.forEach(function (row) {
      row.hidden = false;
      body.appendChild(row);
    });
    if (group && group.checked) {
      var totals = {};
      shown.forEach(function (row) {
        totals[row.dataset.severity] = (totals[row.dataset.severity] || 0) + 1;
      });
      var current = null;
      shown.forEach(function (row) {
        if (row.dataset.severity !== current) {
          current = row.dataset.severity;
          var header = document.createElement("tr");
          header.className = "group";
          var cell = document.createElement("th");
          cell.colSpan = 8;
          cell.textContent = labels[current] + " (" + totals[current] + ")";
          header.appendChild(cell);
          body.insertBefore(header, row);
        }
      });
    }
    if (empty) {
      empty.hidden = shown.length !== 0;
    }
  }

  checkboxes.forEach(function (checkbox) {
    checkbox.addEventListener("change", render);
  });
  if (search) {
    search.addEventListener("input", render);
  }
  if (group) {
    group.addEventListener("change", render);
  }
  render();
})();
"""


def _escape(value: object) -> str:
    """Escape a value for HTML text and quoted attributes."""

    return html.escape(clean(value, limit=0), quote=True)


def _project_name(context: ScanContext) -> str:
    targets = [target for target in context.targets if target]
    if not targets:
        return "cloudrift"
    if len(targets) > 1:
        return f"{_target_name(targets[0])} +{len(targets) - 1} more"
    return _target_name(targets[0])


def _target_name(target: str) -> str:
    if target == "-":
        return "stdin"
    name = Path(target.rstrip("/\\")).name
    return name or target


def _timestamp(context: ScanContext) -> str:
    started = context.started_at
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    return started.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _status(context: ScanContext) -> str:
    if context.errors:
        return "ERROR"
    if context.gate.get("status") == "fail":
        return "FAIL"
    return "PASS"


def _reference_html(reference: object) -> str:
    text = str(reference).strip()
    escaped = _escape(text)
    try:
        parts = urlsplit(text)
    except ValueError:
        return escaped
    if parts.scheme.lower() not in {"http", "https"} or not parts.netloc:
        return escaped
    return f'<a href="{escaped}" rel="noreferrer noopener">{escaped}</a>'


def _references_html(finding: Finding) -> str:
    if not finding.references:
        return "-"
    return "<br>".join(_reference_html(reference) for reference in finding.references)


def _finding_row(finding: Finding) -> str:
    search = " ".join([finding.policy_id, finding.title, finding.resource_address]).lower()
    return (
        f'<tr class="finding" data-severity="{finding.severity.value}" '
        f'data-policy="{_escape(finding.policy_id)}" '
        f'data-resource="{_escape(finding.resource_address)}" '
        f'data-search="{_escape(search)}">'
        f'<td><span class="badge badge-{finding.severity.value}">'
        f"{finding.severity.value}</span></td>"
        f'<td class="policy">{_escape(finding.policy_id)}</td>'
        f'<td class="title">{_escape(finding.title)}</td>'
        f'<td class="resource"><code>{_escape(finding.resource_address)}</code></td>'
        f'<td class="location"><code>{_escape(finding.location)}</code></td>'
        f"<td>{_escape(finding.message)}</td>"
        f"<td>{_escape(finding.remediation)}</td>"
        f'<td class="references">{_references_html(finding)}</td>'
        "</tr>"
    )


def _summary_cards(counts: dict[str, int], total: int) -> str:
    cards = []
    for severity in SEVERITIES:
        cards.append(
            f'<article class="card card-{severity}">'
            f'<span class="card-label">{_LABELS[severity]}</span>'
            f'<strong class="card-count" id="count-{severity}">{counts[severity]}</strong>'
            "</article>"
        )
    cards.append(
        '<article class="card card-total">'
        '<span class="card-label">Total</span>'
        f'<strong class="card-count" id="count-total">{total}</strong>'
        "</article>"
    )
    return '<section class="cards" aria-label="Finding counts">' + "".join(cards) + "</section>"


def _distribution(counts: dict[str, int], total: int) -> str:
    if not total:
        return (
            '<div class="distribution" role="img" aria-label="No findings by severity">'
            '<span class="distribution-empty">No findings</span>'
            "</div>"
        )
    segments = []
    for severity in SEVERITIES:
        count = counts[severity]
        if not count:
            continue
        width = count / total * 100
        segments.append(
            f'<span class="segment seg-{severity}" style="width:{width:.4f}%" '
            f'title="{_LABELS[severity]}: {count}"></span>'
        )
    summary = ", ".join(f"{_LABELS[severity]} {counts[severity]}" for severity in SEVERITIES)
    return (
        f'<div class="distribution" role="img" aria-label="{summary}">'
        + "".join(segments)
        + "</div>"
    )


def _controls(counts: dict[str, int]) -> str:
    filters = []
    for severity in SEVERITIES:
        filters.append(
            f'<label class="filter-pill sev-{severity}">'
            f'<input type="checkbox" name="severity" value="{severity}" checked>'
            f"<span>{_LABELS[severity]}</span><b>{counts[severity]}</b>"
            "</label>"
        )
    return (
        '<section class="controls" aria-label="Finding filters">'
        '<fieldset class="severity-filter">'
        "<legend>Severity</legend>" + "".join(filters) + "</fieldset>"
        '<label class="search"><span class="control-label">Search</span>'
        '<input id="search" type="search" autocomplete="off" '
        'placeholder="Rule id, title, or resource"></label>'
        '<label class="group-toggle"><input id="group" type="checkbox" checked> '
        "Group by severity</label>"
        "</section>"
    )


def _findings_table(context: ScanContext) -> str:
    parts = [
        '<div class="table-wrap">',
        '<table class="findings" id="findings">',
        '<caption class="visually-hidden">Findings grouped by severity</caption>',
        "<thead><tr>",
        '<th scope="col">Severity</th>',
        '<th scope="col">Policy</th>',
        '<th scope="col">Title</th>',
        '<th scope="col">Resource</th>',
        '<th scope="col">Location</th>',
        '<th scope="col">Message</th>',
        '<th scope="col">Remediation</th>',
        '<th scope="col">References</th>',
        "</tr></thead>",
        "<tbody>",
    ]
    for severity in SEVERITIES:
        group = sorted(
            (finding for finding in context.findings if finding.severity.value == severity),
            key=lambda finding: (finding.policy_id, finding.resource_address),
        )
        if not group:
            continue
        parts.append(
            f'<tr class="group"><th colspan="8">{_LABELS[severity]} ({len(group)})</th></tr>'
        )
        parts.extend(_finding_row(finding) for finding in group)
    parts.extend(["</tbody>", "</table>", "</div>"])
    return "".join(parts)


def render_html(context: ScanContext) -> str:
    """Render a single self-contained HTML document for a scan."""

    counts = context.severity_counts()
    total = len(context.findings)
    project = _escape(_project_name(context))
    status = _status(context)
    fail_on = _escape(context.gate.get("fail_on", "high"))
    timestamp = _escape(_timestamp(context))
    targets = _escape(", ".join(context.targets) or "none")

    facts = [
        ("project", "Project", project),
        ("scanned", "Scanned", timestamp),
        ("resources", "Resources", str(len(context.resources))),
        ("policies", "Policies", str(context.policy_count)),
        ("evaluations", "Evaluations", str(context.evaluations)),
        ("suppressed", "Suppressed", str(len(context.suppressed))),
    ]
    fact_items = "".join(
        f'<div class="fact"><span class="fact-label">{label}</span>'
        f'<span class="fact-value" id="fact-{key}">{value}</span></div>'
        for key, label, value in facts
    )

    if total:
        findings = _controls(counts) + _findings_table(context)
        findings += (
            '<p class="no-findings" id="filter-empty" hidden>'
            "No findings match the current filters.</p>"
        )
    else:
        findings = '<p class="no-findings">No findings.</p>'

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="cloudrift {_escape(__version__)}">
<title>cloudrift report: {project}</title>
<style>{_STYLE}</style>
</head>
<body>
<header class="report-header">
  <div>
    <p class="eyebrow">cloudrift scan report</p>
    <h1>{project}</h1>
    <p class="meta">Targets: {targets} | Scanned {timestamp}</p>
  </div>
  <div class="gate gate-{status.lower()}">
    <span class="gate-label">Gate</span>
    <strong>{status}</strong>
    <small>threshold: {fail_on}</small>
  </div>
</header>
<section class="facts" aria-label="Scan facts">{fact_items}</section>
{_summary_cards(counts, total)}
{_distribution(counts, total)}
{findings}
<script>{_SCRIPT}</script>
</body>
</html>
"""
