"""Export formatters — JSON, SARIF, CSV, Markdown, HTML, JUnit."""

from __future__ import annotations

import json
import re
from pathlib import Path

from sentinel.cli._helpers import _sev, machine_stdout

_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


def _json_envelope(findings, *, command: str | None = None) -> dict:
    """Build a standard JSON envelope from a list of findings."""
    from datetime import datetime, timezone

    from sentinel import __version__ as ver

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    serialized = []
    for f in findings:
        v, _, _ = _sev(f)
        severity_counts[v] = severity_counts.get(v, 0) + 1
        if hasattr(f, "to_dict"):
            serialized.append(f.to_dict())
        else:
            serialized.append({
                "rule_id": getattr(f, "rule_id", ""),
                "severity": v,
                "title": getattr(f, "title", ""),
                "description": getattr(f, "description", ""),
                "target": str(getattr(f, "target", "")),
                "evidence": str(getattr(f, "evidence", "")),
                "remediation": getattr(f, "remediation", getattr(f, "fix_hint", "")),
            })

    status = "findings" if findings else "clean"
    return _sanitize_for_json({
        "schema_version": "0.1",
        "command": command,
        "summary": {
            "command": command,
            "status": status,
            "total_findings": len(findings),
        },
        "totals": {
            "findings": len(findings),
            "severity": severity_counts,
        },
        "findings": serialized,
        "errors": [],
        "metadata": {
            "tool": "eresus-sentinel",
            "version": ver,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
    })


def _export(args, findings):
    fmt = getattr(args, "format", "table")
    out = getattr(args, "output", None)
    if fmt == "table":
        if not out:
            return
        result = _table_report(findings)

    elif fmt == "json":
        result = json.dumps(
            _json_envelope(findings, command=getattr(args, "command", None)),
            indent=2,
            default=str,
            ensure_ascii=True,
        )
    elif fmt == "sarif":
        result = json.dumps(_sarif(findings), indent=2, default=str)
    elif fmt == "csv":
        lines = ["rule_id,severity,title,description"]
        for f in findings:
            v, _, _ = _sev(f)
            lines.append(f"{getattr(f,'rule_id','')},{v},{getattr(f,'title','').replace(',',';')},{getattr(f,'description','').replace(',',';')[:200]}")
        result = "\n".join(lines)
    elif fmt == "markdown":
        result = _markdown_report(findings)
    elif fmt == "html":
        result = _html_report(findings)
    elif fmt == "junit":
        result = _junit_report(findings)
    else:
        return

    if out:
        Path(out).write_text(result, encoding="utf-8")
        from sentinel.cli._helpers import _ok
        _ok(f"written {out}")
    else:
        out_stream = machine_stdout()
        out_stream.write(result)
        out_stream.write("\n")
        out_stream.flush()


def _table_report(findings) -> str:
    """Plain-text table export for `-f table -o report.txt`."""
    from datetime import datetime, timezone

    from sentinel import __version__ as ver

    rows = []
    for finding in findings:
        severity, _, _ = _sev(finding)
        rows.append((
            severity,
            str(getattr(finding, "rule_id", "")),
            _one_line(str(getattr(finding, "title", ""))),
            _one_line(str(getattr(finding, "target", ""))),
        ))

    headers = ("Severity", "Rule", "Title", "Target")
    widths = [
        (
            max(len(headers[index]), *(len(row[index]) for row in rows))
            if rows else len(headers[index])
        )
        for index in range(len(headers))
    ]

    def fmt_row(values: tuple[str, str, str, str]) -> str:
        return "  ".join(value.ljust(widths[index]) for index, value in enumerate(values))

    lines = [
        f"Eresus Sentinel Scan Report v{ver}",
        f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"Findings: {len(findings)}",
        "",
    ]

    if not rows:
        lines.append("No security findings detected.")
        return "\n".join(lines) + "\n"

    lines.append(fmt_row(headers))
    lines.append(fmt_row(tuple("-" * width for width in widths)))
    lines.extend(fmt_row(row) for row in rows)

    for index, finding in enumerate(findings, 1):
        description = _one_line(str(getattr(finding, "description", "")))
        evidence = _one_line(str(getattr(finding, "evidence", "")))
        if description or evidence:
            lines.append("")
            lines.append(f"{index}. {getattr(finding, 'rule_id', '')}")
            if description:
                lines.append(f"   Description: {description}")
            if evidence:
                lines.append(f"   Evidence: {evidence}")

    return "\n".join(lines) + "\n"


def _one_line(value: str, limit: int = 180) -> str:
    cleaned = _sanitize_for_json(value).replace("\n", " ").replace("\r", " ")
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 3] + "..."


def _sanitize_for_json(obj):
    """Recursively strip ANSI escape codes and control chars from string values."""
    if isinstance(obj, str):
        s = _ANSI_ESCAPE_RE.sub("", obj)
        return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", s)
    if isinstance(obj, dict):
        return {k: _sanitize_for_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize_for_json(v) for v in obj]
    return obj


def _sarif(findings) -> dict:
    from sentinel import __version__ as ver
    rules, results = [], []
    seen_rules = set()
    for i, f in enumerate(findings):
        v, _, _ = _sev(f)
        rid = getattr(f, "rule_id", f"RULE-{i}")
        level = "error" if v in ("HIGH", "CRITICAL") else "warning" if v == "MEDIUM" else "note"

        if rid not in seen_rules:
            rule_entry = {"id": rid, "shortDescription": {"text": getattr(f, "title", "")}}
            cwe_ids = getattr(f, "cwe_ids", [])
            if cwe_ids:
                rule_entry["properties"] = {
                    "tags": [
                        f"CWE-{c}" if not str(c).startswith("CWE") else str(c)
                        for c in cwe_ids
                    ]
                }
            rules.append(rule_entry)
            seen_rules.add(rid)

        result_entry = {
            "ruleId": rid,
            "level": level,
            "message": {"text": getattr(f, "description", "")},
        }
        evidence = getattr(f, "evidence", "")
        if evidence:
            result_entry["message"]["text"] += f"\n\nEvidence: {evidence[:300]}"

        results.append(result_entry)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Eresus Sentinel",
                        "version": ver,
                        "informationUri": "https://github.com/EresusSecurity/Eresus-sentiel",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def _markdown_report(findings) -> str:
    from datetime import datetime, timezone

    from sentinel import __version__ as ver

    lines = [
        "# Eresus Sentinel Scan Report",
        "",
        f"**Version**: {ver}  ",
        f"**Date**: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
        f"**Findings**: {len(findings)}",
        "",
    ]

    if not findings:
        lines.append("> ✅ No security findings detected.")
        return "\n".join(lines)

    counts = {}
    for f in findings:
        v, _, _ = _sev(f)
        counts[v] = counts.get(v, 0) + 1

    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in counts:
            lines.append(f"| {sev} | {counts[sev]} |")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    for i, f in enumerate(findings, 1):
        v, emoji, _ = _sev(f)
        rid = getattr(f, "rule_id", "")
        title = getattr(f, "title", "")
        desc = getattr(f, "description", "")
        evidence = getattr(f, "evidence", "")
        fix = getattr(f, "remediation", getattr(f, "fix_hint", ""))

        lines.append(f"### {i}. {emoji} [{v}] {rid} — {title}")
        lines.append("")
        if desc:
            lines.append(f"{desc}")
            lines.append("")
        if evidence:
            lines.append(f"**Evidence**: `{evidence[:200]}`")
            lines.append("")
        if fix:
            lines.append(f"**Remediation**: {fix}")
            lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def _html_report(findings) -> str:
    from datetime import datetime, timezone
    from string import Template

    from sentinel import __version__ as ver

    sev_colors = {
        "CRITICAL": "#ef4444", "HIGH": "#f97316",
        "MEDIUM": "#eab308", "LOW": "#3b82f6", "INFO": "#6b7280",
    }

    counts = {}
    for f in findings:
        v, _, _ = _sev(f)
        counts[v] = counts.get(v, 0) + 1

    summary_html = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        c = counts.get(sev, 0)
        if c > 0:
            color = sev_colors.get(sev, "#6b7280")
            summary_html += f'<span class="badge" style="background:{color}">{sev}: {c}</span>\n'

    findings_html = ""
    for _i, f in enumerate(findings, 1):
        v, emoji, _ = _sev(f)
        rid = getattr(f, "rule_id", "")
        title = getattr(f, "title", "")
        desc = getattr(f, "description", "")
        evidence = getattr(f, "evidence", "")
        fix = getattr(f, "remediation", getattr(f, "fix_hint", ""))
        color = sev_colors.get(v, "#6b7280")
        desc_html = f"<p>{_esc(desc)}</p>" if desc else ""
        evidence_html = (
            '<div class="evidence"><strong>Evidence:</strong> '
            f"<code>{_esc(evidence[:300])}</code></div>"
            if evidence else ""
        )
        fix_html = (
            f'<div class="fix"><strong>Fix:</strong> {_esc(fix)}</div>'
            if fix else ""
        )

        findings_html += f'''
        <div class="finding" style="border-left:4px solid {color}">
            <div class="finding-header">
                <span class="sev" style="color:{color}">{v}</span>
                <code>{rid}</code> — {_esc(title)}
            </div>
            {desc_html}
            {evidence_html}
            {fix_html}
        </div>'''

    if not findings:
        findings_html = '<div class="clean">✅ No security findings detected.</div>'

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    template = Template('''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Eresus Sentinel — Scan Report</title>
<style>
:root{--bg:#09090B;--card:#111114;--text:#D1D5DB;--muted:#6B7280;--border:#1C1C22;--accent:#DC2626}
*{margin:0;padding:0;box-sizing:border-box}
body{
font-family:'JetBrains Mono','SF Mono',ui-monospace,monospace;
background:var(--bg);color:var(--text);padding:2rem;max-width:900px;
margin:0 auto;line-height:1.6;font-size:13px}
h1{font-size:14px;letter-spacing:0.15em;text-transform:uppercase;color:#fff;margin-bottom:4px}
h2{
font-size:11px;letter-spacing:0.2em;text-transform:uppercase;margin:2rem 0 1rem;
color:var(--muted);border-bottom:1px solid var(--border);padding-bottom:8px}
.meta{color:var(--muted);font-size:10px;margin-bottom:2rem;letter-spacing:0.1em}
.badge{
display:inline-block;padding:2px 8px;font-size:9px;font-weight:700;color:#fff;
margin-right:6px;letter-spacing:0.1em}
.brand{display:flex;align-items:center;gap:8px;margin-bottom:4px}
.brand-dot{width:8px;height:8px;background:var(--accent);border-radius:50%}
.finding{
background:var(--card);border-left:2px solid var(--border);
padding:12px 16px;margin-bottom:8px}
.finding-header{font-weight:600;margin-bottom:6px;font-size:11px}
.finding p,.finding .evidence,.finding .fix{font-size:11px;color:var(--muted);margin-top:4px}
.finding code{
background:#000;padding:2px 6px;font-size:10px;
border:1px solid var(--border);color:#F87171}
.sev{font-weight:700;margin-right:8px;font-size:10px;letter-spacing:0.1em}
.clean{text-align:center;padding:3rem;font-size:12px;color:#22c55e}
::selection{background:#DC262640}
</style>
</head>
<body>
<div class="brand"><div class="brand-dot"></div><h1>Eresus Sentinel</h1></div>
<div class="meta">v$version · $date · $count finding(s)</div>
<div class="summary">$summary</div>
<h2>Findings</h2>
$findings
</body>
</html>''')

    return template.substitute(
        version=ver, date=now, count=len(findings),
        summary=summary_html, findings=findings_html,
    )


def _junit_report(findings) -> str:
    from xml.sax.saxutils import escape, quoteattr

    cases = []
    for index, finding in enumerate(findings, 1):
        severity, _, _ = _sev(finding)
        rule_id = escape(str(getattr(finding, "rule_id", f"finding-{index}")))
        description = escape(str(getattr(finding, "description", "")))
        evidence = escape(str(getattr(finding, "evidence", "")))
        message = quoteattr(
            (
                f"{severity} "
                f"{getattr(finding, 'rule_id', f'finding-{index}')} "
                f"{getattr(finding, 'title', '')}"
            ).strip()
        )
        details = "\n".join(part for part in (description, evidence) if part)
        cases.append(
            f'  <testcase classname="sentinel.scan" name="{rule_id}">'
            f'<failure message={message}>{details}</failure></testcase>'
        )

    if not cases:
        cases.append('  <testcase classname="sentinel.scan" name="clean" />')

    failures = len(findings)
    tests = max(1, failures)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<testsuite name="eresus-sentinel" tests="{tests}" failures="{failures}">\n'
        + "\n".join(cases)
        + "\n</testsuite>"
    )


def _esc(text: str) -> str:
    """Escape HTML special characters."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
