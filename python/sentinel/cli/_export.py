"""Export formatters — JSON, SARIF, CSV, Markdown, HTML, JUnit, OTLP, Splunk, text, CycloneDX, SPDX, Webhook, ModelCard."""

from __future__ import annotations

import json
import re
from pathlib import Path

from sentinel.cli._helpers import _sev, machine_stdout

_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


def _json_envelope(findings, *, command: str | None = None) -> dict:
    """Build a standard JSON envelope from a list of findings."""
    from sentinel.scan_report import build_scan_envelope

    return build_scan_envelope(findings, command=command)


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
            rule_id = getattr(f, "rule_id", "")
            title = getattr(f, "title", "").replace(",", ";")
            description = getattr(f, "description", "").replace(",", ";")[:200]
            lines.append(f"{rule_id},{v},{title},{description}")
        result = "\n".join(lines)
    elif fmt == "markdown":
        result = _markdown_report(findings)
    elif fmt == "html":
        result = _html_report(findings)
    elif fmt == "junit":
        result = _junit_report(findings)
    elif fmt == "otlp":
        result = _otlp_report(findings, out=out)
    elif fmt == "splunk":
        result = _splunk_report(findings, out=out)
    elif fmt == "plaintext":
        result = _plaintext_report(findings)
    elif fmt == "summary":
        result = _summary_report(findings)
    elif fmt == "cyclonedx":
        result = json.dumps(_cyclonedx_report(findings), indent=2, default=str)
    elif fmt == "spdx":
        result = json.dumps(_spdx_report(findings), indent=2, default=str)
    elif fmt == "webhook":
        webhook_url = getattr(args, "webhook_url", None)
        if not webhook_url:
            from sentinel.cli._helpers import _warn
            _warn("--webhook-url required for webhook format")
            return
        webhook_token = getattr(args, "webhook_token", None)
        result = _webhook_report(findings, webhook_url, token=webhook_token)
        return
    elif fmt == "modelcard":
        result = json.dumps(_modelcard_report(findings), indent=2, default=str)
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


def _otlp_report(findings, *, out: str | None = None) -> str:
    """Render or deliver findings as OTLP HTTP JSON logs."""

    from sentinel.export.otlp import OTLPExporter

    exporter = OTLPExporter()
    if out or not exporter.configured:
        return exporter.render(findings)
    result = exporter.export_findings(findings)
    return json.dumps(result.to_dict(), indent=2, default=str)


def _splunk_report(findings, *, out: str | None = None) -> str:
    """Render or deliver findings as Splunk HEC events."""
    import time

    from sentinel.export.splunk import SplunkHECExporter

    exporter = SplunkHECExporter()
    if out or not exporter.configured:
        rendered = exporter.render(findings)
        if not rendered:
            rendered = json.dumps({
                "time": time.time(),
                "source": "eresus-sentinel",
                "sourcetype": "sentinel:summary",
                "event": {"total_findings": 0, "status": "clean"},
            }, sort_keys=True)
        return rendered + "\n"
    result = exporter.export_findings(findings)
    return json.dumps(result.to_dict(), indent=2, default=str)


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


def _plaintext_report(findings) -> str:
    """Human-readable text export without table alignment."""
    from datetime import datetime, timezone

    from sentinel import __version__ as ver

    lines = [
        f"Eresus Sentinel Scan Report v{ver}",
        f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"Findings: {len(findings)}",
        "",
    ]
    if not findings:
        lines.append("No security findings detected.")
        return "\n".join(lines) + "\n"

    for index, finding in enumerate(findings, 1):
        severity, _, _ = _sev(finding)
        lines.append(
            f"{index}. [{severity}] {getattr(finding, 'rule_id', '')} "
            f"{_one_line(str(getattr(finding, 'title', '')))}"
        )
        target = _one_line(str(getattr(finding, "target", "")))
        description = _one_line(str(getattr(finding, "description", "")))
        evidence = _one_line(str(getattr(finding, "evidence", "")))
        if target:
            lines.append(f"   Target: {target}")
        if description:
            lines.append(f"   Description: {description}")
        if evidence:
            lines.append(f"   Evidence: {evidence}")
    return "\n".join(lines) + "\n"


def _summary_report(findings) -> str:
    """Concise count-oriented report for CI logs."""
    counts: dict[str, int] = {}
    for finding in findings:
        severity, _, _ = _sev(finding)
        counts[severity] = counts.get(severity, 0) + 1

    ordered = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    lines = [f"Findings: {len(findings)}"]
    lines.append(
        "Severity: "
        + ", ".join(f"{severity}={counts.get(severity, 0)}" for severity in ordered)
    )
    if findings:
        lines.append("Top findings:")
        for finding in findings[:5]:
            severity, _, _ = _sev(finding)
            lines.append(
                f"- [{severity}] {getattr(finding, 'rule_id', '')} "
                f"{_one_line(str(getattr(finding, 'title', '')), limit=120)}"
            )
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

    extensions_html = _html_report_extensions(findings)
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
$extensions
<h2>Findings</h2>
$findings
</body>
</html>''')

    return template.substitute(
        version=ver, date=now, count=len(findings),
        summary=summary_html, extensions=extensions_html, findings=findings_html,
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


def _html_report_extensions(findings) -> str:
    """Render optional interactive sections carried by richer analyzers."""
    correlation_groups: dict[str, list] = {}
    taint_traces = []
    for finding in findings:
        group = getattr(finding, "correlation_group", "") or getattr(finding, "fingerprint", "")
        if group:
            correlation_groups.setdefault(str(group), []).append(finding)
        trace = getattr(finding, "taint_trace", None)
        if trace:
            taint_traces.append((finding, trace))

    parts: list[str] = []
    visible_groups = {
        group: grouped
        for group, grouped in correlation_groups.items()
        if len(grouped) > 1
    }
    if visible_groups:
        rows = []
        for group, grouped in sorted(visible_groups.items()):
            rules = ", ".join(sorted({str(getattr(item, "rule_id", "")) for item in grouped}))
            rows.append(
                "<details><summary>"
                f"{_esc(group)} ({len(grouped)} findings)"
                "</summary><p>"
                f"{_esc(rules)}"
                "</p></details>"
            )
        parts.append("<h2>Correlation</h2>" + "\n".join(rows))

    if taint_traces:
        rows = []
        for finding, trace in taint_traces[:20]:
            if isinstance(trace, (list, tuple)):
                trace_text = " -> ".join(str(step) for step in trace)
            else:
                trace_text = str(trace)
            rows.append(
                "<details><summary>"
                f"{_esc(str(getattr(finding, 'rule_id', '')))}"
                "</summary><p><code>"
                f"{_esc(trace_text)}"
                "</code></p></details>"
            )
        parts.append("<h2>Taint Diagrams</h2>" + "\n".join(rows))
    return "\n".join(parts)


# ── CycloneDX 1.6 ML-BOM format ───────────────────────────────────

def _cyclonedx_report(findings) -> dict:
    """Build a CycloneDX 1.6 BOM JSON with findings as vulnerabilities."""
    from datetime import datetime, timezone
    import uuid

    try:
        import importlib.metadata
        tool_version = importlib.metadata.version("eresus-sentinel")
    except Exception:
        tool_version = "0.0.0"

    _sev_cdx = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFO": "info"}

    vulns = []
    for f in findings:
        sev_str, _, _ = _sev(f)
        loc = getattr(f, "location", None)
        file_ref = getattr(loc, "file", None) if loc else getattr(f, "target", None)
        line_start = getattr(loc, "line_start", None) if loc else None

        source = {}
        if file_ref:
            source["url"] = f"file://{file_ref}"
            if line_start:
                source["url"] += f"#L{line_start}"

        vuln: dict = {
            "bom-ref": f"sentinel:{getattr(f, 'rule_id', 'UNKNOWN')}-{uuid.uuid4().hex[:8]}",
            "id": getattr(f, "rule_id", "UNKNOWN"),
            "source": source,
            "ratings": [{"severity": _sev_cdx.get(sev_str, "unknown"), "method": "sentinel"}],
            "description": getattr(f, "description", ""),
            "recommendation": getattr(f, "remediation", "") or "",
            "detail": getattr(f, "evidence", ""),
        }
        owasp = getattr(f, "owasp_llm", "")
        if owasp:
            vuln["advisories"] = [{"title": f"OWASP LLM Top 10: {owasp}", "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"}]
        vulns.append(vuln)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "Eresus", "name": "sentinel", "version": tool_version}],
        },
        "vulnerabilities": vulns,
    }


# ── SPDX 3.0 JSON-LD format ────────────────────────────────────────

def _spdx_report(findings) -> dict:
    """Build a minimal SPDX 3.0 JSON-LD document with security findings."""
    from datetime import datetime, timezone
    import hashlib

    try:
        import importlib.metadata
        tool_version = importlib.metadata.version("eresus-sentinel")
    except Exception:
        tool_version = "0.0.0"

    SPDX_CONTEXT = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
    NS = "https://sentinel.eresus.io/ns/spdx#"

    def _spdx_id(rule_id: str, target: str) -> str:
        digest = hashlib.sha256(f"{rule_id}:{target}".encode()).hexdigest()[:12]
        return f"urn:spdx:sentinel-{rule_id}-{digest}"

    _sev_score = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5, "INFO": 0.5}

    elements = []
    for f in findings:
        sev_str, _, _ = _sev(f)
        loc = getattr(f, "location", None)
        target = getattr(f, "target", "") or ""
        line_start = getattr(loc, "line_start", None) if loc else None

        elem: dict = {
            "type": "security_VulnAssessmentRelationship",
            "spdxId": _spdx_id(getattr(f, "rule_id", "UNKNOWN"), target),
            "security_vuln": getattr(f, "rule_id", "UNKNOWN"),
            "security_cvssScore": _sev_score.get(sev_str, 0.0),
            "security_severity": sev_str.lower(),
            "name": getattr(f, "title", ""),
            "comment": getattr(f, "description", ""),
            "security_remediation": getattr(f, "remediation", ""),
            "security_locator": f"file://{target}" + (f"#L{line_start}" if line_start else ""),
        }
        elements.append(elem)

    return {
        "@context": SPDX_CONTEXT,
        "spdxVersion": "SPDX-3.0",
        "SPDXID": f"{NS}sentinel-scan",
        "name": "Eresus Sentinel Scan Results",
        "dataLicense": "CC0-1.0",
        "creator": f"Tool: sentinel-{tool_version}",
        "created": datetime.now(timezone.utc).isoformat(),
        "elements": elements,
    }


# ── Webhook / HTTP push format ─────────────────────────────────────

def _webhook_report(findings, url: str, *, token: str | None = None) -> str:
    """POST findings JSON to a webhook URL. Returns response status string."""
    import urllib.request
    import urllib.error
    from datetime import datetime, timezone

    _sev_score = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5, "INFO": 0.5}
    counts: dict[str, int] = {}
    finding_list = []
    for f in findings:
        sev_str, _, _ = _sev(f)
        counts[sev_str] = counts.get(sev_str, 0) + 1
        finding_list.append({
            "rule_id": getattr(f, "rule_id", ""),
            "severity": sev_str,
            "title": getattr(f, "title", ""),
            "description": getattr(f, "description", ""),
            "target": getattr(f, "target", ""),
            "evidence": getattr(f, "evidence", ""),
            "remediation": getattr(f, "remediation", ""),
            "owasp_llm": getattr(f, "owasp_llm", ""),
        })

    has_critical = counts.get("CRITICAL", 0) > 0
    has_high = counts.get("HIGH", 0) > 0

    if "hooks.slack.com" in url:
        severity_label = "🔴 CRITICAL" if has_critical else ("🟠 HIGH" if has_high else "🟡 MEDIUM")
        payload = {
            "text": f"*Sentinel Scan* — {len(findings)} finding(s)",
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": "Eresus Sentinel Scan Results"}},
                {"type": "section", "text": {"type": "mrkdwn", "text": (
                    f"*Findings:* {len(findings)}\n"
                    + "\n".join(f"• {sev}: {cnt}" for sev, cnt in sorted(counts.items()))
                )}},
                {"type": "section", "text": {"type": "mrkdwn", "text": f"*Status:* {severity_label}"}},
            ],
        }
    elif "events.pagerduty.com" in url:
        severity_pd = "critical" if has_critical else ("error" if has_high else "warning")
        payload = {
            "routing_key": token or "",
            "event_action": "trigger",
            "payload": {
                "summary": f"Sentinel: {len(findings)} security finding(s)",
                "severity": severity_pd,
                "source": "eresus-sentinel",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "custom_details": {"summary": counts, "top_findings": finding_list[:5]},
            },
        }
    else:
        payload = {
            "tool": "sentinel",
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(findings),
            "summary": counts,
            "findings": finding_list,
        }

    body = json.dumps(payload, default=str).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": "eresus-sentinel/webhook"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
            from sentinel.cli._helpers import _ok
            _ok(f"webhook posted → HTTP {resp.status}")
            return f"HTTP {resp.status}"
    except urllib.error.HTTPError as exc:
        from sentinel.cli._helpers import _warn
        _warn(f"webhook HTTP {exc.code}: {exc.reason}")
        return f"HTTP {exc.code}"
    except Exception as exc:
        from sentinel.cli._helpers import _warn
        _warn(f"webhook error: {exc}")
        return f"error: {exc}"


# ── AI Model Card security format ─────────────────────────────────

def _modelcard_report(findings) -> dict:
    """Generate HuggingFace-compatible model card security section."""
    from datetime import datetime, timezone

    try:
        import importlib.metadata
        tool_version = importlib.metadata.version("eresus-sentinel")
    except Exception:
        tool_version = "0.0.0"

    counts: dict[str, int] = {}
    critical_findings = []
    for f in findings:
        sev_str, _, _ = _sev(f)
        counts[sev_str] = counts.get(sev_str, 0) + 1
        if sev_str in ("CRITICAL", "HIGH"):
            critical_findings.append({
                "id": getattr(f, "rule_id", ""),
                "severity": sev_str,
                "title": getattr(f, "title", ""),
                "remediation": getattr(f, "remediation", ""),
            })

    total_critical = counts.get("CRITICAL", 0)
    total_high = counts.get("HIGH", 0)
    risk_score = min(10.0, total_critical * 3.0 + total_high * 1.5)
    risk_label = "critical" if risk_score >= 7 else ("high" if risk_score >= 4 else ("medium" if risk_score >= 1 else "low"))

    compliance: dict[str, str] = {}
    owasp_set = set()
    for f in findings:
        owasp = getattr(f, "owasp_llm", "")
        if owasp:
            owasp_set.add(owasp)
    if not owasp_set:
        compliance["owasp_llm_top10"] = "PASS"
    else:
        compliance["owasp_llm_top10"] = f"FAIL ({', '.join(sorted(owasp_set))})"

    return {
        "card_type": "model_security_assessment",
        "schema_version": "1.0",
        "tool": {"name": "eresus-sentinel", "version": tool_version},
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "security_findings": {
            "total": len(findings),
            "by_severity": counts,
            "risk_score": round(risk_score, 1),
            "risk_label": risk_label,
        },
        "compliance": compliance,
        "critical_high_findings": critical_findings[:20],
        "recommendation": (
            "No critical security issues detected." if not critical_findings
            else f"Remediate {len(critical_findings)} critical/high finding(s) before deployment."
        ),
    }
