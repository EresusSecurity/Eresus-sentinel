from __future__ import annotations

import csv
import html
import io
import json
import xml.etree.ElementTree as ET
from typing import Any


def render_report(result: dict[str, Any], fmt: str) -> str:
    if fmt == "json":
        return json.dumps(result, indent=2, sort_keys=True, default=str)
    if fmt == "markdown":
        return _markdown(result)
    if fmt == "csv":
        return _csv(result)
    if fmt == "junit":
        return _junit(result)
    if fmt == "sarif":
        return json.dumps(_sarif(result), indent=2, sort_keys=True, default=str)
    if fmt == "html":
        return _html(result)
    if fmt == "pdf":
        return json.dumps({"schema_version": "sentinel.report.pdf-manifest.v1", "source_run": result.get("run", {}).get("id"), "status": "renderer-not-bundled"}, indent=2)
    raise ValueError(f"unsupported report format: {fmt}")


def _markdown(result: dict[str, Any]) -> str:
    summary = result.get("summary", {})
    lines = [
        "# Sentinel Evaluation Report",
        "",
        f"Run: `{result.get('run', {}).get('id', '')}`",
        f"Cells: {summary.get('cells', 0)}",
        f"Passed: {summary.get('passed', 0)}",
        f"Failed: {summary.get('failed', 0)}",
        "",
        "| Cell | Provider | Status | Assertions |",
        "|------|----------|--------|------------|",
    ]
    for cell in result.get("cells", []):
        lines.append(f"| `{cell.get('id')}` | {cell.get('provider')} | {cell.get('status')} | {len(cell.get('assertions', []))} |")
    return "\n".join(lines) + "\n"


def _csv(result: dict[str, Any]) -> str:
    handle = io.StringIO()
    writer = csv.DictWriter(handle, fieldnames=["run_id", "cell_id", "provider", "model", "prompt_id", "dataset_id", "record_id", "status"])
    writer.writeheader()
    run_id = result.get("run", {}).get("id", "")
    for cell in result.get("cells", []):
        writer.writerow(
            {
                "run_id": run_id,
                "cell_id": cell.get("id"),
                "provider": cell.get("provider"),
                "model": cell.get("model"),
                "prompt_id": cell.get("prompt_id"),
                "dataset_id": cell.get("dataset_id"),
                "record_id": cell.get("record_id"),
                "status": cell.get("status"),
            }
        )
    return handle.getvalue()


def _junit(result: dict[str, Any]) -> str:
    suite = ET.Element("testsuite", name="sentinel-eval", tests=str(result.get("summary", {}).get("cells", 0)), failures=str(result.get("summary", {}).get("failed", 0)))
    for cell in result.get("cells", []):
        case = ET.SubElement(suite, "testcase", name=str(cell.get("id")), classname=str(cell.get("provider")))
        if cell.get("status") != "passed":
            failure = ET.SubElement(case, "failure", message="assertion failed")
            failure.text = json.dumps(cell.get("assertions", []), sort_keys=True)
    return ET.tostring(suite, encoding="unicode")


def _sarif(result: dict[str, Any]) -> dict[str, Any]:
    sarif_results = []
    for cell in result.get("cells", []):
        if cell.get("status") == "passed":
            continue
        sarif_results.append(
            {
                "ruleId": "SENTINEL-EVAL-ASSERTION",
                "level": "error",
                "message": {"text": f"Evaluation cell failed: {cell.get('id')}"},
                "properties": {"cell": cell.get("id"), "provider": cell.get("provider")},
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": "Sentinel", "rules": []}}, "results": sarif_results}],
    }


def _html(result: dict[str, Any]) -> str:
    summary = result.get("summary", {})
    rows = "".join(
        f"<tr><td>{html.escape(str(cell.get('id')))}</td><td>{html.escape(str(cell.get('provider')))}</td><td>{html.escape(str(cell.get('status')))}</td><td>{len(cell.get('assertions', []))}</td></tr>"
        for cell in result.get("cells", [])
    )
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Sentinel Evaluation Report</title>"
        "<style>body{font-family:Arial,sans-serif;margin:32px;color:#111827;background:#fff}table{border-collapse:collapse;width:100%}td,th{border:1px solid #e5e7eb;padding:8px;text-align:left}th{background:#f9fafb}</style>"
        "</head><body>"
        f"<h1>Sentinel Evaluation Report</h1><p>Run {html.escape(str(result.get('run', {}).get('id', '')))}</p>"
        f"<p>Cells {summary.get('cells', 0)} Passed {summary.get('passed', 0)} Failed {summary.get('failed', 0)}</p>"
        "<table><thead><tr><th>Cell</th><th>Provider</th><th>Status</th><th>Assertions</th></tr></thead><tbody>"
        f"{rows}</tbody></table></body></html>"
    )
