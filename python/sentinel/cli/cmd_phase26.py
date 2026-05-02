"""Phase 26 CLI commands: compliance packs, plugin SDK, cloud mode."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from rich import box
from rich.table import Table

from sentinel.cli._helpers import _fail, _header, _ok, console, machine_stdout
from sentinel.compliance import (
    build_compliance_report,
    map_finding_to_frameworks,
    normalize_framework,
    render_compliance_html,
    write_report,
)


def cmd_compliance(args) -> int:
    action = getattr(args, "compliance_action", "check") or "check"
    if action != "check":
        _fail(f"unknown compliance action: {action}")
        return 2

    framework = normalize_framework(getattr(args, "framework", "owasp-llm"))
    target = Path(getattr(args, "path", "."))
    if not target.exists():
        _fail(f"target not found: {target}")
        return 2

    try:
        bom, source_data = _load_or_scan_aibom(target)
    except Exception as exc:
        _fail(f"failed to load AIBOM target: {exc}")
        return 2

    from sentinel.aibom.compliance import evaluate

    results = evaluate(bom, framework=framework)
    mappings = []
    for finding in source_data.get("findings", []) if isinstance(source_data, dict) else []:
        mappings.extend(map_finding_to_frameworks(finding))
    report = build_compliance_report(
        framework=framework,
        source=str(target),
        results=results,
        finding_mappings=mappings,
    )

    fmt = getattr(args, "format", "json")
    output = getattr(args, "output", None)
    if fmt == "html":
        rendered = render_compliance_html(report)
        if output:
            write_report(output, rendered)
            _ok(f"written {output}")
        else:
            _write(rendered)
    elif fmt == "json":
        rendered = json.dumps(report, indent=2, default=str)
        if output:
            write_report(output, rendered)
            _ok(f"written {output}")
        else:
            _write(rendered + "\n")
    else:
        _header(f"compliance · {framework}", args=args)
        _print_compliance_table(report)

    return 1 if report["summary"]["status"] == "fail" else 0


def cmd_plugin(args) -> int:
    action = getattr(args, "plugin_action", "guide") or "guide"
    if getattr(args, "json_output", False):
        args.format = "json"
        console.file = sys.stderr

    if action == "new":
        from sentinel.plugin_sdk import scaffold_plugin
        payload = scaffold_plugin(getattr(args, "name"), getattr(args, "output_dir", "."))
        _emit_payload(args, payload)
        return 0
    if action == "install":
        from sentinel.plugin_sdk import install_plugin_pack
        try:
            payload = install_plugin_pack(getattr(args, "pack"))
        except Exception as exc:
            _fail(str(exc))
            return 2
        _emit_payload(args, payload)
        return 0
    if action == "guide":
        from sentinel.plugin_sdk import PLUGIN_SDK_SCHEMA_VERSION, plugin_authoring_guide
        payload = {
            "schema_version": PLUGIN_SDK_SCHEMA_VERSION,
            "summary": {"status": "ok"},
            "guide": plugin_authoring_guide(),
            "entry_point_group": "sentinel.scanners",
        }
        _emit_payload(args, payload)
        return 0

    _fail(f"unknown plugin action: {action}")
    return 2


def cmd_cloud(args) -> int:
    action = getattr(args, "cloud_action", "scan") or "scan"
    if action != "scan":
        _fail(f"unknown cloud action: {action}")
        return 2
    if getattr(args, "json_output", False):
        args.format = "json"
        console.file = sys.stderr
    from sentinel.cloud import plan_cloud_scan
    try:
        payload = plan_cloud_scan(getattr(args, "uri"))
    except Exception as exc:
        _fail(str(exc))
        return 2
    _emit_payload(args, payload)
    return 0


def _load_or_scan_aibom(target: Path):
    from sentinel.aibom.models import AIBOMResult
    if target.suffix.lower() == ".json":
        data = json.loads(target.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "components" in data:
            return AIBOMResult.from_dict(data), data
    from sentinel.aibom.scan_pipeline import ScanPipeline
    result = ScanPipeline().run(target)
    return result, result.as_dict()


def _emit_payload(args, payload: dict[str, Any]) -> None:
    fmt = getattr(args, "format", "table")
    output = getattr(args, "output", None)
    rendered = json.dumps(payload, indent=2, default=str)
    if output:
        Path(output).write_text(rendered, encoding="utf-8")
        _ok(f"written {output}")
        return
    if fmt == "json" or getattr(args, "json_output", False):
        _write(rendered + "\n")
    else:
        _write(rendered + "\n")


def _print_compliance_table(report: dict[str, Any]) -> None:
    table = Table(box=box.SIMPLE_HEAVY)
    table.add_column("rule")
    table.add_column("severity")
    table.add_column("violators", justify="right")
    table.add_column("title")
    for violation in report.get("violations", []):
        table.add_row(
            str(violation["rule_id"]),
            str(violation["severity"]),
            str(violation["violator_count"]),
            str(violation["title"]),
        )
    if not report.get("violations"):
        table.add_row("-", "-", "0", "No compliance violations")
    console.print(table)


def _write(text: str) -> None:
    out = machine_stdout()
    out.write(text)
    out.flush()
