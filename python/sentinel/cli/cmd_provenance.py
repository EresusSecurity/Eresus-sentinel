"""Model provenance CLI commands."""

from __future__ import annotations

import sys
from pathlib import Path

from rich import box
from rich.table import Table

from sentinel.cli._helpers import _fail, _header, _ok, console
from sentinel.cli.cmd_tools import _emit_info
from sentinel.provenance import FingerprintDatabase, ModelProvenanceScanner, compare_models


def cmd_provenance(args) -> int:
    """Dispatch provenance subcommands."""
    if getattr(args, "json_output", False):
        args.format = "json"
        console.file = sys.stderr
    action = getattr(args, "provenance_action", "scan")
    if action == "scan":
        return _cmd_provenance_scan(args)
    if action == "compare":
        return _cmd_provenance_compare(args)
    if action == "db-info":
        return _cmd_provenance_db_info(args)
    if action == "download-fingerprints":
        return _cmd_provenance_download(args)
    _fail(f"unknown provenance action: {action}")
    return 2


def _load_db(args) -> FingerprintDatabase:
    return FingerprintDatabase.load(getattr(args, "db", None))


def _cmd_provenance_scan(args) -> int:
    if not Path(args.model).exists():
        _fail(f"model path not found: {args.model}")
        return 2
    scanner = ModelProvenanceScanner(_load_db(args))
    report = scanner.scan(args.model, top_k=getattr(args, "top_k", 5), threshold=getattr(args, "threshold", 0.5))
    payload = report.to_dict()
    if getattr(args, "format", "table") in ("json", "sarif") or getattr(args, "output", None) or getattr(args, "json_output", False):
        _emit_info(args, payload)
        return 0

    _header(f"provenance scan -> {args.model}", args=args)
    console.print(f"  verdict: [bold]{report.verdict}[/bold]  score={report.pipeline_score:.3f}")
    table = Table(box=box.SIMPLE_HEAVY, border_style="dim")
    table.add_column("match", style="bold")
    table.add_column("family")
    table.add_column("publisher")
    table.add_column("score", justify="right")
    for match in report.matches:
        table.add_row(match["model_id"], match["family"], match["publisher"], f"{match['score']:.3f}")
    console.print(table)
    return 0


def _cmd_provenance_compare(args) -> int:
    for path in (args.model_a, args.model_b):
        if not Path(path).exists():
            _fail(f"model path not found: {path}")
            return 2
    payload = compare_models(args.model_a, args.model_b)
    if getattr(args, "format", "table") in ("json", "sarif") or getattr(args, "output", None) or getattr(args, "json_output", False):
        _emit_info(args, payload)
        return 0

    _header("provenance compare", args=args)
    console.print(f"  verdict: [bold]{payload['verdict']}[/bold]  score={payload['pipeline_score']:.3f}")
    for signal, score in payload["signals"].items():
        console.print(f"  {signal}: {score:.3f}")
    return 0


def _cmd_provenance_db_info(args) -> int:
    db = _load_db(args)
    payload = db.info()
    if getattr(args, "format", "table") in ("json", "sarif") or getattr(args, "output", None) or getattr(args, "json_output", False):
        _emit_info(args, payload)
        return 0

    _header("provenance db-info", args=args)
    console.print(f"  references: {payload['reference_count']}")
    console.print(f"  families: {', '.join(payload['families'])}")
    console.print(f"  integrity: {'ok' if payload['integrity_ok'] else 'failed'}")
    return 0


def _cmd_provenance_download(args) -> int:
    output = Path(getattr(args, "output_path", None) or Path.home() / ".cache" / "eresus-sentinel" / "provenance" / "fingerprints.json")
    db = FingerprintDatabase()
    written = db.write(output)
    payload = {
        "schema_version": "provenance.download.v1",
        "summary": {"status": "ok", "path": str(written), "reference_count": len(db.references)},
        "path": str(written),
        "reference_count": len(db.references),
        "integrity_ok": db.verify_integrity(),
    }
    if getattr(args, "format", "table") in ("json", "sarif") or getattr(args, "json_output", False):
        _emit_info(args, payload)
        return 0

    _header("provenance download-fingerprints", args=args)
    _ok(f"wrote {written}")
    return 0
