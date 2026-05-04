"""RAG / vector-store security commands."""
from __future__ import annotations

import json
from pathlib import Path

from sentinel.cli._export import _export
from sentinel.cli._helpers import _fail, _header, _ok, _warn, console, _print_findings


def cmd_rag(args) -> int:
    """Dispatcher for `sentinel rag` subcommands."""
    action = getattr(args, "rag_action", None) or "scan"
    if action == "scan":
        return _cmd_rag_scan(args)
    _header("rag — vector store security")
    console.print("  [dim]subcommands: scan[/dim]")
    return 2


def _cmd_rag_scan(args) -> int:
    from sentinel.rag.hubness import RAGHubnessScanner

    path = getattr(args, "path", None)
    if not path:
        _fail("path required")
        return 2

    k = getattr(args, "k", 10)
    hubness_threshold = getattr(args, "hubness_threshold", 3.0)
    near_dup_threshold = getattr(args, "near_dup_threshold", 0.995)

    _header(f"rag scan → {path}")

    scanner = RAGHubnessScanner(
        k=k,
        hubness_threshold=hubness_threshold,
        near_dup_threshold=near_dup_threshold,
    )

    result = scanner.scan_path(path)

    if result.error:
        _fail(result.error)
        return 2

    findings = result.findings
    fmt = getattr(args, "format", "table")

    if fmt == "table":
        console.print(f"  [dim]vectors scanned: {result.total_vectors:,}[/dim]")
        if not findings:
            _ok("no adversarial hubs detected")
        else:
            _warn(f"{len(findings)} anomalies detected")
            _print_findings(findings, args=args)
    else:
        _export(args, findings)

    return 1 if findings else 0
