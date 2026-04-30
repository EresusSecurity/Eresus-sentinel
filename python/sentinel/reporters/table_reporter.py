"""Rich terminal table reporter for Sentinel findings.

Falls back gracefully to plain-text ASCII table when the ``rich`` library
is not installed.
"""
from __future__ import annotations

from typing import Any

from sentinel.reporters.base import BaseReporter

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_SEVERITY_STYLES = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "green",
    "info": "blue",
}


def _sev(f) -> str:
    return str(getattr(getattr(f, "severity", None), "value", getattr(f, "severity", "info"))).lower()


class TableReporter(BaseReporter):
    """Generate a terminal-friendly table report.

    Uses ``rich`` for colored output when available; falls back to plain ASCII.
    """

    def generate(self, findings: list, metadata: dict[str, Any] | None = None) -> str:
        try:
            return self._rich_table(findings, metadata or {})
        except ImportError:
            return self._ascii_table(findings, metadata or {})

    def _rich_table(self, findings: list, meta: dict) -> str:
        from io import StringIO

        from rich.console import Console
        from rich.table import Table

        buf = StringIO()
        console = Console(file=buf, force_terminal=False, width=120)

        table = Table(
            title="Eresus Sentinel — Findings",
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
        )
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Rule ID", style="dim cyan", width=16)
        table.add_column("Title", width=36)
        table.add_column("Target", width=28)
        table.add_column("Description", width=40)

        sorted_findings = sorted(
            findings,
            key=lambda x: _SEVERITY_ORDER.index(_sev(x)) if _sev(x) in _SEVERITY_ORDER else 99,
        )

        for f in sorted_findings:
            sev = _sev(f)
            style = _SEVERITY_STYLES.get(sev, "")
            rule_id = str(getattr(f, "rule_id", ""))
            title = str(getattr(f, "title", ""))
            target = str(getattr(f, "target", ""))[:40]
            desc = str(getattr(f, "description", ""))[:80]
            table.add_row(
                f"[{style}]{sev.upper()}[/{style}]",
                rule_id, title, target, desc,
            )

        console.print(table)
        scan_path = str(meta.get("scan_path", "."))
        total = len(findings)
        console.print(f"\n[dim]Scan path: {scan_path} | Total findings: {total}[/dim]")
        return buf.getvalue()

    @staticmethod
    def _ascii_table(findings: list, meta: dict) -> str:
        headers = ["SEVERITY", "RULE ID", "TITLE", "TARGET", "DESCRIPTION"]
        col_widths = [10, 16, 36, 28, 40]

        def trunc(s: str, n: int) -> str:
            return s[:n - 1] + "…" if len(s) > n else s.ljust(n)

        sep = "+" + "+".join("-" * (w + 2) for w in col_widths) + "+"
        header_row = (
            "| "
            + " | ".join(h.ljust(w) for h, w in zip(headers, col_widths))
            + " |"
        )
        lines = [sep, header_row, sep]

        sorted_findings = sorted(
            findings,
            key=lambda x: _SEVERITY_ORDER.index(_sev(x)) if _sev(x) in _SEVERITY_ORDER else 99,
        )
        for f in sorted_findings:
            sev = _sev(f).upper()
            rule_id = str(getattr(f, "rule_id", ""))
            title = str(getattr(f, "title", ""))
            target = str(getattr(f, "target", ""))
            desc = str(getattr(f, "description", ""))
            row = (
                "| "
                + " | ".join(
                    trunc(v, w)
                    for v, w in zip([sev, rule_id, title, target, desc], col_widths)
                )
                + " |"
            )
            lines.append(row)

        lines.append(sep)
        lines.append(f"\nScan path: {meta.get('scan_path', '.')} | Total: {len(findings)}")
        return "\n".join(lines)
