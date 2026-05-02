"""Shared CLI helpers — console, severity, printing utilities."""

from __future__ import annotations

import sys

from rich.console import Console

console = Console(highlight=False)
err = Console(stderr=True, highlight=False)
_machine_stdout = sys.stdout


def set_machine_stdout(stream) -> None:
    """Remember original stdout for structured payload writers."""
    global _machine_stdout
    _machine_stdout = stream


def machine_stdout():
    """Return stdout reserved for machine-readable output."""
    return _machine_stdout

# ── Severity ──────────────────────────────────────────────────────

_SEV = {
    "CRITICAL": ("🔴", "bold white on red"),
    "HIGH":     ("🟠", "bold red"),
    "MEDIUM":   ("🟡", "yellow"),
    "LOW":      ("🔵", "cyan"),
    "INFO":     ("⚪", "dim"),
}


def _sev(finding) -> tuple[str, str, str]:
    """Return (sev_str, emoji, style) for a finding."""
    s = getattr(finding, "severity", None)
    v = (s.value if hasattr(s, "value") else str(s) if s else "info").upper()
    emoji, style = _SEV.get(v, ("⚪", "dim"))
    return v, emoji, style


# ── Print helpers ─────────────────────────────────────────────────

def _header(text: str, args=None):
    if args is not None and getattr(args, "format", "table") != "table":
        return
    console.print(f"\n[red]●[/red] [bold]sentinel[/bold] [dim]·[/dim] {text}")


def _ok(text: str):
    console.print(f"  [green]✓[/green] {text}")


def _warn(text: str):
    console.print(f"  [yellow]![/yellow] {text}")


def _fail(text: str):
    console.print(f"  [red]✗[/red] {text}")


def _finding_line(f, compact: bool = False):
    """Print a single finding as one or two lines."""
    v, emoji, style = _sev(f)
    rid = getattr(f, "rule_id", "")
    title = getattr(f, "title", "")
    desc = getattr(f, "description", "")
    evidence = getattr(f, "evidence", "")
    fix = getattr(f, "remediation", getattr(f, "fix_hint", ""))

    console.print(f"  {emoji} [{style}]{v:<8}[/{style}] [bold]{rid}[/bold]  {title}")
    if not compact:
        if desc:
            console.print(f"             [dim]{desc[:160]}[/dim]")
        if evidence:
            console.print(f"             [yellow]evidence:[/yellow] {evidence[:120]}")
        if fix:
            console.print(f"             [green]fix:[/green] {fix[:120]}")


def _print_findings(findings, label: str = "", args=None):
    """Print findings as rich UI table. Skipped when format != table (use _export instead)."""
    if args is not None and getattr(args, "format", "table") != "table":
        return
    if not findings:
        _ok(f"clean{f' — {label}' if label else ''}")
        return
    _fail(f"{len(findings)} finding(s){f' — {label}' if label else ''}")
    for f in findings:
        _finding_line(f)


def _apply_severity_filter(findings, args):
    """Filter findings by minimum severity if --min-severity is set."""
    min_sev = getattr(args, "min_severity", None)
    if not min_sev:
        return findings
    order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    threshold = order.get(min_sev.upper(), 0)
    return [f for f in findings if order.get(_sev(f)[0], 0) >= threshold]


def _severity_dashboard(findings):
    """Print a severity histogram dashboard."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        v, _, _ = _sev(f)
        counts[v] = counts.get(v, 0) + 1

    max_count = max(counts.values()) if counts.values() else 1
    bar_width = 30

    console.print("\n  [bold]Severity Distribution[/bold]")
    sev_styles = {
        "CRITICAL": "bold white on red",
        "HIGH": "bold red",
        "MEDIUM": "yellow",
        "LOW": "cyan",
        "INFO": "dim",
    }
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        c = counts[sev]
        if c == 0:
            continue
        bar_len = max(1, int((c / max_count) * bar_width)) if max_count > 0 else 0
        bar = "█" * bar_len
        style = sev_styles.get(sev, "dim")
        console.print(f"    [{style}]{sev:<9}[/{style}] [{style}]{bar}[/{style}] {c}")
