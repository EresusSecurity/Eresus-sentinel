"""Analysis commands — sast, secrets-scan, agent, supply-chain, diff, notebook, red-team."""

from __future__ import annotations

import time
from pathlib import Path

from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from sentinel.cli._helpers import (
    console, _header, _ok, _fail, _print_findings,
    _finding_line, _apply_severity_filter, _severity_dashboard,
)
from sentinel.cli._export import _export


def cmd_sast(args):
    from sentinel.cli_dispatch import dispatch_sast
    _header(f"sast → {args.path}")
    findings = dispatch_sast(args.path)
    _print_findings(findings)
    _export(args, findings)
    return 1 if findings else 0


def cmd_agent(args):
    from sentinel.cli_dispatch import dispatch_agent
    _header(f"agent/mcp → {args.path}")
    findings = dispatch_agent(args.path)
    _print_findings(findings)
    _export(args, findings)
    return 1 if findings else 0


def cmd_supply_chain(args):
    from sentinel.cli_dispatch import dispatch_supply_chain
    _header(f"supply chain → {args.path}")
    findings = dispatch_supply_chain(args.path)
    _print_findings(findings)
    _export(args, findings)
    return 1 if findings else 0


def cmd_diff(args):
    from sentinel.cli_dispatch import dispatch_diff
    _header(f"diff → {args.target}")
    findings = dispatch_diff(args.target)
    _print_findings(findings)
    _export(args, findings)
    return 1 if findings else 0


def cmd_notebook(args):
    from sentinel.cli_dispatch import dispatch_notebook
    _header(f"notebook → {args.path}")
    findings = dispatch_notebook(args.path)
    _print_findings(findings)
    _export(args, findings)
    return 1 if findings else 0


def cmd_redteam(args):
    from sentinel.cli_dispatch import dispatch_redteam
    _header(f"red-team → {args.target}")
    console.print("  [red]⚠ ensure you have authorization[/red]")
    findings = dispatch_redteam(args.target)
    _print_findings(findings)
    _export(args, findings)
    return 1 if findings else 0


def cmd_secrets_scan(args):
    """Enterprise secrets scanner — 120+ patterns + entropy + git history."""
    from sentinel.sast.secrets_scanner import SecretsScanner

    path = args.path
    _header(f"secrets scan → {path}")

    enable_entropy = not getattr(args, "no_entropy", False)
    scanner = SecretsScanner(enable_entropy=enable_entropy)
    console.print(f"  [dim]{scanner.pattern_count} patterns loaded · entropy={'on' if enable_entropy else 'off'}[/dim]")

    t0 = time.perf_counter()

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]{task.description}"),
        BarColumn(bar_width=20),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("scanning files...", total=None)

        findings = scanner.scan_directory(path) if Path(path).is_dir() else scanner.scan_file(path)
        progress.update(task, description="files done")

        if getattr(args, "git_history", False):
            progress.update(task, description="scanning git history...")
            max_commits = getattr(args, "max_git_commits", 500)
            git_findings = scanner.scan_git_history(path, max_commits=max_commits)
            findings.extend(git_findings)
            console.print(f"  [dim]git history: {len(git_findings)} finding(s) in ≤{max_commits} commits[/dim]")

        progress.update(task, description="scanning config files...")
        config_findings = scanner.scan_config_files(path)
        findings.extend(config_findings)

    ms = (time.perf_counter() - t0) * 1000

    if not findings:
        _ok(f"clean — no secrets detected  [dim]{ms:.0f}ms[/dim]")
    else:
        _fail(f"{len(findings)} secret(s) found  [dim]{ms:.0f}ms[/dim]")
        if len(findings) > 0:
            _severity_dashboard(findings)
        for f in findings:
            _finding_line(f)

    _export(args, findings)
    return 1 if findings else 0
