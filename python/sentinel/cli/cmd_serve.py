"""Service commands — serve, proxy, playbook, dep-scan, policy, validate."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from sentinel.cli._helpers import (
    console, _header, _ok, _fail, _warn, _print_findings,
    _finding_line, _severity_dashboard, _SEV,
)
from sentinel.cli._export import _export


def cmd_serve(args):
    use_ui = getattr(args, 'ui', False)
    policy = getattr(args, 'policy', '')
    host, port = args.host, args.port

    if use_ui:
        _header(f"dashboard → http://{host}:{port}")
        try:
            import uvicorn
            from sentinel.web.app import create_dashboard_app
            app = create_dashboard_app(policy_path=policy or None, host=host, port=port)
            console.print(f"  [dim]React SPA + hardened JSON API[/dim]")
            console.print(f"  [dim]CORS · CSP · rate-limit · input validation[/dim]")
            uvicorn.run(app, host=host, port=port)
        except ImportError as e:
            _fail(f"missing dependency: {e}")
            _fail("install: pip install 'eresus-sentinel[web]'")
            return 2
    else:
        _header(f"API server → {host}:{port}")
        from sentinel.cli_dispatch import dispatch_serve
        dispatch_serve(f"{host}:{port}", policy=policy)


def cmd_validate(args):
    from sentinel.cli_dispatch import dispatch_validate_rules
    _header("validate rules")
    dispatch_validate_rules("")
    _ok("rules valid")


def cmd_policy(args):
    action = args.action

    if action == "init":
        import yaml
        from sentinel.policy import PolicyEngine
        engine = PolicyEngine.default()
        s = engine.list_scanners()
        policy = {
            "name": "custom", "version": "1.0", "environment": "production",
            "mode": "enforce", "fail_open": False,
            "input_scanners": [{"scanner": n, "enabled": True} for n in s["input"]],
            "output_scanners": [{"scanner": n, "enabled": True} for n in s["output"]],
        }
        Path("policy.yaml").write_text(yaml.dump(policy, sort_keys=False), encoding="utf-8")
        _ok("written policy.yaml")

    elif action == "show":
        import os
        from rich.syntax import Syntax
        p = os.environ.get("SENTINEL_POLICY", "policy.yaml")
        if Path(p).exists():
            console.print(Syntax(Path(p).read_text(encoding="utf-8"), "yaml", theme="monokai"))
        else:
            _warn(f"no policy at {p} — run `sentinel policy init`")

    elif action == "validate":
        from sentinel.cli_dispatch import dispatch_validate_rules
        dispatch_validate_rules("")
        _ok("rules valid")


def cmd_proxy(args):
    """Live MCP intercepting proxy."""
    from sentinel.mcp_proxy import MCPProxy, ProxyConfig, ProxyMode

    mode_map = {
        "enforce": ProxyMode.ENFORCE,
        "audit": ProxyMode.AUDIT,
        "passthrough": ProxyMode.PASSTHROUGH,
    }
    config = ProxyConfig(mode=mode_map.get(args.mode, ProxyMode.ENFORCE))

    proxy = MCPProxy(config)
    transport = getattr(args, "transport", "http")

    _header(f"MCP proxy · mode={args.mode} · transport={transport}")
    console.print(f"  [dim]rate limit: {config.rate_limit_rps} rps · block on critical: {config.block_on_critical}[/dim]")

    if transport == "stdio":
        server_cmd = getattr(args, "server_cmd", None)
        if not server_cmd:
            _fail("--server-cmd required for stdio transport")
            return 2
        console.print(f"  [dim]server: {' '.join(server_cmd)}[/dim]")
        console.print(f"  [green]▶[/green] proxy running (Ctrl+C to stop)")
        try:
            asyncio.run(proxy.run_stdio(server_cmd))
        except KeyboardInterrupt:
            console.print(f"\n  [dim]stopped — {json.dumps(proxy.stats)}[/dim]")
    else:
        host = getattr(args, "host", "127.0.0.1")
        port = getattr(args, "port", 8080)
        upstream = getattr(args, "upstream", "http://localhost:3000")
        console.print(f"  [green]▶[/green] listening on {host}:{port} → {upstream}")
        console.print(f"  [dim]health: http://{host}:{port}/health[/dim]")
        try:
            asyncio.run(proxy.run_http(upstream, host, port))
        except KeyboardInterrupt:
            console.print(f"\n  [dim]stopped — {json.dumps(proxy.stats)}[/dim]")

    return 0


def cmd_playbook(args):
    """Attack playbook runner."""
    from sentinel.redteam.playbook_engine import PlaybookEngine, PlaybookLoader, ReportGenerator

    path = args.path
    _header(f"playbook → {path}")

    engine = PlaybookEngine()
    t0 = time.perf_counter()

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("loading playbook...", total=None)

        if Path(path).is_dir():
            progress.update(task, description="running playbook suite...")
            reports = asyncio.run(engine.run_suite(path))
        else:
            progress.update(task, description="running playbook...")
            report = asyncio.run(engine.run_file(path))
            reports = [report]

    ms = (time.perf_counter() - t0) * 1000

    for report in reports:
        grade_styles = {
            "A": "bold green", "B": "green", "C": "yellow",
            "D": "red", "F": "bold white on red",
        }
        grade_style = grade_styles.get(report.grade.value, "white")
        console.print(f"\n  [{grade_style}]Grade: {report.grade.value}[/{grade_style}] "
                      f"({report.pass_rate:.1f}%) · {report.playbook_name}")
        console.print(f"  Total: {report.total_probes} · "
                      f"[green]Pass: {report.passed}[/green] · "
                      f"[red]Fail: {report.failed}[/red] · "
                      f"Error: {report.errors} · Timeout: {report.timeouts}")

        failed = [o for o in report.outcomes if o.result.value == "fail"]
        if failed:
            console.print(f"\n  [red]Failed Probes ({len(failed)}):[/red]")
            for o in failed:
                console.print(f"    ❌ [{o.severity}] {o.probe_name} ({o.probe_type})")

        report_fmt = getattr(args, "report_format", "text")
        report_out = getattr(args, "report_output", None)

        if report_out:
            if report_fmt == "html":
                content = ReportGenerator.to_html(report)
            elif report_fmt == "sarif":
                content = json.dumps(ReportGenerator.to_sarif(report), indent=2)
            elif report_fmt == "json":
                content = ReportGenerator.to_json(report)
            else:
                content = report.summary

            with open(report_out, "w", encoding="utf-8") as f:
                f.write(content)
            _ok(f"report written: {report_out} ({report_fmt})")

    console.print(f"\n  [dim]{ms:.0f}ms[/dim]")

    return 1 if any(r.grade.value == "F" for r in reports) else 0


def cmd_dep_scan(args):
    """Live dependency vulnerability scanner."""
    from sentinel.supply_chain.live_scanner import LiveDependencyScanner

    path = args.path
    ecosystem = getattr(args, "ecosystem", "pypi")
    enable_osv = not getattr(args, "no_osv", False)
    enable_pip = not getattr(args, "no_pip_audit", False)

    _header(f"dep-scan → {path} · ecosystem={ecosystem}")

    scanner = LiveDependencyScanner(
        ecosystem=ecosystem,
        enable_osv=enable_osv,
        enable_pip_audit=enable_pip,
    )

    t0 = time.perf_counter()

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]{task.description}"),
        BarColumn(bar_width=20),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("scanning dependencies...", total=None)

        if enable_osv:
            progress.update(task, description="querying OSV.dev...")
        findings = scanner.full_audit(path)

    ms = (time.perf_counter() - t0) * 1000

    if not findings:
        _ok(f"clean — no vulnerabilities  [dim]{ms:.0f}ms[/dim]")
    else:
        _fail(f"{len(findings)} vulnerability(ies)  [dim]{ms:.0f}ms[/dim]")

        vulns = [f for f in findings if "CVE" in getattr(f, "rule_id", "") or "PIPAUDIT" in getattr(f, "rule_id", "")]
        typos = [f for f in findings if "TYPOSQUAT" in getattr(f, "rule_id", "")]
        other = [f for f in findings if f not in vulns and f not in typos]

        if vulns:
            console.print(f"\n  [bold red]CVEs ({len(vulns)}):[/bold red]")
            for f in vulns:
                _finding_line(f, compact=True)
        if typos:
            console.print(f"\n  [bold yellow]Typosquatting ({len(typos)}):[/bold yellow]")
            for f in typos:
                _finding_line(f, compact=True)
        if other:
            console.print(f"\n  [bold]Other ({len(other)}):[/bold]")
            for f in other:
                _finding_line(f, compact=True)

        _severity_dashboard(findings)

    _export(args, findings)
    return 1 if findings else 0
