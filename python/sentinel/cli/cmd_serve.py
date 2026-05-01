"""Service commands — serve, proxy, playbook, dep-scan, policy, validate."""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path

from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from sentinel.cli._export import _export
from sentinel.cli._helpers import (
    _fail,
    _finding_line,
    _header,
    _ok,
    _severity_dashboard,
    _warn,
    console,
)


def cmd_serve(args):
    use_ui = getattr(args, 'ui', False)
    policy = getattr(args, 'policy', '')
    host, port = args.host, args.port

    if use_ui:
        public_bind_hosts = {"0.0.0.0", "::"}  # noqa: S104 - display URL for public binds
        display_host = "127.0.0.1" if host in public_bind_hosts else host
        dashboard_url = f"http://{display_host}:{port}"
        _header(f"dashboard → {dashboard_url}")
        if host != display_host:
            console.print(f"  [dim]listening on {host}:{port}[/dim]")
        if not os.environ.get("SENTINEL_PASSWORD"):
            _warn("SENTINEL_PASSWORD is not set; dashboard login will not be available")
        try:
            import uvicorn

            from sentinel.web.app import _DIST_DIR, create_dashboard_app
            app = create_dashboard_app(policy_path=policy or None, host=host, port=port)
            console.print("  [dim]React SPA + hardened JSON API[/dim]")
            console.print("  [dim]CORS · CSP · rate-limit · input validation[/dim]")
            console.print(f"  [dim]API docs: {dashboard_url}/api/docs[/dim]")
            if not (_DIST_DIR.is_dir() and (_DIST_DIR / "index.html").is_file()):
                _warn("React SPA is not built; browser will show a build-missing page")
                console.print("  [dim]build: cd frontend && npm install && npm run build[/dim]")
            if getattr(args, "open_browser", False):
                import webbrowser
                webbrowser.open(dashboard_url)
            uvicorn.run(app, host=host, port=port, server_header=False)
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
        if server_cmd and server_cmd[0] == "--":
            server_cmd = server_cmd[1:]
        if not server_cmd:
            _fail("--server-cmd required for stdio transport")
            return 2
        console.print(f"  [dim]server: {' '.join(server_cmd)}[/dim]")
        console.print("  [green]▶[/green] proxy running (Ctrl+C to stop)")
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
    from sentinel.redteam.playbook_engine import PlaybookEngine, ReportGenerator

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

    all_failed = []

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
        all_failed.extend(failed)
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

    if getattr(args, "fail_on_failed_probes", False) and all_failed:
        _fail(f"playbook failed: {len(all_failed)} failed probe(s)")
        return 1

    critical_failed = [o for o in all_failed if str(o.severity).upper() == "CRITICAL"]
    if getattr(args, "fail_on_critical", False) and critical_failed:
        _fail(f"playbook failed: {len(critical_failed)} failed CRITICAL probe(s)")
        return 1

    fail_on_grade = getattr(args, "fail_on_grade", None)
    if fail_on_grade:
        grade_order = {"A": 5, "B": 4, "C": 3, "D": 2, "F": 1}
        failing_reports = [
            r for r in reports
            if grade_order.get(r.grade.value, 0) <= grade_order[fail_on_grade]
        ]
        if failing_reports:
            grades = ", ".join(f"{r.playbook_name}={r.grade.value}" for r in failing_reports)
            _fail(f"playbook grade threshold failed (--fail-on-grade {fail_on_grade}): {grades}")
            return 1

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
