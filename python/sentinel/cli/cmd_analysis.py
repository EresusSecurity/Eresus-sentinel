"""Analysis commands — sast, secrets-scan, agent, supply-chain, diff, notebook, red-team."""

from __future__ import annotations

import time
from pathlib import Path

from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from sentinel.cli._export import _export
from sentinel.cli._helpers import (
    _apply_severity_filter,
    _fail,
    _finding_line,
    _header,
    _ok,
    _print_findings,
    _severity_dashboard,
    console,
)


def cmd_sast(args):
    from sentinel.cli_dispatch import dispatch_sast
    if not Path(args.path).exists():
        _fail(f"path not found: {args.path}")
        return 2
    _header(f"sast → {args.path}", args=args)
    findings = _apply_severity_filter(dispatch_sast(args.path), args)
    _print_findings(findings, args=args)
    _export(args, findings)
    return 1 if findings else 0


def cmd_agent(args):
    from sentinel.cli_dispatch import dispatch_agent
    _header(f"agent/mcp → {args.path}", args=args)
    findings = _apply_severity_filter(dispatch_agent(args.path), args)
    _print_findings(findings, args=args)
    _export(args, findings)
    return 1 if findings else 0


def cmd_supply_chain(args):
    from sentinel.cli_dispatch import dispatch_supply_chain
    _header(f"supply chain → {args.path}", args=args)
    findings = _apply_severity_filter(dispatch_supply_chain(args.path), args)
    _print_findings(findings, args=args)
    _export(args, findings)
    return 1 if findings else 0


def cmd_diff(args):
    from sentinel.cli_dispatch import dispatch_diff
    target = getattr(args, "target", None)
    if getattr(args, "all", False):
        target = "--all"
    elif getattr(args, "unstaged", False):
        target = "--unstaged"
    elif getattr(args, "staged", False) or not target:
        target = "--staged"
    _header(f"diff → {target}", args=args)
    findings = _apply_severity_filter(dispatch_diff(target), args)
    _print_findings(findings, args=args)
    _export(args, findings)
    return 1 if findings else 0


def cmd_notebook(args):
    from sentinel.cli_dispatch import dispatch_notebook
    p = Path(args.path)
    if not p.exists():
        _fail(f"path not found: {args.path}")
        return 2
    if p.is_file() and p.suffix != ".ipynb":
        _fail(f"expected .ipynb file or directory, got: {args.path}")
        return 2
    _header(f"notebook → {args.path}", args=args)
    findings = _apply_severity_filter(dispatch_notebook(args.path), args)
    _print_findings(findings, args=args)
    _export(args, findings)
    return 1 if findings else 0


def cmd_redteam(args):
    from sentinel.cli_dispatch import dispatch_redteam
    target = getattr(args, "target", None) or getattr(args, "target_flag", None)
    if not target:
        _fail("target required — use `sentinel redteam <target>` or `sentinel redteam --target <target>`")
        return 2

    fmt = getattr(args, "format", "table")
    if fmt == "table":
        _header(f"red-team → {target}", args=args)
        console.print("  [red]⚠ ensure you have authorization[/red]")
    findings = dispatch_redteam(target)

    # --vertical: run industry-specific probes
    vertical = getattr(args, "vertical", None)
    if vertical:
        try:
            from sentinel.redteam.probes.industry_verticals import ALL_INDUSTRY_PROBES
            probes = (
                ALL_INDUSTRY_PROBES
                if vertical == "all"
                else [p for p in ALL_INDUSTRY_PROBES if p.vertical == vertical]
            )
            if probes:
                if fmt == "table":
                    console.print(f"  [dim]vertical={vertical}: running {len(probes)} probe(s)[/dim]")
                from sentinel.redteam.orchestrator import RedTeamOrchestrator
                from sentinel.redteam.probe import Probe

                orch = RedTeamOrchestrator()
                for industry_probe in probes:
                    try:
                        # Adapt IndustryProbe → Probe ABC so the orchestrator can run it
                        class _WrappedProbe(Probe):
                            probe_name = industry_probe.name
                            probe_description = industry_probe.description
                            prompts = industry_probe.get_prompts()
                            triggers: list[str] = []

                        probe_findings = orch.run_probes([_WrappedProbe()])
                        findings.extend(probe_findings)
                    except Exception as exc:  # noqa: BLE001
                        from sentinel.cli._helpers import _warn
                        _warn(f"probe {industry_probe.name} failed: {exc}")
            else:
                from sentinel.cli._helpers import _warn
                _warn(f"no probes found for vertical={vertical!r}")
        except Exception as exc:  # noqa: BLE001
            from sentinel.cli._helpers import _warn
            _warn(f"vertical probe loading failed: {exc}")

    findings = _apply_severity_filter(findings, args)
    _print_findings(findings, args=args)
    _export(args, findings)
    return 1 if findings else 0


def cmd_mcp(args):
    """Live MCP manifest/HTTP/stdio scanner."""
    import json
    import sys

    from rich import box
    from rich.table import Table

    from sentinel.agent.mcp.live_scanner import MCPLiveScanner

    if getattr(args, "mcp_action", None) != "scan":
        _fail("mcp action required — use `sentinel mcp scan ...`")
        return 2

    scanner = MCPLiveScanner(timeout=getattr(args, "timeout", 5.0))
    target = getattr(args, "target", None)
    manifest = getattr(args, "manifest", None)
    url = getattr(args, "url", None)
    stdio_command = getattr(args, "stdio_command", None)
    if stdio_command and stdio_command[0] == "--":
        stdio_command = stdio_command[1:]
    header_label = ""

    if manifest or (target and not str(target).startswith(("http://", "https://"))):
        source = manifest or target
        header_label = f"mcp scan → {source}"
        result = scanner.scan_manifest(source)
    elif url or (target and str(target).startswith(("http://", "https://"))):
        source = url or target
        header_label = f"mcp scan → {source}"
        result = scanner.scan_http(source)
    elif stdio_command:
        header_label = "mcp scan → stdio"
        result = scanner.scan_stdio(stdio_command)
    else:
        _fail("target required — pass a manifest path, --url, or --stdio-command")
        return 2

    findings = _apply_severity_filter(result.findings, args)
    if args.format == "json":
        payload = json.dumps(result.to_dict(), indent=2)
        if args.output:
            Path(args.output).write_text(payload + "\n", encoding="utf-8")
            _ok(f"wrote MCP scan report → {args.output}")
        else:
            sys.stdout.write(payload + "\n")
            sys.stdout.flush()
        return 1 if findings else 0

    if args.format == "markdown":
        markdown = _format_mcp_markdown(result)
        if args.output:
            Path(args.output).write_text(markdown, encoding="utf-8")
            _ok(f"wrote MCP scan report → {args.output}")
        else:
            sys.stdout.write(markdown)
            if not markdown.endswith("\n"):
                sys.stdout.write("\n")
            sys.stdout.flush()
        return 1 if findings else 0

    _header(header_label, args=args)
    summary = Table(box=box.SIMPLE, border_style="dim", show_header=False, pad_edge=False)
    summary.add_column("Metric", style="cyan")
    summary.add_column("Value")
    summary.add_row("Transport", result.transport)
    summary.add_row("Tools", str(len(result.tools)))
    summary.add_row("Prompts", str(len(result.prompts)))
    summary.add_row("Resources", str(len(result.resources)))
    summary.add_row("Readiness", f"{result.readiness_score:.0f}% ({result.readiness_grade})")
    summary.add_row("Errors", str(len(result.errors)))
    console.print(summary)

    if findings:
        _severity_dashboard(findings)
        _print_findings(findings, args=args)
    else:
        _ok("clean — no MCP findings")

    _export(args, findings)
    return 1 if findings else 0


def cmd_a2a(args):
    """A2A agent-card/source scanner."""
    from sentinel.agent.a2a_scanner import A2AScanner

    target = getattr(args, "path", None) or getattr(args, "target", None)
    if not target:
        _fail("path required — use `sentinel a2a scan <path>`")
        return 2

    scanner = A2AScanner()
    result = scanner.scan(target)
    findings = _apply_severity_filter(result.findings, args)

    _header(f"a2a scan → {target}", args=args)
    console.print(f"  [dim]scanned_files={result.scanned_files} findings={len(findings)}[/dim]")
    if findings:
        _severity_dashboard(findings)
        _print_findings(findings, args=args)
    else:
        _ok("clean — no A2A findings")

    _export(args, findings)
    return 1 if findings else 0


def _format_mcp_markdown(result) -> str:
    lines = [
        f"# MCP Scan Report: {result.source}",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Transport | {result.transport} |",
        f"| Tools | {len(result.tools)} |",
        f"| Prompts | {len(result.prompts)} |",
        f"| Resources | {len(result.resources)} |",
        f"| Readiness | {result.readiness_score:.0f}% ({result.readiness_grade}) |",
        f"| Findings | {len(result.findings)} |",
        f"| Errors | {len(result.errors)} |",
        "",
        "| Severity | Rule | Title |",
        "| --- | --- | --- |",
    ]
    for finding in result.findings:
        lines.append(f"| {finding.severity.value} | {finding.rule_id} | {finding.title} |")
    return "\n".join(lines) + "\n"


def cmd_secrets_scan(args):
    """Enterprise secrets scanner — 120+ patterns + entropy + git history."""
    from sentinel.sast.secrets_scanner import SecretsScanner

    path = args.path
    fmt = getattr(args, "format", "table")
    _header(f"secrets scan → {path}", args=args)

    enable_entropy = not getattr(args, "no_entropy", False)
    scanner = SecretsScanner(enable_entropy=enable_entropy)
    if fmt == "table":
        console.print(f"  [dim]{scanner.pattern_count} patterns loaded · entropy={'on' if enable_entropy else 'off'}[/dim]")

    t0 = time.perf_counter()

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]{task.description}"),
        BarColumn(bar_width=20),
        TimeElapsedColumn(),
        console=console,
        transient=True,
        disable=(fmt != "table"),
    ) as progress:
        task = progress.add_task("scanning files...", total=None)

        findings = scanner.scan_directory(path) if Path(path).is_dir() else scanner.scan_file(path)
        progress.update(task, description="files done")

        if getattr(args, "git_history", False):
            progress.update(task, description="scanning git history...")
            max_commits = getattr(args, "max_git_commits", 500)
            git_findings = scanner.scan_git_history(path, max_commits=max_commits)
            findings.extend(git_findings)
            if fmt == "table":
                console.print(f"  [dim]git history: {len(git_findings)} finding(s) in ≤{max_commits} commits[/dim]")

        progress.update(task, description="scanning config files...")
        config_findings = scanner.scan_config_files(path)
        findings.extend(config_findings)

    ms = (time.perf_counter() - t0) * 1000

    findings = _apply_severity_filter(findings, args)

    if fmt == "table":
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


# ── Pre-commit hooks ───────────────────────────────────────────────────────────

_SKILL_EXTS = frozenset({".md", ".yaml", ".yml", ".py"})
_MCP_NAMES = ("mcp", "tools.json", "tools.yaml", "tools.yml")
_FAIL_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _hook_threshold(findings, fail_on: str) -> bool:
    from sentinel.cli._helpers import _sev
    level = _FAIL_ORDER.get(fail_on.upper(), 4)
    return any(_FAIL_ORDER.get(_sev(f)[0], 0) >= level for f in findings)


def _fail_empty_hook(args, command: str, file_kind: str) -> int:
    """Fail closed for direct hook invocation without matched files."""
    if getattr(args, "allow_empty", False):
        _export(args, [])
        return 0

    from sentinel.cli._helpers import err

    err.print(
        f"  [red]error:[/red] {command} requires at least one matching {file_kind}; "
        "use --allow-empty for pre-commit no-match runs"
    )
    return 2


def cmd_skill_scan(args):
    """Pre-commit hook — audit SKILL.md and plugin manifests.

    Accepts multiple positional FILE arguments (pre-commit pass_filenames).
    """
    from pathlib import Path

    from sentinel.cli_dispatch import dispatch_agent

    files = [Path(f) for f in args.files if Path(f).suffix.lower() in _SKILL_EXTS]
    if not files:
        return _fail_empty_hook(args, "skill-scan", "skill/plugin file")

    fail_on: str = getattr(args, "fail_on", "critical") or "critical"
    all_findings = []
    fmt = getattr(args, "format", "table")

    for f in files:
        try:
            found = dispatch_agent(str(f))
            all_findings.extend(found)
            if fmt == "table":
                if found:
                    _fail(f"{f.name}  →  {len(found)} finding(s)")
                    for finding in found:
                        _finding_line(finding)
                else:
                    _ok(f"{f.name}  →  clean")
        except Exception as exc:  # noqa: BLE001
            from sentinel.cli._helpers import _warn
            if fmt == "table":
                _warn(f"{f.name}  →  scan error: {exc}")

    all_findings = _apply_severity_filter(all_findings, args)
    _export(args, all_findings)

    if fmt != "table":
        return 1 if all_findings else 0

    if not all_findings:
        return 0

    if _hook_threshold(all_findings, fail_on):
        console.print(
            f"\n  [bold red]sentinel:[/bold red] {len(all_findings)} finding(s) "
            f"at or above [bold]{fail_on.upper()}[/bold] — commit blocked.",
            highlight=False,
        )
        return 1
    return 0


def cmd_mcp_validate(args):
    """Pre-commit hook — validate MCP tool manifests.

    Accepts multiple positional FILE arguments (pre-commit pass_filenames).
    """
    from pathlib import Path

    from sentinel.cli_dispatch import dispatch_agent

    files = [
        Path(f) for f in args.files
        if Path(f).is_file() and any(pat in Path(f).name.lower() for pat in _MCP_NAMES)
    ]
    if not files:
        return _fail_empty_hook(args, "mcp-validate", "MCP manifest")

    fail_on: str = getattr(args, "fail_on", "high") or "high"
    all_findings = []
    fmt = getattr(args, "format", "table")

    for f in files:
        try:
            found = dispatch_agent(str(f))
            all_findings.extend(found)
            if fmt == "table":
                if found:
                    _fail(f"{f.name}  →  {len(found)} finding(s)")
                    for finding in found:
                        _finding_line(finding)
                else:
                    _ok(f"{f.name}  →  clean")
        except Exception as exc:  # noqa: BLE001
            from sentinel.cli._helpers import _warn
            if fmt == "table":
                _warn(f"{f.name}  →  scan error: {exc}")

    all_findings = _apply_severity_filter(all_findings, args)
    _export(args, all_findings)

    if fmt != "table":
        return 1 if all_findings else 0

    if not all_findings:
        return 0

    if _hook_threshold(all_findings, fail_on):
        console.print(
            f"\n  [bold red]sentinel:[/bold red] {len(all_findings)} finding(s) "
            f"at or above [bold]{fail_on.upper()}[/bold] — commit blocked.",
            highlight=False,
        )
        return 1
    return 0


def cmd_multi_agent_scan(args):
    """Static multi-agent security analysis from manifest files."""
    import json
    from pathlib import Path

    manifests: list[dict] = []
    for raw in getattr(args, "agents", []):
        p = Path(raw)
        if p.is_file():
            try:
                if p.suffix.lower() in (".yaml", ".yml"):
                    import yaml
                    manifests.append(yaml.safe_load(p.read_text(encoding="utf-8")) or {})
                else:
                    manifests.append(json.loads(p.read_text(encoding="utf-8")))
            except Exception as exc:
                from sentinel.cli._helpers import _warn
                _warn(f"could not parse {p}: {exc}")
        else:
            try:
                manifests.append(json.loads(raw))
            except Exception:
                pass

    if len(manifests) < 2:
        _fail("multi-agent scan requires at least 2 agent manifests")
        return 2

    from sentinel.cli_dispatch import dispatch_multi_agent

    scenarios = getattr(args, "scenarios", None)
    findings = dispatch_multi_agent(manifests, scenarios=scenarios)
    findings = _apply_severity_filter(findings, args)

    _header(f"multi-agent scan · {len(manifests)} agents", args=args)
    if findings:
        _severity_dashboard(findings)
        _print_findings(findings, args=args)
    else:
        from sentinel.cli._helpers import _ok
        _ok("clean — no multi-agent security findings")

    _export(args, findings)
    return 1 if findings else 0


def cmd_mcp_fingerprint(args):
    """Enumerate and fingerprint MCP server capabilities."""
    import json
    import sys

    from sentinel.agent.mcp.live_scanner import MCPLiveScanner

    target = getattr(args, "target", None) or getattr(args, "url", None)
    if not target:
        _fail("target required — pass a URL or --url <endpoint>")
        return 2

    scanner = MCPLiveScanner(timeout=getattr(args, "timeout", 5.0))
    _header(f"mcp fingerprint → {target}", args=args)

    try:
        if str(target).startswith(("http://", "https://")):
            result = scanner.scan_http(target)
        else:
            result = scanner.scan_manifest(target)
    except Exception as exc:
        _fail(f"fingerprint failed: {exc}")
        return 2

    findings = _apply_severity_filter(result.findings, args)
    fp = {
        "source": result.source,
        "transport": result.transport,
        "readiness_score": result.readiness_score,
        "readiness_grade": result.readiness_grade,
        "tools": [
            {"name": getattr(t, "name", str(t)), "description": getattr(t, "description", "")}
            for t in result.tools
        ],
        "prompts": [getattr(p, "name", str(p)) for p in result.prompts],
        "resources": [getattr(r, "uri", str(r)) for r in result.resources],
        "finding_count": len(findings),
    }

    fmt = getattr(args, "format", "table")
    if fmt == "json":
        payload = json.dumps(fp, indent=2)
        out = getattr(args, "output", None)
        if out:
            from pathlib import Path
            Path(out).write_text(payload + "\n", encoding="utf-8")
            from sentinel.cli._helpers import _ok
            _ok(f"wrote fingerprint → {out}")
        else:
            sys.stdout.write(payload + "\n")
            sys.stdout.flush()
        return 1 if findings else 0
    else:
        from rich import box as _box
        from rich.table import Table

        t = Table(box=_box.SIMPLE, border_style="dim", show_header=True, pad_edge=False)
        t.add_column("Field", style="cyan")
        t.add_column("Value")
        t.add_row("Transport", fp["transport"])
        t.add_row("Readiness", f"{fp['readiness_score']:.0f}% ({fp['readiness_grade']})")
        t.add_row("Tools", str(len(fp["tools"])))
        t.add_row("Prompts", str(len(fp["prompts"])))
        t.add_row("Resources", str(len(fp["resources"])))
        console.print(t)

        if fp["tools"]:
            console.print("\n  [bold]Tools:[/bold]")
            for tool in fp["tools"][:20]:
                console.print(f"    • [cyan]{tool['name']}[/cyan]  {tool['description'][:80]}")

    if findings:
        _severity_dashboard(findings)
        _print_findings(findings, args=args)

    _export(args, findings)
    return 1 if findings else 0
