"""Sentinel Wizard — interactive first-run setup and guided scan.

Detects the project type, suggests a scan profile, walks through the first
scan, and explains findings interactively using Rich prompts.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from rich.prompt import Confirm, Prompt
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text

from sentinel.cli._helpers import console, _ok, _warn, _fail


def cmd_wizard(args) -> int:
    """Entry point for `sentinel wizard`."""
    path = getattr(args, "path", None) or "."
    auto = getattr(args, "auto", False)
    return SentinelWizard(path=path, auto=auto).run()


class SentinelWizard:
    """Interactive guided wizard for new Sentinel users.

    Steps:
    1. Welcome + version check
    2. Detect project type
    3. Suggest and confirm scan profile
    4. Run scan with progress
    5. Explain top findings
    6. Suggest next steps
    """

    _PROFILES = {
        "fast": "SAST + secrets only. ~5s. No ML models.",
        "balanced": "SAST + secrets + artifact scan. ~30s. Recommended.",
        "deep": "Balanced + red-team probes. ~2min.",
        "paranoid": "Deep + fuzz testing. ~10min. CI gate.",
    }

    def __init__(self, path: str = ".", auto: bool = False) -> None:
        self._path = Path(path).resolve()
        self._auto = auto

    def run(self) -> int:
        self._welcome()
        project_type, hints = self._detect_project()
        profile = self._suggest_profile(project_type, hints)
        confirmed = self._confirm_scan(profile)
        if not confirmed:
            console.print("\n  [dim]Wizard cancelled. Run manually: sentinel scan .[/dim]")
            return 0
        findings = self._run_scan(profile)
        self._explain_findings(findings)
        self._next_steps(profile, len(findings))
        return 1 if findings else 0

    # ── Steps ────────────────────────────────────────────────────

    def _welcome(self) -> None:
        from sentinel import __version__ as ver
        console.print(Panel(
            f"[bold white]ERESUS SENTINEL[/bold white]  [dim]v{ver}[/dim]\n"
            "[dim]AI/LLM Security Platform — Interactive Setup Wizard[/dim]",
            border_style="red",
            padding=(0, 2),
        ))
        console.print(f"\n  Scanning: [cyan]{self._path}[/cyan]")

    def _detect_project(self) -> tuple[str, list[str]]:
        hints: list[str] = []
        project_type = "generic"

        indicators = {
            "python": ["*.py", "pyproject.toml", "setup.py", "requirements.txt"],
            "node": ["package.json", "*.js", "*.ts"],
            "docker": ["Dockerfile", "docker-compose.yml", "*.dockerfile"],
            "ml": ["*.pkl", "*.pt", "*.safetensors", "*.gguf", "*.h5", "*.onnx"],
            "notebook": ["*.ipynb"],
            "mcp": ["SKILL.md", "skill.json", "*.mcp.json"],
        }

        detected = []
        for ptype, patterns in indicators.items():
            for pat in patterns:
                if list(self._path.rglob(pat)):
                    detected.append(ptype)
                    break

        if "ml" in detected:
            project_type = "ml"
            hints.append("Model artifacts detected → artifact scanner will run")
        elif "mcp" in detected:
            project_type = "mcp"
            hints.append("MCP skills/manifests detected → skill-scan + MCP validation")
        elif "python" in detected:
            project_type = "python"
            hints.append("Python project → SAST + secrets + supply chain")
        elif "node" in detected:
            project_type = "node"
            hints.append("Node.js project → SAST + secrets")

        if "notebook" in detected:
            hints.append("Jupyter notebooks found → notebook scanner will run")
        if "docker" in detected:
            hints.append("Docker files found → container extraction available")

        type_display = {
            "ml": "[bold cyan]ML/Model[/bold cyan]",
            "mcp": "[bold magenta]MCP/Agent[/bold magenta]",
            "python": "[bold yellow]Python[/bold yellow]",
            "node": "[bold green]Node.js[/bold green]",
            "generic": "[dim]Generic[/dim]",
        }
        console.print(f"\n  Detected project type: {type_display.get(project_type, project_type)}")
        for h in hints:
            console.print(f"  [dim]· {h}[/dim]")

        return project_type, hints

    def _suggest_profile(self, project_type: str, hints: list[str]) -> str:
        suggestions = {
            "ml": "balanced",
            "mcp": "balanced",
            "python": "balanced",
            "node": "fast",
            "generic": "fast",
        }
        suggested = suggestions.get(project_type, "balanced")

        console.print("\n  [bold]Scan profiles:[/bold]")
        for name, desc in self._PROFILES.items():
            marker = "[green]►[/green]" if name == suggested else " "
            console.print(f"    {marker} [cyan]{name:<10}[/cyan] {desc}")

        if self._auto:
            console.print(f"\n  [dim]Auto mode: using profile '{suggested}'[/dim]")
            return suggested

        choice = Prompt.ask(
            "\n  Select profile",
            choices=list(self._PROFILES.keys()),
            default=suggested,
        )
        return choice

    def _confirm_scan(self, profile: str) -> bool:
        if self._auto:
            return True
        return Confirm.ask(f"\n  Run [cyan]{profile}[/cyan] scan on [cyan]{self._path}[/cyan]?", default=True)

    def _run_scan(self, profile: str) -> list:
        console.print(f"\n  [dim]Running {profile} scan...[/dim]")
        try:
            import argparse
            from sentinel.cli.cmd_scan import cmd_scan
            args = argparse.Namespace(
                path=str(self._path),
                format="json",
                output=None,
                min_severity=None,
                fail_on=None,
                ci=False,
                fast=(profile == "fast"),
                stdin_files=False,
                explain_plan=False,
                profile=profile,
                verbose=False,
                quiet=False,
                command="scan",
            )
            import io
            from contextlib import redirect_stdout
            buf = io.StringIO()
            with redirect_stdout(buf):
                cmd_scan(args)
            output = buf.getvalue().strip()
            if output:
                try:
                    import json
                    data = json.loads(output)
                    findings_raw = data.get("findings", [])
                    return findings_raw
                except Exception:
                    pass
            return []
        except Exception as exc:
            _warn(f"Scan encountered an error: {exc}")
            console.print(f"  [dim]Run manually: sentinel scan {self._path} -f json[/dim]")
            return []

    def _explain_findings(self, findings: list) -> None:
        if not findings:
            console.print("\n  [green]✓ No security findings detected.[/green]")
            console.print("  [dim]Your project looks clean from a quick scan perspective.[/dim]")
            return

        n = len(findings)
        console.print(f"\n  [bold]Found {n} finding{'s' if n != 1 else ''}[/bold]")

        sev_counts: dict[str, int] = {}
        for f in findings:
            sev = (f.get("severity") or "INFO").upper()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        sev_colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim"}
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            c = sev_counts.get(sev, 0)
            if c:
                console.print(f"    [{sev_colors[sev]}]{sev}: {c}[/{sev_colors[sev]}]")

        top = sorted(findings, key=lambda f: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(str(f.get("severity", "INFO")).upper(), 4))[:5]

        console.print("\n  [bold]Top findings:[/bold]")
        for i, f in enumerate(top, 1):
            sev = str(f.get("severity", "INFO")).upper()
            rule = f.get("rule_id", "")
            title = f.get("title", "")
            remediation = f.get("remediation", "")
            color = sev_colors.get(sev, "dim")
            console.print(f"\n  [{color}]{i}. [{sev}] {rule}[/{color}] — {title}")
            if remediation:
                console.print(f"     [dim]Fix: {remediation[:120]}[/dim]")

    def _next_steps(self, profile: str, finding_count: int) -> None:
        console.print("\n  [bold]Next steps:[/bold]")
        steps = []

        if finding_count > 0:
            steps.append("sentinel scan . -f html -o report.html   # full HTML report")
            steps.append("sentinel scan . -f sarif -o report.sarif  # SARIF for IDE/GitHub")
        else:
            steps.append("sentinel scan . --profile paranoid        # deeper scan")

        steps.append("sentinel firewall 'test prompt'             # test firewall")
        if profile in ("fast", "balanced"):
            steps.append("sentinel scan . --profile deep              # add red-team probes")
        steps.append("sentinel wizard --auto                      # non-interactive re-run")

        for step in steps:
            console.print(f"  [dim]→ {step}[/dim]")

        console.print("\n  [dim]Docs: https://eresus.dev/docs | sentinel help[/dim]\n")
