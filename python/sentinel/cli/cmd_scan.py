"""Scan commands — scan, firewall, artifact, hf-artifact, hf-scan, hf-guard."""

from __future__ import annotations

import sys
import time
from pathlib import Path

from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from sentinel.cli._helpers import (
    console, _header, _ok, _fail, _warn, _print_findings,
    _finding_line, _sev, _apply_severity_filter, _severity_dashboard, _SEV,
)
from sentinel.cli._export import _export


def cmd_scan(args):
    """Full scan."""
    from sentinel.cli_dispatch import (
        dispatch_artifact, dispatch_firewall_input, dispatch_firewall_output,
        dispatch_sast, dispatch_agent, dispatch_supply_chain,
        dispatch_diff, dispatch_notebook, dispatch_validate_rules,
    )

    _header(f"full scan → {args.path}")

    modules = [
        ("artifact",      "artifact scan",     dispatch_artifact),
        ("firewall.in",   "input firewall",    dispatch_firewall_input),
        ("firewall.out",  "output firewall",   dispatch_firewall_output),
        ("sast",          "static analysis",   dispatch_sast),
        ("agent",         "agent/mcp",         dispatch_agent),
        ("supply-chain",  "supply chain",      dispatch_supply_chain),
        ("diff",          "git diff",          dispatch_diff),
        ("notebook",      "notebooks",         dispatch_notebook),
        ("rules",         "yaml validation",   dispatch_validate_rules),
    ]

    results = []
    all_findings = []
    t0 = time.perf_counter()

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]{task.description}"),
        BarColumn(bar_width=20),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("scanning...", total=len(modules))

        for name, label, func in modules:
            progress.update(task, description=f"{label}...")
            t1 = time.perf_counter()
            try:
                findings = func(args.path) or []
                ok = True
            except Exception as e:
                findings = []
                ok = False
                from sentinel.cli._helpers import err
                err.print(f"  [dim red]⚠ {name}: {e}[/dim red]")

            ms = (time.perf_counter() - t1) * 1000
            fc = len(findings)
            all_findings.extend(findings)

            mark = "[green]✓[/green]" if ok and fc == 0 else "[yellow]![/yellow]" if ok else "[red]✗[/red]"
            count_str = f"[red]{fc}[/red]" if fc > 0 else "[green]0[/green]"
            console.print(f"  {mark} {label:<20} {count_str:>12} findings  [dim]{ms:>6.0f}ms[/dim]")

            results.append({"name": name, "label": label, "ms": ms, "ok": ok, "findings": fc})
            progress.advance(task)

    all_findings = _apply_severity_filter(all_findings, args)

    wall = time.perf_counter() - t0
    total_f = len(all_findings)
    passed = sum(1 for r in results if r["ok"])

    console.print(f"\n  [bold]{passed}/{len(results)}[/bold] passed · "
                  f"[bold]{total_f}[/bold] finding(s) · "
                  f"[dim]{wall:.1f}s[/dim]")

    if total_f > 0:
        _severity_dashboard(all_findings)
        console.print()
        for f in all_findings:
            _finding_line(f, compact=True)

    console.print()
    _export(args, all_findings)
    return 1 if total_f > 0 else 0


def cmd_firewall(args):
    """Firewall scan."""
    from sentinel.cli_dispatch import dispatch_firewall_input, dispatch_firewall_output

    text = sys.stdin.read() if args.input == "-" else args.input
    direction = args.direction

    _header(f"{direction} firewall · {len(text)} chars")

    t0 = time.perf_counter()
    findings = dispatch_firewall_output(text) if direction == "output" else dispatch_firewall_input(text)
    ms = (time.perf_counter() - t0) * 1000

    if not findings:
        _ok(f"pass  [dim]{ms:.0f}ms[/dim]")
    else:
        _fail(f"{len(findings)} finding(s)  [dim]{ms:.0f}ms[/dim]")
        for f in findings:
            _finding_line(f)

    console.print()
    _export(args, findings)
    return 1 if findings else 0


def cmd_artifact(args):
    from sentinel.cli_dispatch import dispatch_artifact
    path = getattr(args, 'path', None) or getattr(args, 'hf_repo', '')
    _header(f"artifact scan → {path}")
    findings = dispatch_artifact(path)
    findings = _apply_severity_filter(findings, args)
    _print_findings(findings)

    if getattr(args, 'show_skipped', False):
        p = Path(path)
        supported = {
            '.pkl', '.pickle', '.p', '.pt', '.pth', '.bin', '.ckpt',
            '.safetensors', '.gguf', '.pb', '.torchscript', '.ptc',
            '.tflite', '.ptl', '.llamafile', '.onnx', '.keras', '.h5', '.hdf5',
            '.xgb', '.ubj', '.model', '.lgb', '.joblib',
            '.npy', '.npz',
            '.nemo', '.mar', '.tar', '.tgz', '.zip',
        }
        if p.is_dir():
            skipped = [
                f for f in p.rglob('*')
                if f.is_file() and f.suffix.lower() not in supported
                and not f.name.startswith('.')
            ]
            if skipped:
                console.print(f"\n  [dim]⊘ {len(skipped)} file(s) skipped (unsupported format):[/dim]")
                for s in skipped[:20]:
                    console.print(f"    [dim]· {s.relative_to(p)}[/dim]")
                if len(skipped) > 20:
                    console.print(f"    [dim]  ... and {len(skipped) - 20} more[/dim]")

    _export(args, findings)
    return 1 if findings else 0


def cmd_hf_artifact(args):
    """Download and scan model artifacts directly from HuggingFace Hub."""
    _header(f"hf-artifact → {args.hf_repo}")

    try:
        from huggingface_hub import snapshot_download
    except ImportError:
        _fail("huggingface_hub not installed — run: pip install huggingface-hub")
        return 2

    from sentinel.cli_dispatch import dispatch_artifact

    console.print(f"  [dim]downloading {args.hf_repo}...[/dim]")

    model_exts = [
        '*.pkl', '*.pickle', '*.pt', '*.pth', '*.bin', '*.ckpt',
        '*.safetensors', '*.gguf', '*.pb', '*.tflite', '*.onnx',
        '*.keras', '*.h5', '*.hdf5', '*.xgb', '*.ubj', '*.model',
        '*.lgb', '*.joblib', '*.llamafile',
    ]

    try:
        local_dir = snapshot_download(
            repo_id=args.hf_repo,
            allow_patterns=model_exts,
            local_dir=None,
        )
        console.print(f"  [green]✓[/green] downloaded to {local_dir}")

        findings = dispatch_artifact(local_dir)
        _print_findings(findings)
        _export(args, findings)
        return 1 if findings else 0

    except Exception as e:
        _fail(f"download failed: {e}")
        return 2


def cmd_hf_scan(args):
    """Scan a HuggingFace model repository."""
    from sentinel.cli_dispatch import dispatch_huggingface
    _header(f"huggingface → {args.repo}")
    findings = dispatch_huggingface(args.repo)
    _print_findings(findings)
    _export(args, findings)
    return 1 if findings else 0


def cmd_hf_guard(args):
    """Pre-download security assessment for HuggingFace repos."""
    from sentinel.hf_guard import HFGuard

    _header(f"hf-guard → {args.repo}")
    guard = HFGuard(
        block_pickle=getattr(args, "block_pickle", False),
        require_safetensors=getattr(args, "require_safetensors", False),
    )
    assessment = guard.assess(args.repo)

    risk_colors = {"INFO": "dim", "LOW": "blue", "MEDIUM": "yellow", "HIGH": "red", "CRITICAL": "bold red"}
    color = risk_colors.get(assessment.risk_level, "white")
    console.print(f"  Risk Level: [{color}]{assessment.risk_level}[/{color}] (score: {assessment.risk_score:.2f})")
    console.print(f"  Total files: {assessment.total_files}")
    console.print(f"  Safetensors: {'✅' if assessment.has_safetensors else '❌'}")
    console.print(f"  Pickle files: {'⚠️' if assessment.has_pickle else '✅ none'}")

    if assessment.dangerous_files:
        console.print(f"\n  [yellow]⚠ {len(assessment.dangerous_files)} dangerous file(s):[/yellow]")
        for f in assessment.dangerous_files[:10]:
            console.print(f"    • {f['file']} [{f['risk']}] — {f['reason']}")

    for rec in assessment.recommendations:
        console.print(f"  → {rec}")

    if getattr(args, "deep", False):
        console.print("\n  Running deep scan...")
        findings = guard.scan(args.repo)
        _print_findings(findings)
        _export(args, findings)
        return 1 if findings else 0

    return 1 if assessment.risk_level in ("HIGH", "CRITICAL") else 0
