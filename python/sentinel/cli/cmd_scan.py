"""Scan commands — scan, firewall, artifact, hf-artifact, hf-scan, hf-guard."""

from __future__ import annotations

import sys
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
    _sev,
    _severity_dashboard,
    _warn,
    console,
)


def _fails_threshold(findings, fail_on: str | None) -> bool:
    """Return true when a finding meets the configured CI failure threshold."""
    order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    if not fail_on:
        return any(order.get(_sev(f)[0], 0) >= order["MEDIUM"] for f in findings)

    threshold = order.get(fail_on.upper(), 3)
    return any(order.get(_sev(f)[0], 0) >= threshold for f in findings)


_SCAN_MAX_FILES = 10_000
_DANGEROUS_ROOTS = frozenset({"/", "/usr", "/System", "/Applications", "/Library", "/var", "/etc", "/opt", "C:\\", "C:\\Windows"})


def cmd_scan(args):
    """Full scan."""
    import os
    if not args.path or not args.path.strip():
        from sentinel.cli._helpers import err
        err.print("  [red]error:[/red] path argument cannot be empty")
        return 2
    if not os.path.exists(args.path):
        from sentinel.cli._helpers import err
        err.print(f"  [red]error:[/red] target not found: {args.path}")
        return 2

    resolved = os.path.realpath(args.path)
    if resolved in _DANGEROUS_ROOTS:
        _fail(f"refusing to scan system root '{resolved}' — specify a project directory")
        return 2

    if os.path.isdir(resolved):
        file_count = sum(1 for _ in Path(resolved).rglob("*") if _.is_file())
        if file_count > _SCAN_MAX_FILES:
            _warn(f"directory has {file_count:,} files (limit {_SCAN_MAX_FILES:,}). Narrow scope or increase limit.")
            return 2

    from sentinel.cli_dispatch import (
        dispatch_agent,
        dispatch_artifact,
        dispatch_diff,
        dispatch_firewall_input,
        dispatch_firewall_output,
        dispatch_notebook,
        dispatch_sast,
        dispatch_supply_chain,
        dispatch_validate_rules,
    )

    def dispatch_secrets(target: str):
        from sentinel.sast.secrets_scanner import SecretsScanner
        scanner = SecretsScanner()
        target_path = Path(target)
        findings = scanner.scan_directory(target) if target_path.is_dir() else scanner.scan_file(target)
        if target_path.is_dir():
            findings.extend(scanner.scan_config_files(target))
        return findings

    fast = getattr(args, "fast", False)
    _header(f"{'fast' if fast else 'full'} scan → {args.path}", args=args)

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

    # --fast for file/path scans is code-oriented: avoid treating docs as giant prompts.
    if fast:
        modules = [
            ("sast", "static analysis", dispatch_sast),
            ("secrets", "secrets", dispatch_secrets),
        ]

    # --stdin-files: read additional paths from stdin
    if getattr(args, "stdin_files", False):
        import sys as _sys
        extra_paths = [p.strip() for p in _sys.stdin.read().splitlines() if p.strip()]
        if extra_paths:
            # Prepend an extra sast pass over stdin-provided paths
            extra_paths[0] if len(extra_paths) == 1 else args.path

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
                from sentinel.finding import Finding, Severity
                findings = [Finding(
                    rule_id="SCAN-ERROR",
                    module=name,
                    title=f"{label} failed",
                    description=str(e),
                    severity=Severity.HIGH,
                    confidence=1.0,
                    target=args.path,
                    evidence=str(e),
                )]
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
    has_scan_error = any(not r["ok"] for r in results)
    return 1 if has_scan_error or _fails_threshold(all_findings, getattr(args, "fail_on", None)) else 0


MAX_FIREWALL_INPUT = 100_000


def cmd_firewall(args):
    """Firewall scan."""
    from sentinel.cli_dispatch import dispatch_firewall_input, dispatch_firewall_output

    text = sys.stdin.read() if args.input == "-" else args.input
    direction = args.direction
    fmt = getattr(args, "format", "table")

    if len(text) > MAX_FIREWALL_INPUT:
        _warn(f"input truncated from {len(text):,} to {MAX_FIREWALL_INPUT:,} chars (DoS protection)")
        text = text[:MAX_FIREWALL_INPUT]

    t0 = time.perf_counter()
    findings = dispatch_firewall_output(text) if direction == "output" else dispatch_firewall_input(text)
    ms = (time.perf_counter() - t0) * 1000

    findings = _apply_severity_filter(findings, args)

    if fmt == "table":
        _header(f"{direction} firewall · {len(text)} chars", args=args)
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
    fmt = getattr(args, "format", "table")

    if not Path(path).exists():
        _fail(f"path not found: {path}")
        return 2

    if fmt == "table":
        _header(f"artifact scan → {path}", args=args)
    findings = dispatch_artifact(path)
    findings = _apply_severity_filter(findings, args)

    if fmt == "table":
        _print_findings(findings, args=args)

    if fmt == "table" and getattr(args, 'show_skipped', False):
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
    return 1 if _fails_threshold(findings, getattr(args, "fail_on", None)) else 0


def cmd_hf_artifact(args):
    """Download and scan model artifacts directly from HuggingFace Hub."""
    _header(f"hf-artifact → {args.hf_repo}", args=args)

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
        _print_findings(findings, args=args)
        _export(args, findings)
        return 1 if findings else 0

    except Exception as e:
        _fail(f"download failed: {e}")
        return 2


def cmd_hf_scan(args):
    """Scan a HuggingFace model repository."""
    from sentinel.cli_dispatch import dispatch_huggingface
    _header(f"huggingface → {args.repo}", args=args)
    findings = dispatch_huggingface(args.repo)
    _print_findings(findings, args=args)
    _export(args, findings)
    return 1 if findings else 0


def cmd_hf_guard(args):
    """Pre-download security assessment for HuggingFace repos."""
    from sentinel.hf_guard import HFGuard

    _header(f"hf-guard → {args.repo}", args=args)
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
        _print_findings(findings, args=args)
        _export(args, findings)
        return 1 if findings else 0

    return 1 if assessment.risk_level in ("HIGH", "CRITICAL") else 0


# ── Pre-commit hooks ───────────────────────────────────────────────────────────
#
# These commands are designed for `pass_filenames: true` pre-commit hooks.
# They accept multiple positional file paths and exit non-zero only when
# findings at or above `--fail-on` severity are detected.

_FAIL_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _hook_threshold(findings, fail_on: str) -> bool:
    level = _FAIL_ORDER.get(fail_on.upper(), 4)
    return any(_FAIL_ORDER.get(_sev(f)[0], 0) >= level for f in findings)


def cmd_artifact_scan(args):
    """Pre-commit artifact scanner — scans each staged file individually.

    Accepts multiple positional FILE arguments (pre-commit pass_filenames).
    Exits 1 if any finding is at or above ``--fail-on`` severity (default: critical).
    """
    from sentinel.cli_dispatch import dispatch_artifact

    files: list[Path] = []
    for raw in args.files:
        p = Path(raw)
        if p.is_file():
            files.append(p)
        elif p.is_dir():
            files.extend(f for f in p.rglob("*") if f.is_file())

    if not files:
        return 0

    all_findings = []
    fail_on: str = getattr(args, "fail_on", "critical") or "critical"

    for f in files:
        try:
            found = dispatch_artifact(str(f))
            if found:
                all_findings.extend(found)
                _fail(f"{f.name}  →  {len(found)} finding(s)")
                for finding in found:
                    _finding_line(finding)
            else:
                _ok(f"{f.name}  →  clean")
        except Exception as exc:  # noqa: BLE001
            from sentinel.cli._helpers import _warn
            _warn(f"{f.name}  →  scan error: {exc}")

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


def cmd_hf_bulk_scan(args):
    """Bulk scan HuggingFace Hub repositories."""
    from sentinel.hf_bulk_scanner import HFBulkScanner

    tags_raw = getattr(args, "tags", None) or []
    tags = [t.strip() for t in tags_raw if t.strip()] if tags_raw else None

    scanner = HFBulkScanner(concurrency=getattr(args, "concurrency", 4))
    try:
        results = scanner.scan_bulk(
            owner=getattr(args, "owner", None),
            task=getattr(args, "task", None),
            tags=tags,
            limit=getattr(args, "limit", 1000),
            min_downloads=getattr(args, "min_downloads", 0),
            mode=getattr(args, "mode", "guard"),
            output_path=getattr(args, "output", None),
            resume=getattr(args, "resume", False),
        )
    except Exception as exc:
        _fail(str(exc))
        return 1

    # Summary table
    by_risk: dict[str, int] = {}
    total_findings = 0
    for r in results:
        by_risk[r.risk_level] = by_risk.get(r.risk_level, 0) + 1
        total_findings += r.finding_count

    console.print(f"\n  Scanned [bold]{len(results)}[/bold] repos · [bold]{total_findings}[/bold] finding(s)")
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "ERROR"):
        count = by_risk.get(level, 0)
        if count:
            colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow",
                      "LOW": "blue", "INFO": "dim", "ERROR": "red"}
            c = colors.get(level, "white")
            console.print(f"  [{c}]{level:>8}[/{c}]  {count}")

    has_high = (by_risk.get("CRITICAL", 0) + by_risk.get("HIGH", 0)) > 0
    has_errors = by_risk.get("ERROR", 0) > 0
    return 1 if has_high or has_errors else 0
