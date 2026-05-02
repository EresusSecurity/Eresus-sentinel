"""Fuzz commands — generate, mutate, validate, selftest, payloads."""

from __future__ import annotations

import time
from pathlib import Path

from rich import box
from rich.table import Table

from sentinel.cli._helpers import _fail, _header, _ok, _warn, console


def cmd_fuzz(args):
    """Fuzzer command dispatcher."""
    action = getattr(args, "fuzz_action", None)

    if action == "generate":
        return _cmd_fuzz_generate(args)
    elif action == "mutate":
        return _cmd_fuzz_mutate(args)
    elif action == "validate":
        return _cmd_fuzz_validate(args)
    elif action == "selftest":
        return _cmd_fuzz_selftest(args)
    elif action == "payloads":
        return _cmd_fuzz_payloads(args)
    elif action == "minimize":
        return _cmd_fuzz_minimize(args)
    else:
        _header("fuzz — AI offensive security testing")
        console.print("  [dim]subcommands: generate, mutate, validate, selftest, payloads, minimize[/dim]")
        console.print("  [dim]try: sentinel fuzz selftest --samples 200[/dim]")
        return 2


def _cmd_fuzz_generate(args):
    """Generate random structure-aware pickle samples."""
    from sentinel.fuzzer.pickle.generator import PickleGenerator

    protocol = getattr(args, "protocol", 4)
    n = getattr(args, "count", 100)
    seed = getattr(args, "seed", None)
    output_dir = getattr(args, "dir", None) or getattr(args, "output", None)
    output_file = getattr(args, "file", None)

    _header(f"fuzz generate · protocol={protocol} · n={n}")

    gen = PickleGenerator(
        protocol=protocol,
        min_opcodes=getattr(args, "min_opcodes", 10),
        max_opcodes=getattr(args, "max_opcodes", 200),
    )

    t0 = time.perf_counter()

    if output_file:
        data = gen.generate(seed=seed)
        Path(output_file).write_bytes(data)
        _ok(f"written {len(data)} bytes → {output_file}")
    elif output_dir:
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        for i in range(n):
            data = gen.generate(seed=seed + i if seed else None)
            (out_path / f"sample_{i:05d}.pkl").write_bytes(data)
        _ok(f"generated {n} samples → {output_dir}")
    else:
        data = gen.generate(seed=seed)
        _ok(f"generated {len(data)} bytes (protocol {protocol})")
        console.print(f"  [dim]hex: {data[:60].hex()}{'...' if len(data) > 60 else ''}[/dim]")

    ms = (time.perf_counter() - t0) * 1000
    console.print(f"  [dim]{ms:.0f}ms[/dim]")
    return 0


def _cmd_fuzz_mutate(args):
    """Mutate an existing pickle file."""
    from sentinel.fuzzer.pickle.mutators import PickleMutator

    input_file = args.input_file
    n = getattr(args, "count", 10)

    _header(f"fuzz mutate · {input_file} · {n} variants")

    data = Path(input_file).read_bytes()
    mutator = PickleMutator(seed=getattr(args, "seed", None))

    output_dir = getattr(args, "dir", None)
    if output_dir:
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        for i in range(n):
            mutated = mutator.mutate(data)
            (out_path / f"mutated_{i:05d}.pkl").write_bytes(mutated)
        _ok(f"generated {n} mutated variants → {output_dir}")
    else:
        mutated = mutator.mutate(data)
        _ok(f"mutated {len(data)} → {len(mutated)} bytes")
        console.print(f"  [dim]hex: {mutated[:60].hex()}{'...' if len(mutated) > 60 else ''}[/dim]")
    return 0


def _cmd_fuzz_validate(args):
    """Validate generated pickle samples with pickletools."""
    import pickletools

    target = args.dir
    _header(f"fuzz validate · {target}")

    target_path = Path(target)
    if target_path.is_file():
        files = [target_path]
    else:
        files = list(target_path.glob("*.pkl"))

    ok_count = 0
    fail_count = 0
    for f in files:
        data = f.read_bytes()
        try:
            list(pickletools.genops(data))
            ok_count += 1
        except Exception as exc:
            fail_count += 1
            console.print(f"  [red]✗[/red] {f.name}: {exc}")

    if fail_count == 0:
        _ok(f"all {ok_count} samples parse correctly")
    else:
        _warn(f"{ok_count} ok, {fail_count} failed")
    return 1 if fail_count else 0


def _cmd_fuzz_selftest(args):
    """Run the Sentinel Eats Itself self-test pipeline."""
    from sentinel.fuzzer.base import FuzzConfig
    from sentinel.fuzzer.pickle.selftest import PickleSelfTest

    samples = getattr(args, "samples", 500)
    seed = getattr(args, "seed", None)
    output_dir = getattr(args, "dir", None)
    allow_bypass = getattr(args, "allow_bypass", False)

    _header(f"fuzz selftest · {samples} samples")

    config = FuzzConfig(samples=samples, output_dir=output_dir)
    selftest = PickleSelfTest(config=config, seed=seed)

    import logging
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    t0 = time.perf_counter()
    score = selftest.run(output_dir=output_dir)
    wall = time.perf_counter() - t0

    console.print()
    table = Table(
        title="Detection Score",
        box=box.ROUNDED,
        border_style="cyan",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")

    tpr_color = "green" if score.tpr >= 0.95 else "yellow" if score.tpr >= 0.80 else "red"
    fpr_color = "green" if score.fpr <= 0.05 else "yellow" if score.fpr <= 0.10 else "red"

    table.add_row("Total Samples", str(score.total_samples))
    table.add_row("Malicious", str(score.malicious_samples))
    table.add_row("Benign", str(score.benign_samples))
    table.add_row("───", "───")
    table.add_row("True Positive Rate", f"[{tpr_color}]{score.tpr:.1%}[/{tpr_color}]")
    table.add_row("False Positive Rate", f"[{fpr_color}]{score.fpr:.1%}[/{fpr_color}]")
    table.add_row("Precision", f"{score.precision:.1%}")
    table.add_row("F1 Score", f"{score.f1:.3f}")
    table.add_row("Bypass Rate", f"[{'red' if score.bypass_rate > 0.05 else 'green'}]{score.bypass_rate:.1%}[/]")
    table.add_row("Scanner Crashes", f"[{'red' if score.scanner_crashes > 0 else 'green'}]{score.scanner_crashes}[/]")
    table.add_row("───", "───")
    table.add_row("Wall Time", f"{wall:.1f}s")
    table.add_row("Avg Scan Time", f"{score.avg_scan_time_ms:.2f}ms")

    console.print(table)

    if score.bypassed_payloads:
        console.print(f"\n  [red bold]⚠ {len(score.bypassed_payloads)} BYPASSED PAYLOADS:[/red bold]")
        for name in score.bypassed_payloads[:30]:
            console.print(f"    [red]•[/red] {name}")

    if score.false_positive_payloads:
        console.print(f"\n  [yellow bold]⚠ {len(score.false_positive_payloads)} FALSE POSITIVES:[/yellow bold]")
        for name in score.false_positive_payloads[:20]:
            console.print(f"    [yellow]•[/yellow] {name}")

    if output_dir:
        _ok(f"report saved → {output_dir}/fuzz_report.json")

    console.print()
    if score.scanner_crashes:
        _fail(f"selftest failed: {score.scanner_crashes} scanner crash(es)")
        return 1
    if score.bypassed_payloads and not allow_bypass:
        _fail(f"selftest failed: {len(score.bypassed_payloads)} bypassed payload(s)")
        console.print("  [dim]Use --allow-bypass for exploratory runs that should exit 0.[/dim]")
        return 1
    return 0


def _cmd_fuzz_payloads(args):
    """List all available adversarial payloads."""
    from sentinel.fuzzer.pickle.payloads import PicklePayloadFactory

    _header("fuzz payloads — adversarial pickle templates")

    payloads = PicklePayloadFactory.all_payloads()

    table = Table(box=box.SIMPLE, border_style="dim", show_header=True, pad_edge=False)
    table.add_column("#", style="dim", justify="right", width=4)
    table.add_column("Name", style="cyan", max_width=30)
    table.add_column("Category", max_width=18)
    table.add_column("Severity", width=10)
    table.add_column("Size", justify="right", width=8)
    table.add_column("Description", max_width=45)

    for i, p in enumerate(payloads, 1):
        sev_style = "red" if p.severity_expected == "CRITICAL" else "yellow" if p.severity_expected == "HIGH" else "green" if p.severity_expected == "NONE" else "dim"
        cat_style = "red" if p.is_malicious else "green"
        table.add_row(
            str(i),
            p.name,
            f"[{cat_style}]{p.category.value}[/{cat_style}]",
            f"[{sev_style}]{p.severity_expected}[/{sev_style}]",
            str(len(p.data)),
            p.description[:45],
        )

    console.print(table)
    mal = sum(1 for p in payloads if p.is_malicious)
    ben = sum(1 for p in payloads if not p.is_malicious)
    console.print(f"\n  [bold]{len(payloads)}[/bold] payloads · [red]{mal} malicious[/red] · [green]{ben} benign[/green]")
    return 0


def _cmd_fuzz_minimize(args):
    """Minimize fuzz corpus by removing redundant samples (same scan verdict)."""
    from sentinel.artifact.pickle_scanner import PickleScanner

    corpus_dir = args.corpus_dir
    output_dir = getattr(args, "output", None)
    dry_run = getattr(args, "dry_run", False)

    _header(f"fuzz minimize · {corpus_dir}")

    corpus_path = Path(corpus_dir)
    if not corpus_path.is_dir():
        _fail(f"{corpus_dir} is not a directory")
        return 1

    files = sorted(corpus_path.glob("*.pkl"))
    if not files:
        _warn("no .pkl files found in corpus")
        return 0

    scanner = PickleScanner()
    # Group files by their scan signature (set of finding titles)
    signature_groups: dict[frozenset[str], list[Path]] = {}
    t0 = time.perf_counter()

    for f in files:
        try:
            data = f.read_bytes()
            findings = scanner.scan_bytes(data, source=f.name)
            sig = frozenset(f.title for f in findings) if findings else frozenset(["CLEAN"])
        except Exception:
            sig = frozenset(["ERROR"])
        signature_groups.setdefault(sig, []).append(f)

    wall = time.perf_counter() - t0

    # For each signature group, keep the smallest file (most minimized)
    kept: list[Path] = []
    removed: list[Path] = []

    for sig, group in signature_groups.items():
        # Keep the smallest sample per unique signature
        group_sorted = sorted(group, key=lambda p: p.stat().st_size)
        kept.append(group_sorted[0])
        removed.extend(group_sorted[1:])

    console.print(f"  [dim]Scanned {len(files)} files in {wall:.1f}s[/dim]")
    console.print(f"  [green]{len(kept)}[/green] unique signatures · [yellow]{len(removed)}[/yellow] redundant")

    if dry_run:
        console.print("\n  [dim]--dry-run: would remove:[/dim]")
        for f in removed[:20]:
            console.print(f"    [yellow]•[/yellow] {f.name}")
        if len(removed) > 20:
            console.print(f"    [dim]... and {len(removed) - 20} more[/dim]")
        return 0

    out_path = Path(output_dir) if output_dir else corpus_path / "minimized"
    out_path.mkdir(parents=True, exist_ok=True)

    for f in kept:
        import shutil
        shutil.copy2(f, out_path / f.name)

    _ok(f"minimized corpus: {len(files)} → {len(kept)} files → {out_path}")
    return 0
