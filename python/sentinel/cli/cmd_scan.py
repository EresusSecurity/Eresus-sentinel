"""Scan commands — scan, firewall, artifact, hf-artifact, hf-scan, hf-guard."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import urlretrieve

from rich import box
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from sentinel.cli._export import _export, _sanitize_for_json
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
    machine_stdout,
    console,
)


def _fails_threshold(findings, fail_on: str | None) -> bool:
    """Return true when a finding meets the configured CI failure threshold."""
    order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    if not fail_on:
        return any(order.get(_sev(f)[0], 0) >= order["MEDIUM"] for f in findings)

    threshold = order.get(fail_on.upper(), 3)
    return any(order.get(_sev(f)[0], 0) >= threshold for f in findings)


_ARTIFACT_OUTPUT_FORMATS = [
    "table",
    "json",
    "sarif",
    "csv",
    "markdown",
    "html",
    "junit",
    "plaintext",
    "summary",
    "otlp",
    "splunk",
    "cyclonedx",
    "spdx",
    "webhook",
    "modelcard",
]


def _add_artifact_output_args(parser: argparse.ArgumentParser, *, severity: bool = True) -> None:
    parser.add_argument("-f", "--format", choices=_ARTIFACT_OUTPUT_FORMATS, default=argparse.SUPPRESS)
    parser.add_argument("-o", "--output", default=argparse.SUPPRESS, help="output file")
    parser.add_argument("--webhook-url", default=None, help="HTTP endpoint for -f webhook")
    parser.add_argument("--webhook-token", default=None, help="Bearer token for -f webhook")
    if severity:
        parser.add_argument(
            "--min-severity",
            choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
            default=argparse.SUPPRESS,
        )


def _inherit_artifact_globals(parsed: argparse.Namespace, root_args: argparse.Namespace) -> argparse.Namespace:
    for attr, default in (
        ("format", getattr(root_args, "format", "table")),
        ("output", getattr(root_args, "output", None)),
        ("min_severity", getattr(root_args, "min_severity", None)),
        ("show_skipped", getattr(root_args, "show_skipped", False)),
    ):
        if not hasattr(parsed, attr):
            setattr(parsed, attr, default)
    parsed.command = "artifact"
    return parsed


def _scanner_tokens(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(token.strip().lower() for token in value.split(",") if token.strip())


def _parse_size_limit(value: str | None) -> int | None:
    if not value:
        return None
    text = value.strip().lower()
    units = {
        "b": 1,
        "kb": 1000,
        "kib": 1024,
        "mb": 1000**2,
        "mib": 1024**2,
        "gb": 1000**3,
        "gib": 1024**3,
        "tb": 1000**4,
        "tib": 1024**4,
    }
    for suffix, multiplier in sorted(units.items(), key=lambda item: len(item[0]), reverse=True):
        if text.endswith(suffix):
            number = text[: -len(suffix)].strip()
            return int(float(number) * multiplier)
    return int(float(text))


def _download_stream_target(target: str) -> tuple[Path, tempfile.TemporaryDirectory[str] | None]:
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"}:
        return Path(target), None
    tmpdir = tempfile.TemporaryDirectory(prefix="sentinel-artifact-stream-")
    suffix = Path(parsed.path).suffix or ".artifact"
    local_path = Path(tmpdir.name) / f"streamed{suffix}"
    urlretrieve(target, local_path)
    return local_path, tmpdir


def _artifact_scanner_rows() -> list[dict]:
    from sentinel.artifact import _scanner_catalog

    return [
        {
            "id": spec.key,
            "class": spec.scanner_cls.__name__,
            "extensions": list(spec.extensions),
            "unsafe_serialization": spec.unsafe_serialization,
        }
        for spec in _scanner_catalog()
    ]


def _emit_artifact_info(args: argparse.Namespace, payload: dict) -> None:
    from sentinel.cli.cmd_tools import _emit_info

    _emit_info(args, payload)


def _cmd_artifact_list_scanners(args: argparse.Namespace) -> int:
    scanners = _artifact_scanner_rows()
    payload = {
        "schema_version": "artifact.scanners.v1",
        "summary": {"total": len(scanners), "unsafe_serialization": sum(1 for row in scanners if row["unsafe_serialization"])},
        "scanners": scanners,
        "errors": [],
        "metadata": {"command": "artifact scan --list-scanners"},
    }
    if getattr(args, "format", "table") in ("json", "sarif") or getattr(args, "output", None):
        _emit_artifact_info(args, payload)
        return 0

    table = Table(box=box.SIMPLE_HEAVY, border_style="dim")
    table.add_column("id", style="bold")
    table.add_column("class")
    table.add_column("extensions")
    table.add_column("unsafe", justify="center")
    for row in scanners:
        table.add_row(row["id"], row["class"], ", ".join(row["extensions"]), "yes" if row["unsafe_serialization"] else "")
    _header(f"artifact scanners · {len(scanners)} registered", args=args)
    console.print(table)
    return 0


def _artifact_options(args: argparse.Namespace):
    from sentinel.artifact import ArtifactScanOptions

    return ArtifactScanOptions(
        include=_scanner_tokens(getattr(args, "scanners", None)),
        exclude=_scanner_tokens(getattr(args, "exclude_scanner", None)),
        strict=bool(getattr(args, "strict", False)),
        cache=True,
        fail_closed=True,
    )


def _artifact_plan(path: Path, args: argparse.Namespace) -> tuple[list[dict], list[dict]]:
    from sentinel.artifact import _find_scanner_spec, _scanner_selected

    options = _artifact_options(args)
    max_size = _parse_size_limit(getattr(args, "max_size", None))
    candidates = [path] if path.is_file() else [p for p in path.rglob("*") if p.is_file()]
    planned: list[dict] = []
    skipped: list[dict] = []
    for candidate in candidates:
        try:
            size = candidate.stat().st_size
        except OSError as exc:
            skipped.append({"path": str(candidate), "reason": f"stat failed: {exc}"})
            continue
        spec = _find_scanner_spec(candidate)
        if spec is None:
            skipped.append({"path": str(candidate), "reason": "unsupported format"})
            continue
        if not _scanner_selected(spec, options):
            skipped.append({"path": str(candidate), "reason": "scanner excluded"})
            continue
        if max_size is not None and size > max_size:
            skipped.append({"path": str(candidate), "reason": "max-size exceeded", "size": size})
            continue
        planned.append(
            {
                "path": str(candidate),
                "scanner": spec.key,
                "class": spec.scanner_cls.__name__,
                "size": size,
                "extensions": list(spec.extensions),
            }
        )
    return planned, skipped


def _max_size_finding(path: str, max_size: str):
    from sentinel.finding import Finding, Severity

    return Finding.artifact(
        rule_id="ARTIFACT-MAX-SIZE",
        title="Artifact skipped by CLI max-size limit",
        description="The artifact was not scanned because it exceeds the requested CLI max-size budget.",
        severity=Severity.MEDIUM,
        target=path,
        evidence=f"max_size={max_size}",
        confidence=0.9,
        remediation="Raise --max-size for trusted large artifacts, or scan the file in a controlled environment.",
    )


def _write_artifact_sbom(path: Path, planned: list[dict], output: str) -> None:
    components = []
    for item in planned:
        component_path = Path(item["path"])
        hashes = []
        if component_path.is_file():
            digest = hashlib.sha256()
            with open(component_path, "rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            hashes.append({"alg": "SHA-256", "content": digest.hexdigest()})
        components.append(
            {
                "type": "file",
                "name": component_path.name,
                "bom-ref": str(component_path),
                "hashes": hashes,
                "properties": [
                    {"name": "sentinel:scanner", "value": item["scanner"]},
                    {"name": "sentinel:size", "value": str(item["size"])},
                ],
            }
        )
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": {"type": "file", "name": path.name, "bom-ref": str(path)}},
        "components": components,
    }
    Path(output).write_text(json.dumps(sbom, indent=2, ensure_ascii=True), encoding="utf-8")


def _scan_artifact_planned(planned: list[dict], skipped: list[dict], args: argparse.Namespace):
    from sentinel.artifact import scan_file

    findings = []
    max_size = getattr(args, "max_size", None)
    for item in planned:
        findings.extend(
            scan_file(
                item["path"],
                options=_artifact_options(args),
            )
        )
    if getattr(args, "strict", False):
        for item in skipped:
            if item.get("reason") == "unsupported format":
                findings.extend(scan_file(item["path"], options=_artifact_options(args)))
    if max_size:
        findings.extend(_max_size_finding(item["path"], max_size) for item in skipped if item.get("reason") == "max-size exceeded")
    return findings


def _cmd_artifact_scan(args: argparse.Namespace) -> int:
    if getattr(args, "list_scanners", False):
        return _cmd_artifact_list_scanners(args)

    target = getattr(args, "path", None)
    if not target:
        _fail("path required unless --list-scanners is used")
        return 2

    tmpdir = None
    try:
        path, tmpdir = _download_stream_target(target) if getattr(args, "stream", False) else (Path(target), None)
        if not path.exists():
            _fail(f"path not found: {target}")
            return 2

        planned, skipped = _artifact_plan(path, args)

        if getattr(args, "sbom", None):
            _write_artifact_sbom(path, planned, args.sbom)

        if getattr(args, "dry_run", False):
            payload = {
                "schema_version": "artifact.plan.v1",
                "summary": {"target": str(path), "planned": len(planned), "skipped": len(skipped)},
                "plan": planned,
                "skipped": skipped,
                "errors": [],
                "metadata": {
                    "include": list(_scanner_tokens(getattr(args, "scanners", None))),
                    "exclude": list(_scanner_tokens(getattr(args, "exclude_scanner", None))),
                    "strict": bool(getattr(args, "strict", False)),
                    "max_size": getattr(args, "max_size", None),
                    "sbom": getattr(args, "sbom", None),
                },
            }
            if getattr(args, "format", "table") in ("json", "sarif") or getattr(args, "output", None):
                _emit_artifact_info(args, payload)
            else:
                _header(f"artifact dry-run → {path}", args=args)
                for item in planned[:50]:
                    console.print(f"  [green]●[/green] {item['scanner']}  [dim]{item['path']}[/dim]")
                if len(planned) > 50:
                    console.print(f"  [dim]... and {len(planned) - 50} more[/dim]")
                if getattr(args, "show_skipped", False) and skipped:
                    console.print(f"\n  [dim]⊘ {len(skipped)} skipped[/dim]")
            return 0

        findings = _scan_artifact_planned(planned, skipped, args)
        findings = _apply_severity_filter(findings, args)

        if getattr(args, "format", "table") == "table":
            _header(f"artifact scan → {path}", args=args)
            _print_findings(findings, args=args)
            if getattr(args, "show_skipped", False) and skipped:
                console.print(f"\n  [dim]⊘ {len(skipped)} file(s) skipped:[/dim]")
                for item in skipped[:20]:
                    console.print(f"    [dim]· {item['path']} ({item['reason']})[/dim]")
                if len(skipped) > 20:
                    console.print(f"    [dim]  ... and {len(skipped) - 20} more[/dim]")

        _export(args, findings)
        return 1 if _fails_threshold(findings, getattr(args, "fail_on", None)) else 0
    finally:
        if tmpdir is not None:
            tmpdir.cleanup()


def _cmd_artifact_metadata(args: argparse.Namespace) -> int:
    from sentinel.artifact import _find_scanner_spec

    path = Path(args.path)
    if not path.exists() or not path.is_file():
        _fail(f"path not found: {args.path}")
        return 2

    stat = path.stat()
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        first_bytes = handle.read(64)
        digest.update(first_bytes)
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)

    spec = _find_scanner_spec(path)
    metadata = {
        "path": str(path),
        "name": path.name,
        "size": stat.st_size,
        "sha256": digest.hexdigest(),
        "scanner": spec.key if spec else None,
        "scanner_class": spec.scanner_cls.__name__ if spec else None,
        "unsafe_serialization": bool(spec and spec.unsafe_serialization),
        "supported": spec is not None,
    }
    if not getattr(args, "security_only", False):
        metadata.update(
            {
                "suffix": path.suffix.lower(),
                "magic_hex": first_bytes[:16].hex(),
                "modified_time": int(stat.st_mtime),
            }
        )

    payload = {
        "schema_version": "artifact.metadata.v1",
        "summary": {"target": str(path), "supported": metadata["supported"], "scanner": metadata["scanner"]},
        "metadata": metadata,
        "errors": [],
    }
    if getattr(args, "format", "table") in ("json", "sarif") or getattr(args, "output", None):
        _emit_artifact_info(args, payload)
        return 0

    table = Table(box=box.SIMPLE_HEAVY, border_style="dim")
    table.add_column("field", style="bold")
    table.add_column("value")
    for key, value in metadata.items():
        table.add_row(key, str(value))
    _header(f"artifact metadata → {path}", args=args)
    console.print(table)
    return 0


def _artifact_scan_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentinel artifact scan", description="scan model artifacts without deserializing them")
    parser.add_argument("path", nargs="?", help="file, directory, or URL when --stream is set")
    parser.add_argument("--list-scanners", action="store_true", help="list registered artifact scanners")
    parser.add_argument("--scanners", help="comma-separated scanner allowlist (id, class, or extension)")
    parser.add_argument("--exclude-scanner", help="comma-separated scanner denylist (id, class, or extension)")
    parser.add_argument("--dry-run", action="store_true", help="preview files and scanners without scanning")
    parser.add_argument("--strict", action="store_true", help="emit findings for unsupported artifact formats and scanner failures")
    parser.add_argument("--stream", action="store_true", help="download remote URL to a temporary file before scanning")
    parser.add_argument("--max-size", help="skip artifacts larger than this size, e.g. 10GB")
    parser.add_argument("--trust-loaders", action="store_true", dest="trust_loaders",
                        help="opt-in to deserialization for formats that require it (pickle, torch, joblib)")
    parser.add_argument("--sbom", help="write a CycloneDX SBOM JSON file")
    parser.add_argument("--show-skipped", action="store_true", default=argparse.SUPPRESS)
    parser.add_argument(
        "--fail-on",
        choices=["info", "low", "medium", "high", "critical", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
    )
    _add_artifact_output_args(parser)
    return parser


def _artifact_metadata_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentinel artifact metadata", description="extract safe metadata from a model artifact")
    parser.add_argument("path")
    parser.add_argument("--security-only", action="store_true", help="omit non-security metadata fields")
    _add_artifact_output_args(parser, severity=False)
    return parser


def _artifact_legacy_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentinel artifact", description="scan model artifacts")
    parser.add_argument("path")
    parser.add_argument("--show-skipped", action="store_true", default=argparse.SUPPRESS)
    _add_artifact_output_args(parser)
    return parser


def cmd_artifact_entry(args: argparse.Namespace) -> int:
    """Artifact command router preserving `sentinel artifact PATH` legacy usage."""
    tokens = list(getattr(args, "artifact_args", []) or [])
    if tokens and tokens[0] == "--":
        tokens = tokens[1:]
    if not tokens or tokens[0] in {"-h", "--help"}:
        _artifact_legacy_parser().print_help()
        return 0

    action = tokens[0]
    if action == "scan":
        parsed = _artifact_scan_parser().parse_args(tokens[1:])
        parsed = _inherit_artifact_globals(parsed, args)
        if getattr(parsed, "format", "table") != "table":
            console.file = sys.stderr
        return _cmd_artifact_scan(parsed)
    if action == "metadata":
        parsed = _artifact_metadata_parser().parse_args(tokens[1:])
        parsed = _inherit_artifact_globals(parsed, args)
        if getattr(parsed, "format", "table") != "table":
            console.file = sys.stderr
        return _cmd_artifact_metadata(parsed)

    parsed = _artifact_legacy_parser().parse_args(tokens)
    parsed = _inherit_artifact_globals(parsed, args)
    if getattr(parsed, "format", "table") != "table":
        console.file = sys.stderr
    return cmd_artifact(parsed)


_SCAN_MAX_FILES = 10_000
_DANGEROUS_ROOTS = frozenset({"/", "/usr", "/System", "/Applications", "/Library", "/var", "/etc", "/opt", "C:\\", "C:\\Windows"})

_PROFILE_DESCRIPTIONS = {
    "fast": "SAST + secrets only; optimized for pre-commit and quick local checks",
    "balanced": "Default multi-domain scan across artifacts, firewalls, SAST, agents, supply chain, diff, notebooks, and rules",
    "deep": "Balanced scan plus explicit secrets pass for higher assurance",
    "paranoid": "Deep scan profile reserved for strict CI; currently runs deep deterministic modules",
}


def _emit_scan_plan(args, plan: dict) -> None:
    fmt = getattr(args, "format", "table")
    out = getattr(args, "output", None)
    if fmt == "json" or out:
        from sentinel.scan_report import SCAN_REPORT_SCHEMA_VERSION

        payload = {
            "schema_version": "0.1",
            "result_schema_version": SCAN_REPORT_SCHEMA_VERSION,
            "command": "scan",
            "summary": {
                "command": "scan",
                "mode": "plan",
                "target": plan["target"],
                "profile": plan["profile"],
                "module_count": len(plan["modules"]),
            },
            "totals": {"modules": len(plan["modules"])},
            "findings": [],
            "errors": [],
            "metadata": {
                "profile_description": plan["profile_description"],
                "strict_exit_contract": "0=clean/plan, 1=findings-or-blocked, 2=usage/internal error",
            },
            "plan": plan,
        }
        rendered = json.dumps(payload, indent=2, default=str, ensure_ascii=True)
        if out:
            Path(out).write_text(rendered + "\n", encoding="utf-8")
            _ok(f"written {out}")
        else:
            out_stream = machine_stdout()
            out_stream.write(rendered + "\n")
            out_stream.flush()
        return

    from rich import box as _box
    from rich.table import Table as _T

    t = _T(title="Scan plan", box=_box.SIMPLE)
    t.add_column("Module")
    t.add_column("Label")
    t.add_column("Status")
    for module in plan["modules"]:
        t.add_row(module["name"], module["label"], "[green]will run[/green]")
    console.print(t)
    console.print(
        f"\n  [dim]{len(plan['modules'])} module(s) would run on "
        f"[cyan]{plan['target']}[/cyan] · profile=[cyan]{plan['profile']}[/cyan][/dim]"
    )


def _emit_scan_result(args, findings, results: list[dict], wall_seconds: float, exit_code: int, profile: str) -> None:
    from sentinel.scan_report import build_scan_envelope

    errors = [
        {
            "module": result["name"],
            "label": result["label"],
            "findings": result["findings"],
        }
        for result in results
        if not result["ok"]
    ]
    status = "error" if errors else "findings" if findings else "clean"
    payload = build_scan_envelope(
        findings,
        command="scan",
        summary={
            "command": "scan",
            "target": getattr(args, "path", ""),
            "profile": profile,
            "status": status,
            "exit_code": exit_code,
            "duration_ms": round(wall_seconds * 1000, 2),
        },
        totals={
            "modules": len(results),
            "modules_passed": sum(1 for result in results if result["ok"]),
        },
        errors=errors,
        metadata={
            "module_results": results,
        },
    )
    rendered = json.dumps(_sanitize_for_json(payload), indent=2, default=str, ensure_ascii=True)
    out = getattr(args, "output", None)
    if out:
        Path(out).write_text(rendered + "\n", encoding="utf-8")
        _ok(f"written {out}")
    else:
        out_stream = machine_stdout()
        out_stream.write(rendered + "\n")
        out_stream.flush()


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
    profile = getattr(args, "profile", None) or ("fast" if fast else "balanced")
    fmt = getattr(args, "format", "table")

    base_modules = [
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

    if profile == "fast":
        modules = [
            ("sast", "static analysis", dispatch_sast),
            ("secrets", "secrets", dispatch_secrets),
        ]
    elif profile == "deep":
        modules = [*base_modules, ("secrets", "secrets", dispatch_secrets)]
    elif profile == "paranoid":
        modules = [*base_modules, ("secrets", "secrets", dispatch_secrets)]
    else:
        modules = base_modules

    scan_plan = {
        "target": args.path,
        "profile": profile,
        "profile_description": _PROFILE_DESCRIPTIONS[profile],
        "modules": [
            {"name": name, "label": label, "status": "will_run"}
            for name, label, _ in modules
        ],
        "options": {
            "min_severity": getattr(args, "min_severity", None),
            "fail_on": getattr(args, "fail_on", None),
            "ci": bool(getattr(args, "ci", False)),
            "stdin_files": bool(getattr(args, "stdin_files", False)),
        },
    }

    # --explain-plan: show what would run, then exit
    if getattr(args, "explain_plan", False):
        _emit_scan_plan(args, scan_plan)
        return 0

    if os.path.isdir(resolved):
        file_count = sum(1 for _ in Path(resolved).rglob("*") if _.is_file())
        if file_count > _SCAN_MAX_FILES:
            _warn(f"directory has {file_count:,} files (limit {_SCAN_MAX_FILES:,}). Narrow scope or increase limit.")
            return 2

    if fmt == "table":
        _header(f"{profile} scan → {args.path}", args=args)

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
        disable=fmt != "table",
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

            if fmt == "table":
                mark = "[green]✓[/green]" if ok and fc == 0 else "[yellow]![/yellow]" if ok else "[red]✗[/red]"
                count_str = f"[red]{fc}[/red]" if fc > 0 else "[green]0[/green]"
                console.print(f"  {mark} {label:<20} {count_str:>12} findings  [dim]{ms:>6.0f}ms[/dim]")

            results.append({"name": name, "label": label, "ms": ms, "ok": ok, "findings": fc})
            progress.advance(task)

    all_findings = _apply_severity_filter(all_findings, args)

    wall = time.perf_counter() - t0
    total_f = len(all_findings)
    passed = sum(1 for r in results if r["ok"])

    if fmt == "table":
        console.print(f"\n  [bold]{passed}/{len(results)}[/bold] passed · "
                      f"[bold]{total_f}[/bold] finding(s) · "
                      f"[dim]{wall:.1f}s[/dim]")

        if total_f > 0:
            _severity_dashboard(all_findings)
            console.print()
            for f in all_findings:
                _finding_line(f, compact=True)

        console.print()
    has_scan_error = any(not r["ok"] for r in results)
    exit_code = 1 if has_scan_error or _fails_threshold(all_findings, getattr(args, "fail_on", None)) else 0
    if fmt == "json":
        _emit_scan_result(args, all_findings, results, wall, exit_code, profile)
    else:
        _export(args, all_findings)
    return exit_code


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
    if direction == "output":
        findings = dispatch_firewall_output(text)
    elif direction == "both":
        findings = list(dispatch_firewall_input(text)) + list(dispatch_firewall_output(text))
    else:
        findings = dispatch_firewall_input(text)
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
            '.xgb', '.ubj', '.model', '.lgb', '.lightgbm', '.joblib',
            '.npy', '.npz',
            '.nemo', '.mar', '.tar', '.tgz', '.zip', '.7z',
            '.rds', '.rda', '.rdata',
            '.skops',
            '.t7', '.th',
            '.pte',
            '.engine', '.plan', '.trt',
            '.cbm',
            '.mlmodel', '.mlpackage',
            '.msgpack', '.orbax', '.flax',
            '.pmml',
            '.pdmodel', '.pdiparams', '.pdparams',
            '.xml',
            '.params',
            '.yaml', '.yml',
            '.oci',
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

    fmt = getattr(args, "format", "table")
    _header(f"hf-guard → {args.repo}", args=args)
    guard = HFGuard(
        block_pickle=getattr(args, "block_pickle", False),
        require_safetensors=getattr(args, "require_safetensors", False),
        offline=getattr(args, "offline", None) or None,
    )
    assessment = guard.assess(args.repo)

    if fmt == "table":
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
        if fmt == "table":
            console.print("\n  Running deep scan...")
        findings = guard.scan(args.repo)
        findings = _apply_severity_filter(findings, args)
        _print_findings(findings, args=args)
        _export(args, findings)
        return 1 if findings else 0

    if fmt != "table":
        from sentinel.cli.cmd_tools import _emit_info
        payload = {
            "schema_version": "hf-guard.assessment.v1",
            "command": "hf-guard",
            "repo": args.repo,
            "risk_level": assessment.risk_level,
            "risk_score": assessment.risk_score,
            "total_files": assessment.total_files,
            "has_safetensors": assessment.has_safetensors,
            "has_pickle": assessment.has_pickle,
            "dangerous_files": assessment.dangerous_files,
            "recommendations": assessment.recommendations,
            "metadata": assessment.metadata,
        }
        _emit_info(args, payload)

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
    Exit codes follow ref-artifact-scan-suite contract:
      0 = clean, 1 = findings at/above threshold, 2 = scan error
    """
    from sentinel.artifact import scan_file_rich
    from sentinel.artifact.scan_result import ArtifactScanResult, ScanError

    files: list[Path] = []
    for raw in args.files:
        p = Path(raw)
        if p.is_file():
            files.append(p)
        elif p.is_dir():
            files.extend(f for f in p.rglob("*") if f.is_file())

    if not files:
        return 0

    fail_on: str = getattr(args, "fail_on", "critical") or "critical"
    aggregate = ArtifactScanResult()

    for f in files:
        result = scan_file_rich(str(f))
        aggregate.findings.extend(result.findings)
        aggregate.errors.extend(result.errors)
        aggregate.files_scanned += result.files_scanned

        if result.errors:
            from sentinel.cli._helpers import _warn
            for err in result.errors:
                _warn(f"{f.name}  →  scan error: {err.error}")
        elif result.findings:
            _fail(f"{f.name}  →  {len(result.findings)} finding(s)")
            for finding in result.findings:
                _finding_line(finding)
        else:
            _ok(f"{f.name}  →  clean")

    if aggregate.fatal_errors:
        return 2

    if not aggregate.findings:
        return 0

    if _hook_threshold(aggregate.findings, fail_on):
        console.print(
            f"\n  [bold red]sentinel:[/bold red] {len(aggregate.findings)} finding(s) "
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
