"""Remote artifact registry scan command."""
from __future__ import annotations

from sentinel.cli._export import _export
from sentinel.cli._helpers import _fail, _header, _ok, _warn, console, _print_findings


def cmd_remote_scan(args) -> int:
    """Scan AI models stored in remote registries (S3/GCS/DVC/MLflow/JFrog)."""
    from sentinel.artifact.remote_scanner import RemoteArtifactScanner

    uri = args.uri
    dry_run = getattr(args, "dry_run", False)
    max_size = getattr(args, "max_file_size", 2 * 1024 ** 3)
    region = getattr(args, "region", None)
    profile = getattr(args, "profile", None)
    token = getattr(args, "token", None)

    _header(f"remote-scan → {uri}" + (" [dry-run]" if dry_run else ""), args=args)

    scanner = RemoteArtifactScanner(max_file_size=max_size, dry_run=dry_run)

    kwargs = {}
    if region:
        kwargs["region"] = region
    if profile:
        kwargs["profile"] = profile
    if token:
        kwargs["token"] = token

    result = scanner.scan(uri, **kwargs)

    for err in result.errors:
        _warn(err)

    if result.errors and result.scanned_files == 0:
        if any("not installed" in e or "not available" in e for e in result.errors):
            _fail("required dependency missing — see errors above")
            return 2

    findings = result.findings
    fmt = getattr(args, "format", "table")

    mb = result.total_bytes / (1024 ** 2)
    console.print(
        f"  [dim]registry={result.registry}, files={result.scanned_files}, "
        f"downloaded={mb:.1f} MB[/dim]"
    )

    if fmt == "table":
        if not findings:
            _ok("no security findings in remote artifacts")
        else:
            _warn(f"{len(findings)} findings in remote artifacts")
            _print_findings(findings, args=args)
    else:
        _export(args, findings)

    return 1 if findings else 0
