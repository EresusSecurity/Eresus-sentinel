"""sentinel-pre-commit — installable pre-commit hook entrypoint.

Wraps ``sentinel artifact-scan`` with pre-commit-compatible argument handling.
Staged files are passed as positional arguments by pre-commit's pass_filenames.

Usage in .pre-commit-config.yaml:
  - repo: local
    hooks:
      - id: sentinel-scan
        name: Sentinel model artifact scan
        entry: sentinel-pre-commit
        language: system
        types: [file]
        args: [--fail-on, critical]
"""
from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    """Entry point for the sentinel-pre-commit script."""
    import argparse

    from sentinel.cli.cmd_scan import cmd_artifact_scan

    parser = argparse.ArgumentParser(
        prog="sentinel-pre-commit",
        description="Sentinel model artifact security scanner (pre-commit hook)",
    )
    parser.add_argument(
        "files",
        nargs="*",
        metavar="FILE",
        help="Staged files to scan (passed by pre-commit pass_filenames)",
    )
    parser.add_argument(
        "--fail-on",
        default="critical",
        choices=["critical", "high", "medium", "low"],
        help="Minimum severity level that causes a non-zero exit (default: critical)",
    )
    parser.add_argument(
        "--show-all",
        action="store_true",
        help="Show all findings including INFO severity",
    )

    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    if not args.files:
        return 0

    exit_code = cmd_artifact_scan(args)
    return exit_code if isinstance(exit_code, int) else 0


if __name__ == "__main__":
    sys.exit(main())
