"""CLI entry for ``sentinel aibom``."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sentinel.aibom.reporters import (
    CSVReporter,
    CycloneDXReporter,
    HTMLReporter,
    JUnitReporter,
    MarkdownReporter,
    SARIFReporter,
    SPDXReporter,
)
from sentinel.aibom.scan_pipeline import ScanPipeline

_REPORTERS = {
    "cyclonedx": CycloneDXReporter,
    "spdx": SPDXReporter,
    "sarif": SARIFReporter,
    "html": HTMLReporter,
    "csv": CSVReporter,
    "junit": JUnitReporter,
    "markdown": MarkdownReporter,
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sentinel aibom",
        description="Generate an AI Bill of Materials.",
    )
    p.add_argument("path", nargs="?", default=".", help="Repository or directory to scan.")
    p.add_argument("--format", "-f", default="cyclonedx", choices=sorted(_REPORTERS))
    p.add_argument("--output", "-o", help="Output file (default: stdout).")
    p.add_argument(
        "--ci",
        action="store_true",
        help="CI-compatible no-op flag for GitHub Action parity.",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    pipeline = ScanPipeline()
    result = pipeline.run(Path(args.path))
    rendered = _REPORTERS[args.format]().render(result)
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
        if not rendered.endswith("\n"):
            sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
