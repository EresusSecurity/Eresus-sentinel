#!/usr/bin/env python3
"""Print the `.refs` parity manifest as Markdown or JSON."""
from __future__ import annotations

import argparse
import sys

sys.path.insert(0, "python")

from sentinel.parity import manifest_to_json, manifest_to_markdown, write_manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate Sentinel reference parity manifest.")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--output", default="", help="Optional output path.")
    args = parser.parse_args()

    if args.output:
        write_manifest(args.output, fmt=args.format)
    elif args.format == "json":
        print(manifest_to_json())
    else:
        print(manifest_to_markdown(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
