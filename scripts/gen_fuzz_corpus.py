#!/usr/bin/env python3
"""Generate libFuzzer corpus seeds from the Python artifact generators.

Each ArtifactGenerator format produces N byte-level seeds that are written
to the appropriate cargo-fuzz corpus directory.  libFuzzer loads all files
in <target>/corpus/<name>/ at startup, so seeding with semantically valid
(but adversarial) files dramatically increases early coverage compared to
starting from random bytes.

Corpus directory layout (relative to workspace root):
  rust/sentinel-pickle/fuzz/corpus/fuzz_scanner/
  rust/sentinel-pickle/fuzz/corpus/fuzz_all_formats/
  rust/sentinel-pickle/fuzz/corpus/fuzz_gguf/
  rust/sentinel-pickle/fuzz/corpus/fuzz_tokenizer/
  rust/sentinel-gguf/fuzz/corpus/fuzz_gguf/
  rust/sentinel-tokenizer/fuzz/corpus/fuzz_tokenizer/

Usage:
  python scripts/gen_fuzz_corpus.py                    # all targets, 8 seeds/format
  python scripts/gen_fuzz_corpus.py --seeds 20         # 20 seeds per format
  python scripts/gen_fuzz_corpus.py --target fuzz_gguf # one target only
  python scripts/gen_fuzz_corpus.py --dry-run          # print paths, write nothing
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

# ── Workspace root (two levels up from scripts/) ───────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "python"))

from sentinel.fuzzer.artifact.generator import ArtifactGenerator  # noqa: E402

# ── Format → fuzz-target mapping ───────────────────────────────────────────────
# Each target gets seeds for the listed canonical format names.
TARGET_FORMATS: dict[str, tuple[str, ...]] = {
    "fuzz_scanner": ArtifactGenerator.supported_formats(),
    "fuzz_all_formats": ArtifactGenerator.supported_formats(),
    "fuzz_gguf": ("gguf",),
    "fuzz_tokenizer": ("tokenizer_json",),
}

# ── Corpus directory roots per target ──────────────────────────────────────────
CORPUS_ROOTS: dict[str, list[Path]] = {
    # sentinel-pickle fuzz workspace
    "fuzz_scanner": [
        ROOT / "rust/sentinel-pickle/fuzz/corpus/fuzz_scanner",
    ],
    "fuzz_all_formats": [
        ROOT / "rust/sentinel-pickle/fuzz/corpus/fuzz_all_formats",
    ],
    "fuzz_gguf": [
        # present in both the sentinel-pickle fuzz workspace and the
        # standalone sentinel-gguf fuzz workspace
        ROOT / "rust/sentinel-pickle/fuzz/corpus/fuzz_gguf",
        ROOT / "rust/sentinel-gguf/fuzz/corpus/fuzz_gguf",
    ],
    "fuzz_tokenizer": [
        ROOT / "rust/sentinel-pickle/fuzz/corpus/fuzz_tokenizer",
        ROOT / "rust/sentinel-tokenizer/fuzz/corpus/fuzz_tokenizer",
    ],
}


def _write_seed(data: bytes, dest_dirs: list[Path], *, dry_run: bool) -> int:
    """Write *data* to each destination directory; filename = sha256[:16].

    Returns the number of files (actually or would-be) written.
    """
    sha = hashlib.sha256(data).hexdigest()[:16]
    count = 0
    for d in dest_dirs:
        path = d / sha
        if dry_run:
            print(f"  [dry-run] would write {len(data):>6} bytes → {path}")
            count += 1
        else:
            d.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                path.write_bytes(data)
                count += 1
    return count


def generate_seeds(
    targets: list[str],
    seeds_per_format: int,
    dry_run: bool,
) -> None:
    total_written = 0

    for target in targets:
        formats = TARGET_FORMATS[target]
        dirs = CORPUS_ROOTS[target]
        print(f"\n▸ {target} ({len(formats)} formats × {seeds_per_format} seeds each)")

        for fmt in formats:
            gen = ArtifactGenerator(format=fmt)
            for i in range(seeds_per_format):
                try:
                    data = gen.generate(seed=i)
                    total_written += _write_seed(data, dirs, dry_run=dry_run)
                except Exception as exc:  # noqa: BLE001
                    print(f"  ⚠ {fmt} seed {i} failed: {exc}")

    if dry_run:
        print(f"\n[dry-run] would write up to {total_written} corpus files.")
    else:
        print(f"\n✓ {total_written} new corpus files written.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--target",
        choices=list(TARGET_FORMATS),
        default=None,
        help="Seed only this fuzz target (default: all).",
    )
    parser.add_argument(
        "--seeds",
        type=int,
        default=8,
        metavar="N",
        help="Number of seeds to generate per format (default: 8).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be written without writing any files.",
    )
    args = parser.parse_args()

    targets = [args.target] if args.target else list(TARGET_FORMATS)
    generate_seeds(targets, seeds_per_format=args.seeds, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
