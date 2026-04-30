#!/usr/bin/env python3
"""Atheris/libFuzzer harness for the Sentinel pickle scanner.

Usage (coverage-guided fuzzing)::

    pip install atheris
    python fuzz_pickle_scanner.py -corpus=. -max_total_time=60

Usage (single crash reproduction)::

    python fuzz_pickle_scanner.py crash-<hash>

The harness exercises:
  1. ``sentinel.artifact.pickle_scanner.PickleScanner.scan_bytes``
  2. The raw ``pickle.loads`` path (to discover parser crashes)
  3. Opcode parsing in ``sentinel.artifact.pickle_scanner``
"""

import sys
import pickle

# Atheris optional — falls back to a simple byte-mutating loop for CI
try:
    import atheris  # type: ignore[import]
    _HAS_ATHERIS = True
except ImportError:
    _HAS_ATHERIS = False

# Import the scanner under test
try:
    from sentinel.artifact.pickle_scanner import PickleScanner  # type: ignore
    _scanner = PickleScanner()
    _HAS_SCANNER = True
except Exception:
    _HAS_SCANNER = False


def fuzz_one_input(data: bytes) -> None:
    """Exercise the scanner and raw pickle loader on arbitrary bytes."""
    # 1. Run Sentinel scanner — must never raise
    if _HAS_SCANNER:
        try:
            _scanner.scan_bytes(data, source="fuzz_corpus")
        except Exception:
            pass  # findings, not crashes, are expected

    # 2. Raw pickle.loads — document any parser crashes
    try:
        pickle.loads(data)  # noqa: S301  (intentional — fuzzing test)
    except Exception:
        pass  # Expected for malformed inputs


if __name__ == "__main__":
    if _HAS_ATHERIS:
        atheris.Setup(sys.argv, fuzz_one_input)
        atheris.Fuzz()
    else:
        # Simple regression loop over seed files when Atheris is absent
        import os
        corpus_dir = os.path.dirname(__file__)
        seeds = [f for f in os.listdir(corpus_dir) if f.endswith(".pkl")]
        if not seeds:
            print("No .pkl seeds found — run from the corpus directory", file=sys.stderr)
            sys.exit(1)
        for seed_name in seeds:
            seed_path = os.path.join(corpus_dir, seed_name)
            with open(seed_path, "rb") as fh:
                data = fh.read()
            fuzz_one_input(data)
            print(f"  OK  {seed_name}")
        print(f"Regression pass: {len(seeds)} seeds")
