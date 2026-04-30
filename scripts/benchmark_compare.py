"""
Compare two benchmark run JSON files and report deltas.

Usage:
    python scripts/benchmark_compare.py benchmarks/run_A.json benchmarks/run_B.json
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

_NUMERIC_KEYS = ("precision", "recall", "f1", "latency_p50_ms", "latency_p99_ms",
                 "tp", "fp", "fn", "tn", "total")


def _delta(a: float | int, b: float | int) -> str:
    diff = b - a
    sign = "+" if diff >= 0 else ""
    return f"{sign}{diff:.4g}"


def compare(path_a: str, path_b: str) -> dict:
    a = json.loads(Path(path_a).read_text())
    b = json.loads(Path(path_b).read_text())

    rows = {}
    for k in _NUMERIC_KEYS:
        if k in a and k in b:
            rows[k] = {"baseline": a[k], "current": b[k], "delta": _delta(a[k], b[k])}
    return {
        "baseline_timestamp": a.get("timestamp"),
        "current_timestamp":  b.get("timestamp"),
        "metrics": rows,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("baseline")
    ap.add_argument("current")
    args = ap.parse_args()

    result = compare(args.baseline, args.current)
    print(f"Baseline : {result['baseline_timestamp']}")
    print(f"Current  : {result['current_timestamp']}")
    print()
    print(f"{'Metric':<22} {'Baseline':>12} {'Current':>12} {'Delta':>10}")
    print("-" * 60)
    for k, v in result["metrics"].items():
        print(f"{k:<22} {v['baseline']:>12} {v['current']:>12} {v['delta']:>10}")


if __name__ == "__main__":
    main()
