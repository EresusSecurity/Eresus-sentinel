"""
Generate a Markdown summary from all benchmark JSON files in a directory.

Usage:
    python scripts/benchmark_report.py [--dir benchmarks] [--out BENCHMARK_RESULTS.md]
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


_HEADER = "# Benchmark Results\n\n"
_TABLE_HEADER = (
    "| Run | Precision | Recall | F1 | P50 ms | P99 ms | TP | FP | FN |\n"
    "|-----|-----------|--------|----|--------|--------|----|----|----|\n"
)


def _row(run: dict) -> str:
    ts = run.get("timestamp", "?")[:19].replace("T", " ")
    return (
        f"| {ts} "
        f"| {run.get('precision', '-'):.4f} "
        f"| {run.get('recall', '-'):.4f} "
        f"| {run.get('f1', '-'):.4f} "
        f"| {run.get('latency_p50_ms', '-')} "
        f"| {run.get('latency_p99_ms', '-')} "
        f"| {run.get('tp', '-')} "
        f"| {run.get('fp', '-')} "
        f"| {run.get('fn', '-')} |\n"
    )


def build_report(bench_dir: str) -> str:
    runs = []
    for f in sorted(Path(bench_dir).glob("run_*.json")):
        try:
            runs.append(json.loads(f.read_text()))
        except Exception:
            pass
    if not runs:
        return _HEADER + "_No benchmark runs found._\n"
    return _HEADER + _TABLE_HEADER + "".join(_row(r) for r in runs[-20:])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="benchmarks")
    ap.add_argument("--out", default="BENCHMARK_RESULTS.md")
    args = ap.parse_args()

    report = build_report(args.dir)
    Path(args.out).write_text(report, encoding="utf-8")
    print(f"Report written → {args.out}")


if __name__ == "__main__":
    main()
