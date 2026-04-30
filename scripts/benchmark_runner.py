"""
Benchmark runner — scans a sample corpus with Sentinel and records
latency, TP, FP, FN metrics to a timestamped JSON file.

Usage:
    python scripts/benchmark_runner.py [--corpus payloads/injection.yaml]
"""
from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml


def _load_corpus(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    items = data if isinstance(data, list) else data.get("payloads", [])
    return [{"text": str(i.get("text", i)), "label": str(i.get("label", "malicious"))}
            for i in items]


def _run(corpus: list[dict]) -> dict:
    from sentinel.policy import PolicyEngine
    engine = PolicyEngine.default()
    pipe = engine.build_input_pipeline()

    tp = fp = fn = tn = 0
    latencies: list[float] = []

    for item in corpus:
        t0 = time.perf_counter()
        result = pipe.scan(item["text"])
        latencies.append((time.perf_counter() - t0) * 1000)

        predicted_malicious = result.action.value in ("block", "warn")
        is_malicious = item["label"] == "malicious"

        if is_malicious and predicted_malicious:
            tp += 1
        elif not is_malicious and predicted_malicious:
            fp += 1
        elif is_malicious and not predicted_malicious:
            fn += 1
        else:
            tn += 1

    total = tp + fp + fn + tn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall    = tp / (tp + fn) if (tp + fn) else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total": total,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 4),
        "recall":    round(recall, 4),
        "f1":        round(f1, 4),
        "latency_p50_ms": round(sorted(latencies)[len(latencies) // 2], 2),
        "latency_p99_ms": round(sorted(latencies)[int(len(latencies) * 0.99)], 2),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default="payloads/injection.yaml")
    ap.add_argument("--out-dir", default="benchmarks")
    args = ap.parse_args()

    corpus = _load_corpus(args.corpus)
    metrics = _run(corpus)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    out_file = out_dir / f"run_{stamp}.json"
    out_file.write_text(json.dumps(metrics, indent=2))
    print(f"Saved → {out_file}")
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
