#!/usr/bin/env python3
"""Eresus Sentinel — FP/FN benchmark harness.

Runs every sample in `tests/adversarial_corpus/` through the appropriate
Sentinel scanner, compares emitted rule IDs against `labels.yaml`, and
reports per-category precision / recall / F1 plus operational metrics
(parser crashes, timeouts, latency). CI-gate mode fails the build when
critical-category recall drops below a floor.

Usage:
    python scripts/benchmark_fpfn.py
    python scripts/benchmark_fpfn.py \
        --corpus tests/adversarial_corpus \
        --output benchmark_report.json \
        --summary benchmark_summary.md
    python scripts/benchmark_fpfn.py --critical-recall-floor 0.70

Exits non-zero on CI-gate violations (recall below floor) or unexpected
harness errors. A sample that crashes the scanner is counted as an FN
for malicious samples, and reported as a crash regardless.

The harness is deliberately dependency-free beyond what the repo already
uses: PyYAML is already in `pyproject.toml`. No network, no shell.
"""

from __future__ import annotations

import argparse
import json
import signal
import statistics
import sys
import time
import traceback
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

# ─────────────────────────────────────────────────────────────────────
# Path bootstrap — make `sentinel` importable without installing.
# ─────────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parent.parent
PY_SRC = REPO_ROOT / "python"
if str(PY_SRC) not in sys.path:
    sys.path.insert(0, str(PY_SRC))

# ─────────────────────────────────────────────────────────────────────
# Timeout primitive — POSIX-only (SIGALRM). On Windows the harness runs
# without timeout enforcement; the scanner's internal guards still apply.
# ─────────────────────────────────────────────────────────────────────


class _TimeoutError(Exception):
    pass


def _alarm_handler(signum, frame):  # noqa: ARG001
    raise _TimeoutError("scan exceeded timeout")


def _set_timeout(seconds: int) -> bool:
    if hasattr(signal, "SIGALRM"):
        signal.signal(signal.SIGALRM, _alarm_handler)
        signal.alarm(seconds)
        return True
    return False


def _clear_timeout() -> None:
    if hasattr(signal, "SIGALRM"):
        signal.alarm(0)


# ─────────────────────────────────────────────────────────────────────
# Result model
# ─────────────────────────────────────────────────────────────────────


@dataclass
class SampleResult:
    path: str
    module: str
    category: str
    criticality: str
    disposition: str
    expected_rule_ids: list[str]
    currently_expected: list[str]
    got_rule_ids: list[str] = field(default_factory=list)
    duration_ms: float = 0.0
    crashed: bool = False
    timed_out: bool = False
    error: str = ""

    # Scoring against expected_rule_ids ("ideal detector" goal)
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    def score(self) -> None:
        expected = set(self.expected_rule_ids)
        got = set(self.got_rule_ids)
        if self.disposition == "clean":
            # Any finding on a clean sample is a FP (unless tolerated).
            self.fp = len(got)
            self.tn = 1 if not got else 0
            self.tp = 0
            self.fn = 0
        else:
            # Malicious: we want at least one expected rule to fire.
            if expected & got:
                self.tp = 1
                self.fn = 0
            else:
                self.tp = 0
                self.fn = 1
            # Unexpected extra findings on malicious samples are NOT counted
            # as FP in this lenient mode (common in IR tool benchmarks).
            self.fp = 0
            self.tn = 0


# ─────────────────────────────────────────────────────────────────────
# Scanner dispatchers — each returns a list[str] of rule IDs.
# Kept small and defensive; any exception is caught by the caller.
# ─────────────────────────────────────────────────────────────────────


def _rule_ids_from_findings(findings: Any) -> list[str]:
    out: list[str] = []
    if not findings:
        return out
    for f in findings:
        rid = getattr(f, "rule_id", None) or (
            f.get("rule_id") if isinstance(f, dict) else None
        )
        if rid:
            out.append(str(rid))
    return out


def scan_agent_mcp(path: Path) -> list[str]:
    """Dispatch MCP JSON manifests to `MCPValidator`."""
    from sentinel.agent.mcp_validator import MCPValidator
    v = MCPValidator()
    return _rule_ids_from_findings(v.validate_file(str(path)))


def scan_agent_skill(path: Path) -> list[str]:
    """Dispatch skill manifests / helper scripts to `SkillScanner`."""
    from sentinel.agent.skill_scanner import SkillScanner
    scanner = SkillScanner()
    text = path.read_text(encoding="utf-8", errors="replace")
    findings = scanner.scan_skill(text, name=path.name)
    # SkillScanner returns SkillFinding; use `finding_type` as ID fallback.
    out = []
    for f in findings:
        rid = getattr(f, "rule_id", None)
        if rid:
            out.append(rid)
        else:
            out.append(f"SKILL-{f.finding_type.upper()}")
    return out


def scan_firewall_input(path: Path) -> list[str]:
    """Dispatch text prompts to the input firewall pipeline."""
    from sentinel.sdk import Sentinel
    s = Sentinel.default()
    text = path.read_text(encoding="utf-8", errors="replace")
    result = s.scan_input(text)
    return _rule_ids_from_findings(result.findings)


def scan_artifact(path: Path) -> list[str]:
    """Dispatch binary artifacts to the artifact analyzer."""
    from sentinel.sdk import Sentinel
    s = Sentinel.default()
    findings = s.scan_artifact(str(path))
    return _rule_ids_from_findings(findings)


DISPATCH = {
    "agent": scan_agent_mcp,      # default agent dispatch = MCP validator
    "firewall_input": scan_firewall_input,
    "artifact": scan_artifact,
}


def dispatch_for_sample(rel_path: str, module: str, category: str) -> list[str]:
    """Route a sample to the correct scanner.

    Skill-category samples are routed to the skill scanner instead of
    the MCP validator.
    """
    full = REPO_ROOT / "tests" / "adversarial_corpus" / rel_path
    if module == "agent" and category == "skill":
        return scan_agent_skill(full)
    fn = DISPATCH.get(module)
    if fn is None:
        raise RuntimeError(f"no dispatcher for module={module}")
    return fn(full)


# ─────────────────────────────────────────────────────────────────────
# Harness
# ─────────────────────────────────────────────────────────────────────


def load_labels(corpus_dir: Path) -> dict[str, dict]:
    labels_path = corpus_dir / "labels.yaml"
    with open(labels_path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    return raw


def run_sample(rel_path: str, meta: dict, timeout: int) -> SampleResult:
    result = SampleResult(
        path=rel_path,
        module=meta.get("module", ""),
        category=meta.get("category", ""),
        criticality=meta.get("criticality", "normal"),
        disposition=meta.get("disposition", "malicious"),
        expected_rule_ids=list(meta.get("expected_rule_ids") or []),
        currently_expected=list(meta.get("currently_expected") or []),
    )

    start = time.perf_counter()
    had_alarm = _set_timeout(timeout)
    try:
        rule_ids = dispatch_for_sample(rel_path, result.module, result.category)
        result.got_rule_ids = rule_ids
    except _TimeoutError:
        result.timed_out = True
        result.error = f"timeout after {timeout}s"
    except Exception as e:  # noqa: BLE001
        result.crashed = True
        result.error = f"{type(e).__name__}: {e}"
    finally:
        if had_alarm:
            _clear_timeout()
        result.duration_ms = (time.perf_counter() - start) * 1000

    result.score()
    return result


# ─────────────────────────────────────────────────────────────────────
# Aggregation
# ─────────────────────────────────────────────────────────────────────


def aggregate(results: list[SampleResult]) -> dict[str, Any]:
    def pr_f1(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall)
            else 0.0
        )
        return round(precision, 4), round(recall, 4), round(f1, 4)

    agg: dict[str, Any] = {
        "total_samples": len(results),
        "crashes": sum(1 for r in results if r.crashed),
        "timeouts": sum(1 for r in results if r.timed_out),
    }

    # Overall
    tp = sum(r.tp for r in results)
    fp = sum(r.fp for r in results)
    fn = sum(r.fn for r in results)
    tn = sum(r.tn for r in results)
    p, rec, f1 = pr_f1(tp, fp, fn)
    agg["overall"] = {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": p, "recall": rec, "f1": f1,
    }

    # Per-category
    cats: dict[str, dict[str, int]] = {}
    for r in results:
        c = r.category or "uncategorized"
        d = cats.setdefault(c, {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "n": 0})
        d["tp"] += r.tp
        d["fp"] += r.fp
        d["tn"] += r.tn
        d["fn"] += r.fn
        d["n"] += 1
    per_cat = {}
    for c, d in cats.items():
        p2, r2, f2 = pr_f1(d["tp"], d["fp"], d["fn"])
        per_cat[c] = {
            **d, "precision": p2, "recall": r2, "f1": f2,
        }
    agg["per_category"] = per_cat

    # Critical subset
    crit = [r for r in results if r.criticality == "critical"]
    ctp = sum(r.tp for r in crit)
    cfp = sum(r.fp for r in crit)
    cfn = sum(r.fn for r in crit)
    cp, crr, cf1 = pr_f1(ctp, cfp, cfn)
    agg["critical"] = {
        "n": len(crit), "tp": ctp, "fp": cfp, "fn": cfn,
        "precision": cp, "recall": crr, "f1": cf1,
    }

    # Latency
    durs = [r.duration_ms for r in results if not r.crashed]
    if durs:
        agg["latency_ms"] = {
            "p50": round(statistics.median(durs), 2),
            "p95": round(sorted(durs)[int(len(durs) * 0.95) - 1], 2) if len(durs) > 1 else round(durs[0], 2),
            "max": round(max(durs), 2),
        }
    else:
        agg["latency_ms"] = {"p50": 0, "p95": 0, "max": 0}

    return agg


# ─────────────────────────────────────────────────────────────────────
# Reporting
# ─────────────────────────────────────────────────────────────────────


def render_summary(results: list[SampleResult], agg: dict[str, Any]) -> str:
    lines = []
    lines.append("# Eresus Sentinel — FP/FN Benchmark Summary\n")
    lines.append(f"- samples: {agg['total_samples']}")
    lines.append(f"- crashes: {agg['crashes']}")
    lines.append(f"- timeouts: {agg['timeouts']}")
    lines.append(f"- latency p50/p95/max (ms): "
                 f"{agg['latency_ms']['p50']} / {agg['latency_ms']['p95']} / {agg['latency_ms']['max']}")
    lines.append("")
    lines.append("## Overall")
    o = agg["overall"]
    lines.append(f"- TP={o['tp']} FP={o['fp']} TN={o['tn']} FN={o['fn']}")
    lines.append(f"- precision={o['precision']} recall={o['recall']} f1={o['f1']}")
    lines.append("")
    lines.append("## Critical subset")
    c = agg["critical"]
    lines.append(f"- n={c['n']} TP={c['tp']} FP={c['fp']} FN={c['fn']}")
    lines.append(f"- precision={c['precision']} recall={c['recall']} f1={c['f1']}")
    lines.append("")
    lines.append("## Per category")
    lines.append("| category | n | tp | fp | fn | precision | recall | f1 |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for cat, d in sorted(agg["per_category"].items()):
        lines.append(
            f"| {cat} | {d['n']} | {d['tp']} | {d['fp']} | {d['fn']} | "
            f"{d['precision']} | {d['recall']} | {d['f1']} |"
        )
    lines.append("")
    lines.append("## Blind spots (expected detections that did NOT fire)")
    gaps = [r for r in results if r.disposition == "malicious"
            and r.expected_rule_ids
            and not (set(r.expected_rule_ids) & set(r.got_rule_ids))]
    if gaps:
        lines.append("| sample | expected | got | crashed? | error |")
        lines.append("|---|---|---|---|---|")
        for r in gaps:
            err = r.error.replace("|", "\\|") if r.error else ""
            lines.append(
                f"| `{r.path}` | {','.join(r.expected_rule_ids)} | "
                f"{','.join(r.got_rule_ids) or '—'} | "
                f"{'yes' if r.crashed else ('timeout' if r.timed_out else 'no')} | {err} |"
            )
    else:
        lines.append("_(none)_")
    lines.append("")
    lines.append("## False positives on clean samples")
    fps = [r for r in results if r.disposition == "clean" and r.got_rule_ids]
    if fps:
        lines.append("| sample | emitted |")
        lines.append("|---|---|")
        for r in fps:
            lines.append(f"| `{r.path}` | {','.join(r.got_rule_ids)} |")
    else:
        lines.append("_(none)_")
    return "\n".join(lines) + "\n"


# ─────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", default="tests/adversarial_corpus",
                    help="path to adversarial corpus (default: tests/adversarial_corpus)")
    ap.add_argument("--output", default="benchmark_report.json",
                    help="JSON output file (default: benchmark_report.json)")
    ap.add_argument("--summary", default="benchmark_summary.md",
                    help="Markdown summary output (default: benchmark_summary.md)")
    ap.add_argument("--timeout", type=int, default=30,
                    help="per-sample timeout seconds (default: 30)")
    ap.add_argument("--critical-recall-floor", type=float, default=0.0,
                    help="CI-gate: fail if critical-category recall below this floor (default: 0.0)")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="print each sample result to stderr")
    args = ap.parse_args()

    corpus = (REPO_ROOT / args.corpus).resolve() if not Path(args.corpus).is_absolute() else Path(args.corpus)
    if not corpus.is_dir():
        print(f"corpus not found: {corpus}", file=sys.stderr)
        return 2

    labels = load_labels(corpus)
    if not labels:
        print("no labels loaded", file=sys.stderr)
        return 2

    results: list[SampleResult] = []
    for rel_path, meta in labels.items():
        abs_path = corpus / rel_path
        if not abs_path.exists():
            if args.verbose:
                print(f"skip missing sample: {rel_path}", file=sys.stderr)
            continue
        r = run_sample(rel_path, meta, args.timeout)
        results.append(r)
        if args.verbose:
            status = "CRASH" if r.crashed else ("TO" if r.timed_out else "OK")
            print(f"[{status:5}] {rel_path:60} {r.duration_ms:7.1f}ms "
                  f"got={r.got_rule_ids}", file=sys.stderr)

    agg = aggregate(results)

    # Write JSON report
    report = {
        "samples": [asdict(r) for r in results],
        "aggregate": agg,
    }
    Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")

    # Write Markdown summary
    Path(args.summary).write_text(render_summary(results, agg), encoding="utf-8")

    # Console summary
    print(render_summary(results, agg))

    # CI gate
    crit_recall = agg["critical"]["recall"]
    if args.critical_recall_floor > 0 and crit_recall < args.critical_recall_floor:
        print(
            f"FAIL: critical recall {crit_recall} below floor "
            f"{args.critical_recall_floor}",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        sys.exit(130)
    except Exception as e:  # noqa: BLE001
        print(f"harness error: {type(e).__name__}: {e}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(2)
