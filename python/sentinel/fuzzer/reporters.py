"""Multi-format reporting: SARIF, JUnit XML, HTML dashboard."""

from __future__ import annotations

import json
import logging
import xml.etree.ElementTree as ET
from pathlib import Path

from .base import FuzzResult
from .scoring import DetectionScore

logger = logging.getLogger(__name__)


class SARIFReporter:
    """Generate SARIF 2.1.0 output for GitHub Security alerts."""

    SARIF_VERSION = "2.1.0"
    SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

    def generate(
        self,
        results: list[FuzzResult],
        score: DetectionScore,
        tool_name: str = "eresus-sentinel-fuzzer",
        tool_version: str = "0.1.0",
    ) -> dict:
        sarif = {
            "$schema": self.SCHEMA,
            "version": self.SARIF_VERSION,
            "runs": [{
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://eresussec.com",
                        "rules": self._build_rules(results),
                    }
                },
                "results": self._build_results(results),
                "invocations": [{
                    "executionSuccessful": True,
                    "startTimeUtc": score.timestamp,
                    "properties": {
                        "tpr": score.tpr,
                        "fpr": score.fpr,
                        "f1": score.f1,
                        "bypass_rate": score.bypass_rate,
                    },
                }],
            }],
        }
        return sarif

    def _build_rules(self, results: list[FuzzResult]) -> list[dict]:
        seen = set()
        rules = []
        for r in results:
            if r.is_bypass:
                rule_id = f"SENTINEL-BYPASS-{r.payload.category.value.upper()}"
                if rule_id not in seen:
                    seen.add(rule_id)
                    rules.append({
                        "id": rule_id,
                        "name": f"ScannerBypass_{r.payload.category.value}",
                        "shortDescription": {
                            "text": f"Scanner bypass: {r.payload.category.value}",
                        },
                        "defaultConfiguration": {
                            "level": self._severity_to_level(r.payload.severity_expected),
                        },
                    })
        return rules

    def _build_results(self, results: list[FuzzResult]) -> list[dict]:
        sarif_results = []
        for r in results:
            if not r.is_bypass:
                continue
            sarif_results.append({
                "ruleId": f"SENTINEL-BYPASS-{r.payload.category.value.upper()}",
                "level": self._severity_to_level(r.payload.severity_expected),
                "message": {
                    "text": f"Payload '{r.payload.name}' bypassed scanner detection",
                },
                "properties": {
                    "payload_name": r.payload.name,
                    "category": r.payload.category.value,
                    "tags": r.payload.tags,
                    "data_size": len(r.payload.data),
                },
            })
        return sarif_results

    @staticmethod
    def _severity_to_level(severity: str) -> str:
        mapping = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "NONE": "none",
        }
        return mapping.get(severity, "warning")

    def save(self, sarif: dict, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
        logger.info("SARIF report saved to %s", p)


class JUnitReporter:
    """Generate JUnit XML for CI/CD test frameworks."""

    def generate(
        self,
        results: list[FuzzResult],
        score: DetectionScore,
        suite_name: str = "sentinel-fuzz",
    ) -> str:
        ts = ET.Element("testsuites")

        suite = ET.SubElement(ts, "testsuite", {
            "name": suite_name,
            "tests": str(score.total_samples),
            "failures": str(score.false_negatives),
            "errors": str(score.scanner_crashes),
            "timestamp": score.timestamp,
            "time": str(round(score.total_time_ms / 1000, 3)),
        })

        # Properties
        props = ET.SubElement(suite, "properties")
        for key, val in [
            ("tpr", score.tpr), ("fpr", score.fpr),
            ("f1", score.f1), ("bypass_rate", score.bypass_rate),
            ("precision", score.precision),
        ]:
            ET.SubElement(props, "property", {
                "name": key, "value": str(round(val, 4)),
            })

        # Test cases
        for r in results:
            tc = ET.SubElement(suite, "testcase", {
                "name": r.payload.name,
                "classname": f"sentinel.fuzzer.{r.payload.category.value}",
                "time": str(round(r.detection_time_ms / 1000, 6)),
            })

            if r.is_bypass:
                fail = ET.SubElement(tc, "failure", {
                    "type": "ScannerBypass",
                    "message": f"Payload bypassed detection: {r.payload.category.value}",
                })
                fail.text = (
                    f"Payload: {r.payload.name}\n"
                    f"Category: {r.payload.category.value}\n"
                    f"Severity: {r.payload.severity_expected}\n"
                    f"Tags: {', '.join(r.payload.tags)}\n"
                    f"Size: {len(r.payload.data)} bytes"
                )

            if r.scanner_crashed:
                ET.SubElement(tc, "error", {
                    "type": "ScannerCrash",
                    "message": r.error or "Unknown crash",
                })

        tree = ET.ElementTree(ts)
        import io
        buf = io.BytesIO()
        tree.write(buf, encoding="unicode", xml_declaration=True)
        return buf.getvalue().decode("utf-8") if isinstance(buf.getvalue(), bytes) else buf.getvalue()

    def save(self, xml_content: str, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(xml_content, encoding="utf-8")
        logger.info("JUnit report saved to %s", p)


class HTMLReporter:
    """Generate HTML dashboard with category breakdown and metrics."""

    def generate(self, score: DetectionScore, results: list[FuzzResult]) -> str:
        bypasses = [r for r in results if r.is_bypass]
        [r for r in results if r.is_false_positive]
        [r for r in results if r.scanner_crashed]

        bypass_rows = "".join(
            f"<tr><td>{r.payload.name}</td><td>{r.payload.category.value}</td>"
            f"<td>{r.payload.severity_expected}</td><td>{len(r.payload.data)}</td></tr>"
            for r in bypasses
        )

        category_rows = "".join(
            f"<tr><td>{cat}</td><td>{stats.get('total', 0)}</td>"
            f"<td>{stats.get('detected', 0)}</td><td>{stats.get('bypassed', 0)}</td></tr>"
            for cat, stats in score.category_stats.items()
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Eresus Sentinel — Fuzz Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Inter',system-ui,sans-serif;background:#0a0a0f;color:#e0e0e6;padding:2rem}}
h1{{font-size:1.8rem;margin-bottom:1.5rem;background:linear-gradient(135deg,#667eea,#764ba2);-webkit-background-clip:text;-webkit-text-fill-color:transparent}}
h2{{font-size:1.2rem;margin:1.5rem 0 0.8rem;color:#a0a0b0}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;margin-bottom:2rem}}
.card{{background:#15151f;border:1px solid #2a2a3a;border-radius:12px;padding:1.2rem;text-align:center}}
.card .value{{font-size:2rem;font-weight:700;margin-bottom:0.3rem}}
.card .label{{font-size:0.85rem;color:#888}}
.good{{color:#22c55e}}.bad{{color:#ef4444}}.warn{{color:#f59e0b}}.info{{color:#3b82f6}}
table{{width:100%;border-collapse:collapse;margin:0.8rem 0}}
th,td{{padding:0.6rem 0.8rem;text-align:left;border-bottom:1px solid #1a1a2a}}
th{{color:#888;font-weight:500;font-size:0.8rem;text-transform:uppercase}}
tr:hover{{background:#1a1a28}}
.timestamp{{color:#555;font-size:0.8rem;margin-top:2rem}}
</style>
</head>
<body>
<h1>🛡️ Eresus Sentinel — Fuzz Report</h1>

<div class="grid">
<div class="card"><div class="value info">{score.total_samples}</div><div class="label">Total Samples</div></div>
<div class="card"><div class="value {'good' if score.tpr >= 0.95 else 'bad'}">{score.tpr:.1%}</div><div class="label">TPR (Recall)</div></div>
<div class="card"><div class="value {'good' if score.fpr <= 0.05 else 'warn'}">{score.fpr:.1%}</div><div class="label">FPR</div></div>
<div class="card"><div class="value info">{score.f1:.1%}</div><div class="label">F1 Score</div></div>
<div class="card"><div class="value {'good' if score.bypass_rate <= 0.05 else 'bad'}">{score.bypass_rate:.1%}</div><div class="label">Bypass Rate</div></div>
<div class="card"><div class="value {'good' if score.scanner_crashes == 0 else 'bad'}">{score.scanner_crashes}</div><div class="label">Crashes</div></div>
</div>

<h2>Category Breakdown</h2>
<table>
<thead><tr><th>Category</th><th>Total</th><th>Detected</th><th>Bypassed</th></tr></thead>
<tbody>{category_rows}</tbody>
</table>

<h2>Bypasses ({len(bypasses)})</h2>
<table>
<thead><tr><th>Payload</th><th>Category</th><th>Severity</th><th>Size</th></tr></thead>
<tbody>{bypass_rows if bypass_rows else '<tr><td colspan="4" style="color:#22c55e">No bypasses detected 🎉</td></tr>'}</tbody>
</table>

<p class="timestamp">Generated: {score.timestamp}</p>
</body>
</html>"""

    def save(self, html: str, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(html, encoding="utf-8")
        logger.info("HTML report saved to %s", p)
