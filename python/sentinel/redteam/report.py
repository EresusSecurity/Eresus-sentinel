"""
Eresus Sentinel — Red Team Report Generator.

Generates structured reports from harness results in multiple formats:
  - JSON (machine-readable)
  - JSONL (streaming)
  - HTML (visual dashboard)
  - Markdown (documentation)
  - SARIF (security tools integration)

Features:
  - Full HTML dashboard with charts
  - SARIF output for CI/CD integration
  - Executive summary generation
  - Severity classification
  - Trend comparison (vs previous runs)
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generate reports from harness results.

    Usage:
        from sentinel.redteam.report import ReportGenerator

        reporter = ReportGenerator(result)
        reporter.save_json("report.json")
        reporter.save_html("report.html")
        reporter.save_markdown("report.md")
        reporter.save_sarif("report.sarif")
    """

    SEVERITY_THRESHOLDS = {
        "CRITICAL": 0.3,
        "HIGH": 0.5,
        "MEDIUM": 0.7,
        "LOW": 0.9,
        "PASS": 1.0,
    }

    def __init__(self, result):
        self.result = result

    def severity(self, pass_rate: float) -> str:
        """Map pass rate to severity level."""
        for level, threshold in self.SEVERITY_THRESHOLDS.items():
            if pass_rate <= threshold:
                return level
        return "PASS"

    def executive_summary(self) -> str:
        """Generate executive summary."""
        r = self.result
        overall_sev = self.severity(r.pass_rate)

        lines = [
            f"# Eresus Sentinel — Security Assessment Report",
            f"",
            f"**Target:** {r.target_provider}/{r.target_model}",
            f"**Run ID:** {r.run_id}",
            f"**Date:** {r.start_time[:10]}",
            f"**Duration:** {r.duration_seconds:.1f}s",
            f"",
            f"## Overall Result: {overall_sev}",
            f"",
            f"- **Pass Rate:** {r.pass_rate:.1%}",
            f"- **Total Probes:** {r.total_probes}",
            f"- **Total Attempts:** {r.total_attempts}",
            f"- **Failures:** {r.total_failures}",
            f"",
        ]

        # Category breakdown
        if r.category_scores:
            lines.append("## Category Breakdown")
            lines.append("")
            lines.append("| Category | Pass Rate | Severity |")
            lines.append("|----------|-----------|----------|")
            for cat, score in sorted(r.category_scores.items(), key=lambda x: x[1]):
                sev = self.severity(score)
                icon = "🔴" if sev in ("CRITICAL", "HIGH") else "🟡" if sev == "MEDIUM" else "🟢"
                lines.append(f"| {cat} | {score:.1%} | {icon} {sev} |")
            lines.append("")

        # Top failures
        failed = [a for a in r.attempts if a.is_failure]
        if failed:
            lines.append(f"## Top Failures ({len(failed)} total)")
            lines.append("")
            for attempt in failed[:20]:
                lines.append(f"### [{attempt.probe_name}] {attempt.probe_category}")
                lines.append(f"- **Prompt:** `{attempt.original_prompt[:100]}...`")
                if attempt.mutated_prompt != attempt.original_prompt:
                    lines.append(f"- **Mutated:** `{attempt.mutated_prompt[:100]}...`")
                    lines.append(f"- **Buffs:** {', '.join(attempt.buffs_applied)}")
                lines.append(f"- **Response:** `{attempt.response_text[:200]}...`")
                lines.append(f"- **Detectors:** {', '.join(attempt.failure_categories)}")
                lines.append("")

        return "\n".join(lines)

    def save_json(self, path: str) -> str:
        """Save full report as JSON."""
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.result.as_json())
        logger.info("JSON report saved: %s", path)
        return path

    def save_jsonl(self, path: str) -> str:
        """Save attempts as JSONL (one per line)."""
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            for attempt in self.result.attempts:
                f.write(attempt.as_json() + "\n")
        logger.info("JSONL report saved: %s (%d attempts)", path, len(self.result.attempts))
        return path

    def save_markdown(self, path: str) -> str:
        """Save report as Markdown."""
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.executive_summary())
        logger.info("Markdown report saved: %s", path)
        return path

    def save_html(self, path: str) -> str:
        """Save report as interactive HTML dashboard."""
        r = self.result
        overall_sev = self.severity(r.pass_rate)
        sev_color = {
            "CRITICAL": "#dc2626", "HIGH": "#ea580c",
            "MEDIUM": "#ca8a04", "LOW": "#65a30d", "PASS": "#16a34a",
        }

        # Build category chart data
        cat_labels = json.dumps(list(r.category_scores.keys()))
        cat_values = json.dumps([round(v * 100, 1) for v in r.category_scores.values()])
        cat_colors = json.dumps([
            sev_color.get(self.severity(v), "#6b7280")
            for v in r.category_scores.values()
        ])

        # Build probe chart data
        probe_labels = json.dumps(list(r.probe_scores.keys()))
        probe_values = json.dumps([round(v * 100, 1) for v in r.probe_scores.values()])

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Eresus Sentinel — Security Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
  :root {{ --bg: #0a0a0f; --surface: #111118; --border: #1e1e2e; --text: #e4e4ef; --muted: #6b7280; }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'Inter', -apple-system, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
  .header {{ text-align: center; padding: 3rem 0; }}
  .header h1 {{ font-size: 2rem; background: linear-gradient(135deg, #6366f1, #a855f7); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
  .header .meta {{ color: var(--muted); margin-top: 0.5rem; font-size: 0.9rem; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.5rem; margin: 2rem 0; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; }}
  .card .label {{ color: var(--muted); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }}
  .card .value {{ font-size: 2rem; font-weight: 700; margin-top: 0.25rem; }}
  .severity {{ display: inline-block; padding: 0.25rem 0.75rem; border-radius: 6px; font-weight: 600; font-size: 0.85rem; }}
  .chart-container {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; margin: 2rem 0; }}
  .chart-wrapper {{ height: 300px; position: relative; }}
  h2 {{ font-size: 1.3rem; margin-bottom: 1rem; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th, td {{ padding: 0.75rem; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.9rem; }}
  th {{ color: var(--muted); font-weight: 500; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; }}
  .failure-row {{ background: rgba(220, 38, 38, 0.05); }}
  .truncate {{ max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .badge {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>🛡️ Eresus Sentinel — Security Assessment</h1>
    <div class="meta">{r.target_provider}/{r.target_model} · {r.start_time[:10]} · Run {r.run_id}</div>
  </div>

  <div class="grid">
    <div class="card">
      <div class="label">Overall Severity</div>
      <div class="value" style="color: {sev_color.get(overall_sev, '#fff')}">{overall_sev}</div>
    </div>
    <div class="card">
      <div class="label">Pass Rate</div>
      <div class="value">{r.pass_rate:.1%}</div>
    </div>
    <div class="card">
      <div class="label">Total Attempts</div>
      <div class="value">{r.total_attempts}</div>
    </div>
    <div class="card">
      <div class="label">Failures</div>
      <div class="value" style="color: #dc2626">{r.total_failures}</div>
    </div>
    <div class="card">
      <div class="label">Duration</div>
      <div class="value">{r.duration_seconds:.1f}s</div>
    </div>
    <div class="card">
      <div class="label">Tokens Used</div>
      <div class="value">{r.generator_usage.get('total_tokens', 0):,}</div>
    </div>
  </div>

  <div class="chart-container">
    <h2>Category Pass Rates</h2>
    <div class="chart-wrapper"><canvas id="catChart"></canvas></div>
  </div>

  <div class="chart-container">
    <h2>Probe Pass Rates</h2>
    <div class="chart-wrapper"><canvas id="probeChart"></canvas></div>
  </div>

  <div class="chart-container">
    <h2>Failure Details ({r.total_failures} failures)</h2>
    <table>
      <thead><tr><th>Probe</th><th>Category</th><th>Prompt</th><th>Detectors</th><th>Buffs</th></tr></thead>
      <tbody>
"""
        for a in r.attempts:
            if a.is_failure:
                buffs_str = ", ".join(a.buffs_applied) if a.buffs_applied else "—"
                dets_str = ", ".join(a.failure_categories) if a.failure_categories else "—"
                prompt_short = a.original_prompt[:80].replace("<", "&lt;").replace(">", "&gt;")
                html += f'        <tr class="failure-row"><td>{a.probe_name}</td><td>{a.probe_category}</td><td class="truncate">{prompt_short}</td><td>{dets_str}</td><td>{buffs_str}</td></tr>\n'

        html += f"""
      </tbody>
    </table>
  </div>
</div>

<script>
Chart.defaults.color = '#6b7280';
Chart.defaults.borderColor = '#1e1e2e';

new Chart(document.getElementById('catChart'), {{
  type: 'bar',
  data: {{
    labels: {cat_labels},
    datasets: [{{ label: 'Pass Rate %', data: {cat_values}, backgroundColor: {cat_colors}, borderRadius: 6 }}]
  }},
  options: {{ responsive: true, maintainAspectRatio: false, scales: {{ y: {{ max: 100, beginAtZero: true }} }} }}
}});

new Chart(document.getElementById('probeChart'), {{
  type: 'bar',
  data: {{
    labels: {probe_labels},
    datasets: [{{ label: 'Pass Rate %', data: {probe_values}, backgroundColor: '#6366f1', borderRadius: 6 }}]
  }},
  options: {{ responsive: true, maintainAspectRatio: false, indexAxis: 'y', scales: {{ x: {{ max: 100, beginAtZero: true }} }} }}
}});
</script>
</body>
</html>"""

        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        logger.info("HTML report saved: %s", path)
        return path

    def save_sarif(self, path: str) -> str:
        """Save report as SARIF 2.1.0 for CI/CD integration."""
        r = self.result
        rules = []
        results = []

        # Build rule entries from probe categories
        rule_ids = set()
        for attempt in r.attempts:
            if attempt.is_failure:
                rule_id = f"sentinel/{attempt.probe_category}/{attempt.probe_name}"
                if rule_id not in rule_ids:
                    rule_ids.add(rule_id)
                    sev = self.severity(r.probe_scores.get(attempt.probe_name, 1.0))
                    sarif_level = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}.get(sev, "note")
                    rules.append({
                        "id": rule_id,
                        "shortDescription": {"text": f"[{attempt.probe_category}] {attempt.probe_name}"},
                        "defaultConfiguration": {"level": sarif_level},
                    })

                results.append({
                    "ruleId": rule_id,
                    "message": {"text": f"Probe '{attempt.probe_name}' detected unsafe response. Detectors: {', '.join(attempt.failure_categories)}"},
                    "properties": {
                        "attempt_id": attempt.id,
                        "prompt_preview": attempt.original_prompt[:200],
                        "response_preview": attempt.response_text[:200],
                        "buffs": attempt.buffs_applied,
                    },
                })

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Eresus Sentinel",
                        "version": "0.1.0",
                        "informationUri": "https://eresussec.com",
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [{
                    "executionSuccessful": True,
                    "startTimeUtc": r.start_time,
                    "endTimeUtc": r.end_time,
                    "properties": {
                        "target_model": r.target_model,
                        "target_provider": r.target_provider,
                        "pass_rate": r.pass_rate,
                        "total_attempts": r.total_attempts,
                    },
                }],
            }],
        }

        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2, ensure_ascii=False)
        logger.info("SARIF report saved: %s (%d findings)", path, len(results))
        return path
