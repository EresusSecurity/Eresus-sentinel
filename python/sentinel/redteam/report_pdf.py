"""PDF Report Exporter for Red Team results.

Converts redteam scan results, comparison reports, and evaluation histories
into professional PDF reports.

Backend priority:
  1. ReportLab (pip install reportlab) — full featured, recommended
  2. WeasyPrint (pip install weasyprint) — HTML-to-PDF, good styling
  3. Markdown + plain text fallback — always available

Usage::

    from sentinel.redteam.report_pdf import RedTeamPDFExporter

    # From a ComparisonReport
    exporter = RedTeamPDFExporter()
    exporter.from_comparison(report, output_path="report.pdf")

    # From raw results dict
    exporter.from_dict({"title": "Scan", "results": [...]}, output_path="scan.pdf")

    # From redteam JSON output file
    exporter.from_json_file("redteam_results.json", output_path="report.pdf")
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ── ReportLab backend ─────────────────────────────────────────────────────

def _export_reportlab(data: dict, output_path: str) -> bool:
    try:
        from reportlab.lib import colors  # type: ignore[import]
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            HRFlowable, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
        )

        doc = SimpleDocTemplate(output_path, pagesize=A4, rightMargin=2*cm, leftMargin=2*cm,
                                topMargin=2*cm, bottomMargin=2*cm)
        styles = getSampleStyleSheet()
        story = []

        BRAND_RED = colors.HexColor("#C41E3A")
        BRAND_DARK = colors.HexColor("#1A1A2E")

        title_style = ParagraphStyle("Title", parent=styles["Title"],
                                     textColor=BRAND_DARK, fontSize=24, spaceAfter=6)
        h1_style = ParagraphStyle("H1", parent=styles["Heading1"],
                                  textColor=BRAND_RED, fontSize=14, spaceAfter=4)
        h2_style = ParagraphStyle("H2", parent=styles["Heading2"],
                                  textColor=BRAND_DARK, fontSize=11, spaceAfter=3)
        body_style = ParagraphStyle("Body", parent=styles["Normal"],
                                    fontSize=9, spaceAfter=2, leading=13)
        code_style = ParagraphStyle("Code", parent=styles["Code"],
                                    fontSize=7.5, fontName="Courier", spaceAfter=3,
                                    backColor=colors.HexColor("#F5F5F5"))

        title = data.get("title", "Red Team Report")
        generated_at = data.get("generated_at", datetime.now().isoformat())
        story.append(Paragraph(title, title_style))
        story.append(Paragraph(f"Generated: {generated_at}", body_style))
        story.append(HRFlowable(width="100%", thickness=2, color=BRAND_RED))
        story.append(Spacer(1, 0.3*cm))

        if "summary" in data:
            story.append(Paragraph("Executive Summary", h1_style))
            story.append(Paragraph(str(data["summary"]), body_style))
            story.append(Spacer(1, 0.2*cm))

        if "models" in data:
            story.append(Paragraph("Models Tested", h1_style))
            story.append(Paragraph(", ".join(data["models"]), body_style))
            story.append(Spacer(1, 0.2*cm))

        if "asr_table" in data:
            story.append(Paragraph("Attack Success Rates", h1_style))
            table_data = [["Model", "Probe", "ASR", "Probes Run", "Succeeded"]]
            for row in data["asr_table"]:
                table_data.append([
                    str(row.get("model", "")),
                    str(row.get("probe", "")),
                    f"{row.get('asr', 0):.1%}",
                    str(row.get("probes_run", 0)),
                    str(row.get("succeeded", 0)),
                ])
            t = Table(table_data, repeatRows=1)
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), BRAND_RED),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8F8F8")]),
                ("ALIGN", (2, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(t)
            story.append(Spacer(1, 0.3*cm))

        if "findings" in data:
            story.append(Paragraph("Detailed Findings", h1_style))
            for i, finding in enumerate(data["findings"], 1):
                story.append(Paragraph(f"{i}. {finding.get('title', 'Finding')}", h2_style))
                if "description" in finding:
                    story.append(Paragraph(finding["description"], body_style))
                if "prompt" in finding:
                    story.append(Paragraph("<b>Prompt:</b>", body_style))
                    story.append(Paragraph(finding["prompt"][:400], code_style))
                if "response" in finding:
                    story.append(Paragraph("<b>Response:</b>", body_style))
                    story.append(Paragraph(finding["response"][:400], code_style))
                story.append(Spacer(1, 0.2*cm))

        if "recommendations" in data:
            story.append(Paragraph("Recommendations", h1_style))
            for rec in data["recommendations"]:
                story.append(Paragraph(f"• {rec}", body_style))

        story.append(Spacer(1, 0.5*cm))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
        story.append(Paragraph("Generated by Eresus Sentinel — AI Security Platform", body_style))

        doc.build(story)
        return True
    except ImportError:
        return False
    except Exception as exc:
        logger.error("ReportLab export failed: %s", exc)
        return False


# ── WeasyPrint backend ─────────────────────────────────────────────────────

def _export_weasyprint(data: dict, output_path: str) -> bool:
    try:
        from weasyprint import HTML  # type: ignore[import]

        title = data.get("title", "Red Team Report")
        generated_at = data.get("generated_at", datetime.now().isoformat())

        html_parts = [f"""<!DOCTYPE html><html><head>
<meta charset="utf-8">
<style>
  body {{font-family: Arial, sans-serif; font-size: 11px; margin: 2cm; color: #1A1A2E;}}
  h1 {{color: #C41E3A; border-bottom: 2px solid #C41E3A; padding-bottom: 4px;}}
  h2 {{color: #1A1A2E;}}
  table {{border-collapse: collapse; width: 100%; margin: 10px 0;}}
  th {{background: #C41E3A; color: white; padding: 6px; text-align: left;}}
  td {{border: 1px solid #ddd; padding: 5px;}}
  tr:nth-child(even) {{background: #f8f8f8;}}
  pre {{background: #f5f5f5; padding: 8px; font-size: 9px; overflow-wrap: break-word; white-space: pre-wrap;}}
  .footer {{color: #888; font-size: 9px; margin-top: 20px; border-top: 1px solid #ddd; padding-top: 8px;}}
</style></head><body>
<h1>{title}</h1>
<p>Generated: {generated_at}</p>"""]

        if "summary" in data:
            html_parts.append(f"<h1>Executive Summary</h1><p>{data['summary']}</p>")

        if "models" in data:
            html_parts.append(f"<h1>Models Tested</h1><p>{', '.join(data['models'])}</p>")

        if "asr_table" in data:
            html_parts.append("<h1>Attack Success Rates</h1><table>")
            html_parts.append("<tr><th>Model</th><th>Probe</th><th>ASR</th><th>Probes Run</th><th>Succeeded</th></tr>")
            for row in data["asr_table"]:
                asr = row.get("asr", 0)
                html_parts.append(
                    f"<tr><td>{row.get('model','')}</td><td>{row.get('probe','')}</td>"
                    f"<td>{asr:.1%}</td><td>{row.get('probes_run',0)}</td><td>{row.get('succeeded',0)}</td></tr>"
                )
            html_parts.append("</table>")

        if "findings" in data:
            html_parts.append("<h1>Detailed Findings</h1>")
            for i, finding in enumerate(data["findings"], 1):
                html_parts.append(f"<h2>{i}. {finding.get('title', 'Finding')}</h2>")
                if "description" in finding:
                    html_parts.append(f"<p>{finding['description']}</p>")
                if "prompt" in finding:
                    html_parts.append(f"<p><b>Prompt:</b></p><pre>{finding['prompt'][:400]}</pre>")
                if "response" in finding:
                    html_parts.append(f"<p><b>Response:</b></p><pre>{finding['response'][:400]}</pre>")

        if "recommendations" in data:
            html_parts.append("<h1>Recommendations</h1><ul>")
            for rec in data["recommendations"]:
                html_parts.append(f"<li>{rec}</li>")
            html_parts.append("</ul>")

        html_parts.append('<p class="footer">Generated by Eresus Sentinel — AI Security Platform</p></body></html>')
        html_str = "\n".join(html_parts)
        HTML(string=html_str).write_pdf(output_path)
        return True
    except ImportError:
        return False
    except Exception as exc:
        logger.error("WeasyPrint export failed: %s", exc)
        return False


# ── Markdown/text fallback ────────────────────────────────────────────────

def _export_markdown(data: dict, output_path: str) -> bool:
    """Always-available fallback: writes a .md file alongside the PDF path."""
    md_path = str(output_path).replace(".pdf", ".md")
    lines = [f"# {data.get('title', 'Red Team Report')}", "",
             f"Generated: {data.get('generated_at', datetime.now().isoformat())}", ""]
    if "summary" in data:
        lines += ["## Executive Summary", "", str(data["summary"]), ""]
    if "models" in data:
        lines += ["## Models Tested", "", ", ".join(data["models"]), ""]
    if "asr_table" in data:
        lines += ["## Attack Success Rates", "", "| Model | Probe | ASR | Probes | Succeeded |",
                  "|---|---|---|---|---|"]
        for row in data["asr_table"]:
            lines.append(f"| {row.get('model','')} | {row.get('probe','')} | "
                         f"{row.get('asr',0):.1%} | {row.get('probes_run',0)} | {row.get('succeeded',0)} |")
        lines.append("")
    if "findings" in data:
        lines += ["## Findings", ""]
        for i, f in enumerate(data["findings"], 1):
            lines.append(f"### {i}. {f.get('title','Finding')}")
            if "description" in f:
                lines.append(f["description"])
    try:
        Path(md_path).write_text("\n".join(lines), encoding="utf-8")
        logger.info("Markdown fallback written to %s", md_path)
        return True
    except Exception:
        return False


# ── Main exporter class ───────────────────────────────────────────────────

class RedTeamPDFExporter:
    """Export red team results to PDF.

    Args:
        backend: 'auto' | 'reportlab' | 'weasyprint' | 'markdown'
    """

    def __init__(self, backend: str = "auto") -> None:
        self._backend = backend

    def export(self, data: dict, output_path: str) -> str:
        """Export data dict to PDF. Returns the path written."""
        data.setdefault("generated_at", datetime.now().isoformat())
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        backends = (
            [self._backend] if self._backend != "auto"
            else ["reportlab", "weasyprint"]
        )

        for backend in backends:
            if backend == "reportlab":
                if _export_reportlab(data, output_path):
                    logger.info("PDF written via ReportLab: %s", output_path)
                    return output_path
            elif backend == "weasyprint":
                if _export_weasyprint(data, output_path):
                    logger.info("PDF written via WeasyPrint: %s", output_path)
                    return output_path
            elif backend == "markdown":
                _export_markdown(data, output_path)
                return output_path.replace(".pdf", ".md")

        logger.warning(
            "No PDF backend available (install reportlab or weasyprint). "
            "Falling back to Markdown."
        )
        _export_markdown(data, output_path)
        return output_path.replace(".pdf", ".md")

    def from_comparison(self, report: Any, output_path: str) -> str:
        """Export a ComparisonReport to PDF."""
        data: dict[str, Any] = {
            "title": "Red Team Multi-Model Comparison Report",
            "summary": (
                f"Compared {len(getattr(report, 'model_names', []))} models "
                f"against {len(getattr(report, 'probe_names', []))} probes."
            ),
            "models": getattr(report, "model_names", []),
        }

        asr_table = []
        for model_name, probe_results in getattr(report, "results_by_model", {}).items():
            for probe_name, result in probe_results.items():
                asr_table.append({
                    "model": model_name,
                    "probe": probe_name,
                    "asr": getattr(result, "attack_success_rate", 0),
                    "probes_run": getattr(result, "total_attempts", 0),
                    "succeeded": getattr(result, "successful_attacks", 0),
                })
        data["asr_table"] = asr_table

        return self.export(data, output_path)

    def from_dict(self, data: dict, output_path: str) -> str:
        """Export arbitrary dict to PDF."""
        return self.export(data, output_path)

    def from_json_file(self, json_path: str, output_path: str) -> str:
        """Load JSON file and export to PDF."""
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)
        return self.export(data, output_path)
