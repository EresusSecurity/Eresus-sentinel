"""
PDF reporter for AIBOM results.

Uses `fpdf2` (lightweight, zero LaTeX dependency).
Falls back to plain-text with a clear install message if fpdf2 is absent.

Install:  pip install fpdf2
"""
from __future__ import annotations

import io
from datetime import datetime, timezone

from sentinel.aibom.models import AIBOMResult
from sentinel.aibom.reporters.base import BaseAIBOMReporter


class PDFReporter(BaseAIBOMReporter):
    name = "pdf"
    extension = "pdf"

    def render(self, result: AIBOMResult) -> str:
        """Return PDF bytes encoded as latin-1 string (for file writing)."""
        try:
            from fpdf import FPDF  # type: ignore[import]
        except ImportError:
            raise ImportError(
                "fpdf2 is required for PDF export. "
                "Install with: pip install fpdf2"
            )
        pdf = _build_pdf(result)
        buf = io.BytesIO()
        pdf.output(buf)
        return buf.getvalue().decode("latin-1")

    def render_bytes(self, result: AIBOMResult) -> bytes:
        """Return raw PDF bytes."""
        try:
            from fpdf import FPDF  # noqa: F401
        except ImportError:
            raise ImportError("pip install fpdf2")
        return _build_pdf(result).output()


# ── Internal builder ───────────────────────────────────────────

def _build_pdf(result: AIBOMResult):
    from fpdf import FPDF

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # ── Title ──
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 12, "AI Bill of Materials", ln=True)

    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, f"Generated: {datetime.now(timezone.utc).isoformat()}", ln=True)
    pdf.cell(0, 6, f"Components: {len(result.components)}", ln=True)
    pdf.ln(4)

    # ── Component table ──
    _table_header(pdf)
    for c in result.components:
        _table_row(pdf, c)

    # ── Compliance summary ──
    compliance = result.metadata.get("compliance", {})
    if compliance:
        pdf.ln(6)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Compliance Summary", ln=True)
        pdf.set_font("Helvetica", "", 9)
        for framework, status in compliance.items():
            passed = status.get("passed", 0)
            total  = status.get("total", 0)
            pdf.cell(0, 6, f"  {framework}: {passed}/{total} rules passed", ln=True)

    return pdf


def _table_header(pdf):
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_fill_color(230, 230, 230)
    pdf.cell(60, 7, "Name", border=1, fill=True)
    pdf.cell(35, 7, "Type", border=1, fill=True)
    pdf.cell(25, 7, "Version", border=1, fill=True)
    pdf.cell(70, 7, "Source", border=1, fill=True, ln=True)


def _table_row(pdf, c):
    pdf.set_font("Helvetica", "", 8)
    name    = (c.name or "")[:40]
    ctype   = (c.type.value if c.type else "")[:20]
    version = (c.version or "")[:15]
    path    = (c.path or "")[:50]
    pdf.cell(60, 6, name,    border=1)
    pdf.cell(35, 6, ctype,   border=1)
    pdf.cell(25, 6, version, border=1)
    pdf.cell(70, 6, path,    border=1, ln=True)
