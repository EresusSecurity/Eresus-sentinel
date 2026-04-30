"""CSV report generator for Sentinel findings."""
from __future__ import annotations

import csv
import io
from typing import Any

from sentinel.reporters.base import BaseReporter

_COLUMNS = ["rule_id", "severity", "title", "target", "description", "module", "confidence"]


def _sev(f) -> str:
    return str(getattr(getattr(f, "severity", None), "value", getattr(f, "severity", "info"))).lower()


class CsvReporter(BaseReporter):
    """Generate RFC 4180 CSV from Sentinel findings."""

    def generate(self, findings: list, metadata: dict[str, Any] | None = None) -> str:
        buf = io.StringIO()
        writer = csv.DictWriter(
            buf,
            fieldnames=_COLUMNS,
            extrasaction="ignore",
            lineterminator="\r\n",
        )
        writer.writeheader()
        for f in findings:
            row = {
                "rule_id": str(getattr(f, "rule_id", "")),
                "severity": _sev(f).upper(),
                "title": str(getattr(f, "title", "")),
                "target": str(getattr(f, "target", "")),
                "description": str(getattr(f, "description", "")),
                "module": str(getattr(getattr(f, "module", None), "value", getattr(f, "module", ""))),
                "confidence": str(getattr(f, "confidence", "")),
            }
            writer.writerow(row)
        return buf.getvalue()
