"""CSV AIBOM reporter."""
from __future__ import annotations

import csv
import io

from sentinel.aibom.models import AIBOMResult
from sentinel.aibom.reporters.base import BaseAIBOMReporter


class CSVReporter(BaseAIBOMReporter):
    name = "csv"
    extension = "csv"

    def render(self, result: AIBOMResult) -> str:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["type", "name", "version", "path", "description", "evidence", "risks"])
        for c in result.components:
            writer.writerow([
                c.type.value,
                c.name,
                c.version,
                c.path,
                c.description,
                "; ".join(c.evidence),
                "; ".join(c.risks),
            ])
        return buf.getvalue()
