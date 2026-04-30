"""SARIF reporter for AIBOM findings (risks surface as results)."""
from __future__ import annotations

import json

from sentinel.aibom.models import AIBOMResult
from sentinel.aibom.reporters.base import BaseAIBOMReporter


class SARIFReporter(BaseAIBOMReporter):
    name = "sarif"
    extension = "sarif"

    def render(self, result: AIBOMResult) -> str:
        results = []
        for c in result.components:
            if not c.risks:
                continue
            for risk in c.risks:
                results.append({
                    "ruleId": f"AIBOM-{c.type.value.upper()}",
                    "level": "warning",
                    "message": {"text": f"{c.name}: {risk}"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": c.path or c.name}}}],
                })
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {"driver": {"name": "Eresus Sentinel AIBOM", "version": result.version}},
                "results": results,
            }],
        }
        return json.dumps(sarif, indent=2, default=str)
