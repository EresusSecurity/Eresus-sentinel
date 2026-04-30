"""Markdown AIBOM reporter."""
from __future__ import annotations

from collections import defaultdict

from sentinel.aibom.models import AIBOMResult
from sentinel.aibom.reporters.base import BaseAIBOMReporter


class MarkdownReporter(BaseAIBOMReporter):
    name = "markdown"
    extension = "md"

    def render(self, result: AIBOMResult) -> str:
        lines = [
            "# Eresus Sentinel — AI Bill of Materials",
            "",
            f"Generated: {result.generated_at}",
            f"Total components: {len(result.components)}",
            f"Total relationships: {len(result.relationships)}",
            "",
        ]
        grouped: dict[str, list] = defaultdict(list)
        for c in result.components:
            grouped[c.type.value].append(c)
        for type_name in sorted(grouped):
            lines.append(f"## {type_name} ({len(grouped[type_name])})")
            lines.append("")
            lines.append("| Name | Version | Path | Evidence |")
            lines.append("|------|---------|------|----------|")
            for c in grouped[type_name]:
                evidence = "; ".join(c.evidence)[:80]
                lines.append(f"| `{c.name}` | {c.version or '—'} | `{c.path}` | {evidence} |")
            lines.append("")
        if result.relationships:
            lines.append("## Relationships")
            lines.append("")
            for rel in result.relationships:
                lines.append(f"- {rel.source_id[:8]} → **{rel.type.value}** → {rel.target_id[:8]}")
        return "\n".join(lines)
