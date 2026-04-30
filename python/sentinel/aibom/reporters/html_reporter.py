"""Self-contained HTML AIBOM reporter."""
from __future__ import annotations

import html
from collections import Counter

from sentinel.aibom.models import AIBOMResult
from sentinel.aibom.reporters.base import BaseAIBOMReporter

_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Eresus Sentinel AIBOM</title>
<style>
body{{font-family:-apple-system,system-ui,sans-serif;margin:24px;color:#1a1a1a;background:#f7f7f9}}
h1{{font-size:20px;margin:0 0 16px}}
.summary{{display:flex;gap:12px;margin-bottom:24px}}
.card{{flex:1;background:#fff;border:1px solid #e0e0e4;border-radius:8px;padding:16px;box-shadow:0 1px 2px rgba(0,0,0,.04)}}
.kv{{font-size:12px;color:#666}}.v{{font-size:22px;font-weight:600}}
table{{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e0e0e4;border-radius:8px;overflow:hidden}}
th,td{{padding:8px 12px;text-align:left;font-size:13px;border-bottom:1px solid #eef}}
th{{background:#fafafb;font-weight:600;color:#555}}
tr:last-child td{{border-bottom:none}}
.type{{font-family:ui-monospace,monospace;font-size:11px;color:#0b5}}
.risk{{color:#d00}}
</style></head><body>
<h1>Eresus Sentinel — AI Bill of Materials</h1>
<div class="summary">
  <div class="card"><div class="kv">Components</div><div class="v">{total}</div></div>
  <div class="card"><div class="kv">Relationships</div><div class="v">{rels}</div></div>
  <div class="card"><div class="kv">Types</div><div class="v">{types}</div></div>
  <div class="card"><div class="kv">Generated</div><div class="v" style="font-size:13px">{ts}</div></div>
</div>
<table><thead><tr><th>Type</th><th>Name</th><th>Path</th><th>Risks</th></tr></thead><tbody>
{rows}
</tbody></table>
</body></html>"""


class HTMLReporter(BaseAIBOMReporter):
    name = "html"
    extension = "html"

    def render(self, result: AIBOMResult) -> str:
        rows = []
        for c in result.components:
            risk_html = "".join(f'<div class="risk">{html.escape(r)}</div>' for r in c.risks)
            rows.append(
                "<tr>"
                f"<td class='type'>{html.escape(c.type.value)}</td>"
                f"<td>{html.escape(c.name)}</td>"
                f"<td>{html.escape(c.path)}</td>"
                f"<td>{risk_html}</td>"
                "</tr>"
            )
        type_count = len(Counter(c.type.value for c in result.components))
        return _TEMPLATE.format(
            total=len(result.components),
            rels=len(result.relationships),
            types=type_count,
            ts=result.generated_at,
            rows="".join(rows),
        )
