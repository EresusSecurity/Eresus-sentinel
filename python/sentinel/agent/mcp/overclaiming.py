"""Safety-overclaiming detector (MCP-060).

A benign text formatter doesn't need to say "no exec, no subprocess,
no read_file, no network" — that level of negation is a social-
engineering signal used to pre-emptively deflect scanner detection.

Heuristic: collect unique dangerous-capability keywords that appear in
a negation window.  If ≥ 3 distinct capability families are negated,
flag the tool as suspicious.
"""

from __future__ import annotations

import re
from typing import Any

from ...finding import Finding, Severity
from .negation import NEGATION_PATTERN, _WINDOW_CHARS
from .searchable import build_searchable


_MIN_NEGATED_CAPS = 2  # threshold before flagging


def check_safety_overclaiming(
    tool: dict[str, Any],
    tool_name: str,
    source: str,
    caps_catalog: dict[str, dict[str, Any]],
    findings: list[Finding],
) -> None:
    """Append MCP-060 if the tool description negates ≥ 3 distinct
    capability families — a strong evasion-attempt signal.
    """
    searchable = build_searchable(tool)
    negated_caps: list[str] = []

    for cap_name, cap_info in caps_catalog.items():
        for keyword in cap_info.get("keywords", []):
            needle = keyword.lower()
            _pat = re.compile(r"\b" + re.escape(needle) + r"\b")
            positions = [m.start() for m in _pat.finditer(searchable)]
            if not positions:
                continue
            # Check if ALL occurrences are negated (i.e. every hit is inside
            # a "does not / no / never / refuses" window)
            all_negated = True
            for pos in positions:
                window = searchable[max(0, pos - _WINDOW_CHARS): pos]
                if not NEGATION_PATTERN.search(window):
                    all_negated = False
                    break
            if all_negated:
                negated_caps.append(cap_name)
                break  # one match per cap family is enough

    if len(negated_caps) >= _MIN_NEGATED_CAPS:
        findings.append(Finding.agent_mcp(
            rule_id="MCP-060",
            title="Suspicious safety overclaiming in tool description",
            description=(
                f"Tool '{tool_name}' explicitly denies {len(negated_caps)} "
                f"dangerous capability families ({', '.join(negated_caps)}) "
                "in its description. Legitimate tools rarely enumerate what "
                "they cannot do; this pattern is used to pre-emptively bypass "
                "security scanners (social-engineering evasion)."
            ),
            severity=Severity.MEDIUM,
            target=source,
            evidence=f"negated_capabilities={negated_caps}",
        ))
