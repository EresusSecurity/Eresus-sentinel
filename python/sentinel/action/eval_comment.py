"""PR eval comment renderer — before/after eval diff summary for CI."""
from __future__ import annotations

from typing import Any


def render_eval_comment(
    before: dict[str, Any] | None,
    after: dict[str, Any],
    title: str = "Sentinel Eval Report",
) -> str:
    """Render a PR comment comparing eval results."""
    lines = [f"## {title}\n"]

    total = after.get("total", 0)
    passed = after.get("passed", 0)
    failed = after.get("failed", 0)
    errored = after.get("errored", 0)
    pass_rate = passed / max(total, 1)

    icon = "\u2705" if failed == 0 and errored == 0 else "\u274c"
    lines.append(f"{icon} **Pass rate:** {pass_rate:.0%} ({passed}/{total})\n")

    if before:
        prev_passed = before.get("passed", 0)
        prev_total = before.get("total", 0)
        prev_rate = prev_passed / max(prev_total, 1)
        delta = pass_rate - prev_rate
        arrow = "\u2191" if delta > 0 else ("\u2193" if delta < 0 else "\u2192")
        lines.append(f"**Change:** {arrow} {delta:+.1%} (was {prev_rate:.0%})\n")

    lines.append("| Metric | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Total | {total} |")
    lines.append(f"| Passed | {passed} |")
    lines.append(f"| Failed | {failed} |")
    lines.append(f"| Errors | {errored} |")

    if after.get("findings"):
        lines.append("\n### Findings\n")
        for f in after["findings"][:10]:
            sev = f.get("severity", "?")
            msg = f.get("message", "")
            lines.append(f"- **{sev}** {msg}")

    return "\n".join(lines) + "\n"


def render_minimal_badge(pass_rate: float) -> str:
    """Render a minimal text badge for CI summaries."""
    if pass_rate >= 0.95:
        return "PASS \u2705"
    elif pass_rate >= 0.7:
        return "WARN \u26a0\ufe0f"
    else:
        return "FAIL \u274c"
