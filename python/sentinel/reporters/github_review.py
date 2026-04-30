"""GitHub PR review reporter — inline remediation comments."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from sentinel.finding import Finding

logger = logging.getLogger(__name__)


@dataclass
class ReviewComment:
    path: str
    line: int
    body: str
    side: str = "RIGHT"


def findings_to_review_comments(findings: list[Finding]) -> list[ReviewComment]:
    """Convert findings to GitHub PR review comments."""
    comments: list[ReviewComment] = []
    for f in findings:
        if not f.target:
            continue
        line = 1
        if f.location and f.location.line_start:
            line = f.location.line_start
        body = _format_comment(f)
        comments.append(ReviewComment(
            path=f.target,
            line=int(line),
            body=body,
        ))
    return comments


def _format_comment(f: Finding) -> str:
    severity_emoji = {
        "CRITICAL": "\U0001f534",
        "HIGH": "\U0001f7e0",
        "MEDIUM": "\U0001f7e1",
        "LOW": "\U0001f535",
        "INFO": "\u2139\ufe0f",
    }
    emoji = severity_emoji.get(f.severity.name, "")
    lines = [
        f"{emoji} **{f.severity.name}** — {f.rule_id}",
        "",
        f.description,
    ]
    if f.remediation:
        lines.extend(["", f"**Remediation:** {f.remediation}"])
    return "\n".join(lines)


def format_review_body(
    comments: list[ReviewComment],
    summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Format the full PR review request payload."""
    body_lines = ["## Sentinel Security Review\n"]
    if summary:
        total = summary.get("total_findings", 0)
        body_lines.append(f"Found **{total}** findings across reviewed files.\n")

    review_comments = []
    for c in comments[:50]:
        review_comments.append({
            "path": c.path,
            "line": c.line,
            "body": c.body,
            "side": c.side,
        })

    return {
        "body": "\n".join(body_lines),
        "event": "COMMENT",
        "comments": review_comments,
    }
