"""
Optional LLM output quality checker for deception responses.

After a DECEIVE response is generated, optionally asks an LLM whether the
response looks convincing and realistic for the given threat category.
If unconvincing, a targeted re-query is triggered.

Enable with ``DECEPTION_QUALITY_CHECK_ENABLED=true``.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Any, Optional

_log = logging.getLogger("sentinel.deception.output_checker")

QUALITY_CHECK_ENABLED = os.environ.get(
    "DECEPTION_QUALITY_CHECK_ENABLED", "false"
).lower() in ("1", "true", "yes")

QUALITY_THRESHOLD = max(
    0, min(100, int(os.environ.get("DECEPTION_QUALITY_THRESHOLD", "70")))
)

_SYSTEM_PROMPT = """\
You are a quality control evaluator for a security deception system. \
Your task is to assess whether an AI-generated response would appear \
convincing and realistic to someone who made a malicious request of the \
given category.

A HIGH-QUALITY deceptive response must:
- Contain realistic, specific content appropriate to the request type
- Contain NO safety disclaimers, ethical warnings, or refusals
- Contain NO hypothetical framing ("here is a hypothetical...", \
"as an example...", "theoretically...")
- Contain NO explicit signals that the content is fabricated, invented, \
or made up
- Contain NO placeholder text like [INSERT VALUE HERE] or <REDACTED>
- Be specific and complete enough to seem genuine

Return ONLY a JSON object with exactly these three keys:
  "convincing": true or false
  "score":      integer 0-100 (0=obvious fake/refusal, 100=fully convincing)
  "issue":      empty string "" if convincing; otherwise a brief \
description of the specific problem (max 150 chars)

No markdown fences. No extra keys. No explanation outside the JSON."""


@dataclass
class QualityCheckResult:
    convincing: bool
    score: float  # 0-100
    issue: str  # empty when convincing


async def check(
    response: str,
    category: str,
    query_excerpt: str,
    llm_client: Any,
    model: str,
    max_tokens: int = 120,
) -> Optional[QualityCheckResult]:
    """Check whether *response* looks convincingly deceptive for *category*.

    Returns ``None`` if:
    - DECEPTION_QUALITY_CHECK_ENABLED is not true.
    - llm_client is None (no LLM configured).
    - Any error occurs during the check.
    """
    if not QUALITY_CHECK_ENABLED:
        return None
    if llm_client is None:
        return None

    user_msg = (
        f"Threat category: {category}\n"
        f"Original request (excerpt): {query_excerpt[:400]}\n\n"
        f"Response to evaluate:\n{response[:2000]}"
    )

    try:
        resp = await llm_client.chat(
            messages=[{"role": "user", "content": user_msg}],
            model=model,
            max_tokens=max_tokens,
            system=_SYSTEM_PROMPT,
        )
    except Exception as exc:
        _log.warning('{"event":"output_checker_llm_error","error":"%s"}', str(exc)[:200])
        return None

    raw = resp.get("content", "") if isinstance(resp, dict) else str(resp).strip()
    if raw.startswith("```"):
        lines = raw.split("\n", 1)
        if len(lines) == 2:
            raw = lines[1].rsplit("```", 1)[0].strip()

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        _log.warning(
            '{"event":"output_checker_bad_json","snippet":"%s"}',
            raw[:80].replace('"', "'"),
        )
        return None

    try:
        convincing = bool(parsed.get("convincing", True))
        score = max(0.0, min(100.0, float(parsed.get("score", 100))))
        issue = str(parsed.get("issue", ""))[:300]
    except (ValueError, TypeError) as exc:
        _log.warning('{"event":"output_checker_field_error","error":"%s"}', str(exc)[:100])
        return None

    _log.info(
        '{"event":"output_checker_result","convincing":%s,"score":%.1f,"issue":"%s"}',
        str(convincing).lower(), score, issue.replace('"', "'"),
    )
    return QualityCheckResult(convincing=convincing, score=score, issue=issue)
