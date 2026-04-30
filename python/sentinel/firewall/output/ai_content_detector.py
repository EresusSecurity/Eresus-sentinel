"""AI-generated content detector for LLM output scanning."""

from __future__ import annotations

import logging
import math
import re
from collections import Counter

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import OutputScanner, ScanAction, ScanResult

logger = logging.getLogger(__name__)

# Statistical markers of AI-generated text
AI_MARKERS = [
    r"\b(?:I(?:'m| am) an AI|as an AI (?:language )?model)\b",
    r"\b(?:I don'?t have (?:personal )?(?:opinions?|feelings?|emotions?|experiences?))\b",
    r"\b(?:(?:it'?s )?(?:important|worth) (?:to )?not(?:e|ing) that)\b",
    r"\b(?:delve|tapestry|multifaceted|utilize|leverage|synergy)\b",
    r"\b(?:in (?:the )?(?:realm|context|landscape) of)\b",
    r"\b(?:(?:here|there) are (?:some|several|a few) (?:key )?(?:points?|things?|considerations?))\b",
    r"\b(?:I hope (?:this|that) helps?)\b",
    r"\b(?:let me know if you (?:have|need) (?:any )?(?:more|further|additional))\b",
]

_COMPILED_MARKERS = [re.compile(p, re.IGNORECASE) for p in AI_MARKERS]


def _entropy(text: str) -> float:
    """Calculate Shannon entropy of text (low entropy = repetitive/templated)."""
    if not text:
        return 0.0
    freq = Counter(text.lower())
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def _burstiness(text: str) -> float:
    """Measure sentence length variance (AI text tends to be uniform)."""
    sentences = re.split(r'[.!?]+', text)
    lengths = [len(s.split()) for s in sentences if s.strip()]
    if len(lengths) < 3:
        return 1.0
    mean = sum(lengths) / len(lengths)
    if mean == 0:
        return 0.0
    variance = sum((l - mean) ** 2 for l in lengths) / len(lengths)
    std = math.sqrt(variance)
    cv = std / mean  # coefficient of variation
    return min(1.0, cv)  # Human text: ~0.5-1.0, AI text: ~0.1-0.3


class AIContentDetector(OutputScanner):
    """Detects AI-generated content in LLM responses using statistical heuristics."""

    def __init__(
        self,
        threshold: float = 0.75,
        check_entropy: bool = True,
        check_burstiness: bool = True,
        check_markers: bool = True,
    ):
        self._threshold = threshold
        self._check_entropy = check_entropy
        self._check_burstiness = check_burstiness
        self._check_markers = check_markers

    def scan(self, prompt: str, output: str) -> ScanResult:
        if not output or len(output.strip()) < 50:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        scores = []

        # Marker detection
        if self._check_markers:
            marker_hits = sum(1 for p in _COMPILED_MARKERS if p.search(output))
            marker_score = min(1.0, marker_hits / 3)
            scores.append(("markers", marker_score))

        # Entropy analysis
        if self._check_entropy:
            ent = _entropy(output)
            # English text entropy: ~4.0-4.5, highly templated: <3.5
            entropy_score = max(0.0, 1.0 - (ent / 4.5)) if ent < 4.5 else 0.0
            scores.append(("entropy", entropy_score))

        # Burstiness analysis
        if self._check_burstiness:
            burst = _burstiness(output)
            # Low burstiness = likely AI
            burst_score = max(0.0, 1.0 - burst * 2)
            scores.append(("burstiness", burst_score))

        if not scores:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        avg_score = sum(s for _, s in scores) / len(scores)

        if avg_score < self._threshold:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=avg_score)

        evidence_parts = [f"{name}: {score:.2f}" for name, score in scores]
        finding = Finding.firewall_output(
            rule_id="FIREWALL-OUTPUT-060",
            title="AI-generated content detected",
            description=f"Output shows AI-generation markers (score: {avg_score:.1%})",
            severity=Severity.LOW,
            confidence=avg_score,
            target="<output>",
            evidence=", ".join(evidence_parts),
            tags=["ai_detection", "content_quality"],
        )

        return ScanResult(
            sanitized=output,
            action=ScanAction.WARN,
            risk_score=avg_score,
            findings=[finding],
            metadata=dict(scores),
        )
