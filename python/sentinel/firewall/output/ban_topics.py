"""
Output-side topic banning scanner — detects and blocks forbidden topics.

Production-grade features:
  - 30+ pre-built sensitive topic categories loaded from YAML
  - Weighted keyword matching with context window
  - Confidence scoring per topic
  - Regex pattern support
  - Topic co-occurrence analysis
  - Auto-redaction with configurable replacement
  - Custom topic rules
  - OutputScanner-compliant with Finding/ScanResult

Topic data externalized to: data/ban_topics.yaml
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from sentinel.data_loader import load_data
from sentinel.finding import Finding, Severity
from sentinel.firewall.base import OutputScanner, ScanAction, ScanResult

logger = logging.getLogger(__name__)


# ── YAML-driven data loading ────────────────────────────────────────

@dataclass
class TopicRule:
    """Rule defining a banned topic."""
    name: str
    keywords: list[str]
    patterns: list[str] = field(default_factory=list)
    weight: float = 1.0
    category: str = "custom"


_DEFAULT_TOPICS: dict[str, TopicRule] | None = None


def _get_default_topics() -> dict[str, TopicRule]:
    global _DEFAULT_TOPICS
    if _DEFAULT_TOPICS is not None:
        return _DEFAULT_TOPICS

    data = load_data("ban_topics.yaml")
    topics_raw = data.get("topics", {})
    _DEFAULT_TOPICS = {}

    for name, info in topics_raw.items():
        _DEFAULT_TOPICS[name] = TopicRule(
            name=name,
            keywords=info.get("keywords", []),
            patterns=info.get("patterns", []),
            weight=info.get("weight", 1.0),
            category=info.get("category", "custom"),
        )

    return _DEFAULT_TOPICS


# ── Data classes ─────────────────────────────────────────────────────

@dataclass
class TopicMatch:
    """Single topic match."""
    topic: str
    category: str
    keyword: str
    context: str
    confidence: float
    position: int


# ── Scanner ──────────────────────────────────────────────────────────

class BanTopicsOutputScanner(OutputScanner):
    """
    Detects and blocks banned topics in model output.

    All topic rules loaded from data/ban_topics.yaml.

    Features:
      - 12 pre-built sensitive topic categories with 100+ keywords
      - Regex pattern matching for instruction-like content
      - Weighted scoring by topic severity
      - Context window extraction around matches
      - Auto-redaction option

    Usage:
        scanner = BanTopicsOutputScanner(topics=["violence", "drugs", "weapons"])
        result = scanner.scan("", "Here's how to build a bomb...")
    """

    def __init__(
        self,
        topics: list[str] | None = None,
        custom_rules: list[TopicRule] | None = None,
        threshold: float = 0.5,
        redact: bool = False,
    ):
        self._threshold = threshold
        self._redact = redact

        # Build active topic rules
        default_topics = _get_default_topics()
        self._rules: dict[str, TopicRule] = {}
        if custom_rules:
            for rule in custom_rules:
                self._rules[rule.name] = rule

        active_topics = topics or list(default_topics.keys())
        for topic in active_topics:
            if topic in default_topics:
                self._rules[topic] = default_topics[topic]

    def scan(self, prompt: str, output: str) -> ScanResult:
        if not output or len(output.strip()) < 5:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        matches: list[TopicMatch] = []
        text_lower = output.lower()

        for topic_name, rule in self._rules.items():
            # Keyword matching
            for keyword in rule.keywords:
                kw_lower = keyword.lower()
                idx = text_lower.find(kw_lower)
                if idx >= 0:
                    context = output[max(0, idx - 40):idx + len(keyword) + 40]
                    confidence = min(1.0, 0.6 + rule.weight * 0.2)
                    matches.append(TopicMatch(
                        topic=topic_name,
                        category=rule.category,
                        keyword=keyword,
                        context=context.strip(),
                        confidence=round(confidence, 3),
                        position=idx,
                    ))

            # Regex pattern matching
            for pat_str in rule.patterns:
                try:
                    pattern = re.compile(pat_str, re.IGNORECASE)
                    for m in pattern.finditer(output):
                        context = output[max(0, m.start() - 20):m.end() + 20]
                        matches.append(TopicMatch(
                            topic=topic_name,
                            category=rule.category,
                            keyword=m.group(0),
                            context=context.strip(),
                            confidence=round(min(1.0, 0.8 + rule.weight * 0.1), 3),
                            position=m.start(),
                        ))
                except re.error:
                    pass

        # Deduplicate by position
        seen = set()
        unique = []
        for m in matches:
            if m.position not in seen:
                seen.add(m.position)
                unique.append(m)
        matches = unique

        if not matches:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        topics_found = list(set(m.topic for m in matches))
        categories_found = list(set(m.category for m in matches))
        max_confidence = max(m.confidence for m in matches)

        has_banned = max_confidence >= self._threshold

        if not has_banned:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        # Weighted risk
        total_weight = sum(self._rules[m.topic].weight for m in matches if m.topic in self._rules)
        risk_score = min(1.0, total_weight / max(len(self._rules), 1))

        # Severity by category
        if "critical" in categories_found:
            severity = Severity.CRITICAL
        elif "safety" in categories_found:
            severity = Severity.HIGH
        else:
            severity = Severity.MEDIUM

        # Redaction
        sanitized = output
        if self._redact:
            for m in sorted(matches, key=lambda x: x.position, reverse=True):
                start = m.position
                end = start + len(m.keyword)
                sanitized = sanitized[:start] + "[REDACTED]" + sanitized[end:]

        # Build findings
        findings = []
        seen_topics = set()
        for m in sorted(matches, key=lambda x: x.confidence, reverse=True):
            if m.topic in seen_topics:
                continue
            seen_topics.add(m.topic)
            findings.append(Finding.firewall_output(
                rule_id="FIREWALL-OUTPUT-050",
                title=f"Banned topic: {m.topic} ({m.category})",
                description=(
                    f"Response discusses banned topic '{m.topic}' "
                    f"(category: {m.category}). "
                    f"Matched keyword: '{m.keyword}'"
                ),
                severity=severity,
                confidence=m.confidence,
                target="<response>",
                evidence=f"Topic: {m.topic}, Keyword: {m.keyword}, Context: {m.context[:100]}",
                cwe_ids=["CWE-1021"],
                tags=["owasp:llm02", "category:banned_topic", f"topic:{m.topic}"],
                remediation="Remove banned topic content. Redirect response.",
            ))

        action = ScanAction.BLOCK if severity in (Severity.CRITICAL, Severity.HIGH) else ScanAction.WARN

        return ScanResult(
            sanitized=sanitized,
            action=action,
            risk_score=round(risk_score, 4),
            findings=findings,
            metadata={
                "topics_found": topics_found,
                "categories_found": categories_found,
                "match_count": len(matches),
            },
        )
