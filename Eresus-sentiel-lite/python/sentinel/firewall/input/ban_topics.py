"""
Input topic banning scanner.

Blocks prompts containing forbidden topics using keyword-based zero-shot classification.
Configurable topic list with per-topic threshold support.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from sentinel.finding import Finding, Severity


@dataclass
class TopicRule:
    """A single banned topic with detection keywords."""
    name: str
    keywords: list[str]
    threshold: float = 0.6
    severity: Severity = Severity.MEDIUM


DEFAULT_BANNED_TOPICS = [
    TopicRule("weapons", ["gun", "rifle", "firearm", "explosive", "bomb", "ammunition", "grenade", "missile", "artillery", "weapon", "pistol", "shotgun", "machine gun"], severity=Severity.HIGH),
    TopicRule("drugs", ["cocaine", "heroin", "methamphetamine", "fentanyl", "narcotics", "drug trafficking", "drug dealing", "drug manufacturing", "mdma", "lsd", "opium", "crack"], severity=Severity.HIGH),
    TopicRule("violence", ["murder", "assassination", "torture", "kidnapping", "terrorism", "mass shooting", "stabbing", "assault", "homicide", "genocide", "ethnic cleansing"], severity=Severity.HIGH),
    TopicRule("hacking", ["hack into", "exploit vulnerability", "zero-day", "ddos attack", "sql injection", "phishing attack", "brute force", "ransomware", "keylogger", "rootkit", "botnet"], severity=Severity.MEDIUM),
    TopicRule("adult_content", ["pornography", "explicit sexual", "sex trafficking", "child exploitation", "sexual abuse", "revenge porn", "csam"], severity=Severity.CRITICAL),
    TopicRule("self_harm", ["suicide method", "how to kill yourself", "self-harm", "cutting yourself", "overdose instructions", "euthanasia method"], severity=Severity.CRITICAL),
    TopicRule("illegal_activity", ["money laundering", "tax evasion", "fraud scheme", "identity theft", "counterfeiting", "embezzlement", "insider trading", "bribery"], severity=Severity.HIGH),
    TopicRule("hate_speech", ["racial supremacy", "ethnic cleansing", "antisemitism", "islamophobia", "white power", "neo-nazi", "racial slur"], severity=Severity.HIGH),
]


class BanTopicsScanner:
    """
    Bans specific topics from prompts using keyword matching.

    Performs weighted keyword density analysis — a topic is flagged
    when enough topic-specific keywords appear relative to prompt length.
    """

    def __init__(
        self,
        topics: list[TopicRule] | None = None,
        threshold: float = 0.6,
    ):
        self._topics = topics or DEFAULT_BANNED_TOPICS
        self._default_threshold = threshold

    def scan(self, prompt: str) -> tuple[str, bool, float]:
        if not prompt.strip():
            return prompt, True, -1.0

        prompt_lower = prompt.lower()
        words = prompt_lower.split()
        word_count = max(len(words), 1)

        max_risk = 0.0
        detected_topics = []

        for topic in self._topics:
            hits = 0
            matched_keywords = []
            for kw in topic.keywords:
                if kw.lower() in prompt_lower:
                    hits += 1
                    matched_keywords.append(kw)

            if hits == 0:
                continue

            density = hits / min(word_count, len(topic.keywords))
            threshold = topic.threshold or self._default_threshold

            # Scale minimum hits by document length to avoid FP on long docs
            # Short prompts (<100 words): 3 hits is suspicious
            # Longer docs: require proportionally more hits
            min_hits = 3 if word_count < 100 else max(3, int(word_count * 0.02))

            if density >= threshold or (hits >= min_hits and word_count < 200):
                score = min(1.0, density / threshold)
                max_risk = max(max_risk, score)
                detected_topics.append((topic.name, matched_keywords, score))

        if detected_topics:
            return prompt, False, max_risk

        return prompt, True, max_risk


class BanTopicsOutputScanner:
    """Output-side topic banning — checks model responses for forbidden topics."""

    def __init__(
        self,
        topics: list[TopicRule] | None = None,
        threshold: float = 0.6,
    ):
        self._inner = BanTopicsScanner(topics=topics, threshold=threshold)

    def scan(self, prompt: str, output: str) -> tuple[str, bool, float]:
        _, is_valid, risk = self._inner.scan(output)
        return output, is_valid, risk
