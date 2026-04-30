"""
Eresus Sentinel — CoT Response Prefix Attack Scanner (Output).

Detects when a model response starts with compliance-signaling prefixes
that indicate the model's safety alignment has been bypassed via a
Chain-of-Thought (CoT) response prefix attack.

Research basis:
  Li et al. "What Matters For Safety Alignment?" (arXiv:2601.03868, 2026)
  - CoT prefix attacks elevate ASR by 3.34× on average
  - Seed-OSS-36B-Instruct: 0.6% → 96.3% ASR with prefix forcing
  - Text-completion interfaces with user-defined prefixes are especially
    vulnerable since attackers can prepend compliance signals

Detection strategy:
  1. Check if output starts with known compliance prefixes
  2. Cross-reference with dangerous prompt heuristics
  3. Score confidence based on prefix match + topic sensitivity

This scanner catches outputs that begin with phrases like:
  "Sure, here's how to..."
  "Of course! Here are the steps..."
  "Absolutely, let me explain..."
followed by content that matches dangerous topic indicators.

OutputScanner-compliant with Finding/ScanResult.
"""

from __future__ import annotations

import logging
import re

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import OutputScanner, ScanAction, ScanResult

logger = logging.getLogger(__name__)


# ── Compliance-signaling prefixes ───────────────────────────────────
# These are phrases that models produce when their alignment has been
# bypassed — they signal false compliance before delivering harmful content.

COMPLIANCE_PREFIXES: list[tuple[re.Pattern, float]] = [
    # Direct compliance
    (re.compile(r"^sure[,!.]?\s*(here'?s?|i can|let me)", re.I), 0.8),
    (re.compile(r"^of course[,!.]?\s*(here|i('ll| will)|let)", re.I), 0.8),
    (re.compile(r"^absolutely[,!.]?\s*(here|i('ll| will)|let)", re.I), 0.8),
    (re.compile(r"^certainly[,!.]?\s*(here|i('ll| will)|let)", re.I), 0.7),
    (re.compile(r"^definitely[,!.]?\s*(here|i('ll| will)|let)", re.I), 0.7),
    (re.compile(r"^no problem[,!.]?\s*(here|i('ll| will)|let)", re.I), 0.8),
    (re.compile(r"^glad to help[,!.]?\s*(here|with)", re.I), 0.7),
    (re.compile(r"^happy to (help|assist|provide)[,!.]", re.I), 0.7),
    (re.compile(r"^i'?d be happy to", re.I), 0.6),
    # Step-by-step compliance
    (re.compile(r"^(here are|here is) (the |some )?(step|instruction|method|way)", re.I), 0.9),
    (re.compile(r"^(step 1|first,?\s*(you|we|let))", re.I), 0.7),
    (re.compile(r"^let me (explain|walk you through|show you|help you)", re.I), 0.6),
    # CoT-specific patterns (reasoning before compliance)
    (re.compile(r"^(okay|ok|alright),?\s*(so|let|here|i)", re.I), 0.5),
    (re.compile(r"^(thinking|let me think).*\n.*sure", re.I | re.S), 0.9),
    # Forced prefix patterns (exact patterns used in prefix attacks)
    (re.compile(r"^sure,?\s*here('s| is) (how|a|the)", re.I), 0.95),
    (re.compile(r"^i can help (you )?(with that|with this)", re.I), 0.6),
]

# ── Dangerous topic indicators ──────────────────────────────────────
# When a compliance prefix is followed by content matching these topics,
# it's a strong signal that alignment was bypassed.

DANGEROUS_TOPIC_INDICATORS: list[tuple[re.Pattern, str, float]] = [
    # Weapons / explosives
    (re.compile(r"\b(explosive|bomb|detona|weapon|firearm|ammunit|napalm|thermite)\b", re.I), "weapons", 1.0),
    # Hacking / exploitation
    (re.compile(r"\b(exploit|hack|crack|bypass.*(security|auth)|brute.?force|privilege.?escalat|sql.?inject|xss|buffer.?overflow)\b", re.I), "hacking", 0.9),
    # Drugs / synthesis
    (re.compile(r"\b(synthe[st]i[zs]e?|methamphetamine|fentanyl|precursor|cook|recipe.*drug)\b", re.I), "drugs", 1.0),
    # Malware
    (re.compile(r"\b(malware|ransomware|keylogg|trojan|rootkit|spyware|payload|reverse.?shell|c2.?server)\b", re.I), "malware", 0.9),
    # Personal harm
    (re.compile(r"\b(poison|kill|murder|assassinat|harm|injure|suicid)\b", re.I), "harm", 1.0),
    # Privacy violation
    (re.compile(r"\b(doxx|stalk|track.*(person|someone)|social.?security|credit.?card.?number|steal.*identity)\b", re.I), "privacy", 0.9),
    # CBRN
    (re.compile(r"\b(biological.?weapon|chemical.?weapon|nerve.?agent|sarin|anthrax|ricin|uranium)\b", re.I), "cbrn", 1.0),
    # Fraud
    (re.compile(r"\b(counterfeit|forg(e|ing)|launder|phish|scam|fraud|impersonat)\b", re.I), "fraud", 0.8),
]


class CoTResponsePrefixScanner(OutputScanner):
    """
    Detects CoT response prefix attacks where the model's alignment
    is bypassed by forcing compliance-signaling prefixes.

    Based on:
      Li et al. (2026) — CoT prefix attacks elevate ASR by 3.34×
      from 0.6% to 96.3% on safety benchmarks.

    Scans the output for:
      1. Compliance-signaling prefix patterns
      2. Dangerous topic indicators in the body
      3. Confidence scoring based on prefix strength × topic severity
    """

    def __init__(
        self,
        score_threshold: float = 0.5,
        check_topics: bool = True,
        max_prefix_scan: int = 200,
    ):
        """
        Args:
            score_threshold: Minimum combined score to flag (0.0-1.0)
            check_topics:    Whether to cross-check with dangerous topics
            max_prefix_scan: Max characters to check for prefix patterns
        """
        self._threshold = score_threshold
        self._check_topics = check_topics
        self._max_prefix = max_prefix_scan

    def scan(self, prompt: str, output: str) -> ScanResult:
        if not output or len(output.strip()) < 10:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        # ── Phase 1: Check for compliance prefix ──
        prefix_text = output[:self._max_prefix]
        best_prefix_match = None
        best_prefix_score = 0.0

        for pattern, strength in COMPLIANCE_PREFIXES:
            match = pattern.search(prefix_text)
            if match and strength > best_prefix_score:
                best_prefix_match = match.group(0)
                best_prefix_score = strength

        if not best_prefix_match:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        # ── Phase 2: Check for dangerous topics in body ──
        topic_matches: list[tuple[str, float]] = []
        if self._check_topics:
            body = output[len(best_prefix_match):]
            for pattern, topic_name, topic_weight in DANGEROUS_TOPIC_INDICATORS:
                if pattern.search(body):
                    topic_matches.append((topic_name, topic_weight))

        # ── Phase 3: Score calculation ──
        if topic_matches:
            max_topic_weight = max(w for _, w in topic_matches)
            combined_score = best_prefix_score * max_topic_weight
        else:
            # Prefix-only score (lower confidence without topic match)
            combined_score = best_prefix_score * 0.4

        if combined_score < self._threshold:
            return ScanResult(
                sanitized=output,
                action=ScanAction.PASS,
                risk_score=combined_score * 0.3,
            )

        # ── Phase 4: Generate finding ──
        if combined_score >= 0.8:
            severity = Severity.CRITICAL
        elif combined_score >= 0.6:
            severity = Severity.HIGH
        else:
            severity = Severity.MEDIUM

        topics_str = ", ".join(t for t, _ in topic_matches) if topic_matches else "none detected"

        finding = Finding.firewall_output(
            rule_id="FIREWALL-OUTPUT-090",
            title=f"CoT response prefix attack detected (score: {combined_score:.0%})",
            description=(
                f"Response begins with compliance-signaling prefix "
                f"'{best_prefix_match}' (strength: {best_prefix_score:.0%}) "
                f"followed by content matching dangerous topics: [{topics_str}]. "
                f"This pattern is consistent with a CoT response prefix attack "
                f"where the attacker forces the model to begin with a compliant "
                f"prefix, bypassing safety alignment. "
                f"Research shows this technique elevates attack success rate by "
                f"3.34× on average (Li et al., 2026, arXiv:2601.03868)."
            ),
            severity=severity,
            confidence=combined_score,
            target="<response>",
            evidence=(
                f"Prefix: '{best_prefix_match}' | "
                f"Prefix score: {best_prefix_score:.2f} | "
                f"Topics: {topics_str} | "
                f"Combined score: {combined_score:.2f} | "
                f"First 200 chars: {output[:200]}"
            ),
            cwe_ids=["CWE-20"],
            tags=[
                "owasp:llm01", "category:cot_prefix_attack",
                "research:arxiv_2601.03868",
            ] + [f"topic:{t}" for t, _ in topic_matches],
            remediation=(
                "1. Block user-defined response prefixes in text-completion APIs. "
                "2. Implement output-side safety classifiers that scan the full "
                "response regardless of its opening. "
                "3. Use completion-mode restrictions that prevent prefix injection."
            ),
        )

        return ScanResult(
            sanitized=output,
            action=ScanAction.BLOCK if severity == Severity.CRITICAL else ScanAction.WARN,
            risk_score=combined_score,
            findings=[finding],
            metadata={
                "prefix_match": best_prefix_match,
                "prefix_score": best_prefix_score,
                "topics": [t for t, _ in topic_matches],
                "combined_score": combined_score,
            },
        )
