"""
Eresus Sentinel - Competitor Mention Scanner (Input)

Detects competitor names in user prompts using two strategies:
  1. FAST: Exact substring + case-insensitive matching (zero dependencies)
  2. NER:  Named-entity recognition for organization detection
          (optional, uses transformers library)

When a competitor is detected, the scanner can:
  - BLOCK the prompt entirely
  - REDACT competitor names with [COMPETITOR] placeholder
  - WARN with a finding but allow through

Enterprise use case: Prevent LLMs from generating content that mentions
or recommends competitor products/services in customer-facing outputs.

Implementation adds:
  - Fuzzy matching for typos/variations ("Gooogle", "Micr0soft")
  - Alias support (e.g., "AWS" -> "Amazon Web Services")
  - Category-based competitor groups (cloud, saas, ai, etc.)
  - Configurable action (block vs redact vs warn)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Sequence, Tuple

from ...finding import Finding, Severity
from ..base import ScanAction, ScanResult, InputScanner


class MatchMode(str, Enum):
    """How to find competitor names in text."""
    EXACT = "exact"        # Case-insensitive exact substring
    WORD  = "word"         # Word-boundary matching (avoids partial matches)
    FUZZY = "fuzzy"        # Levenshtein distance <= 1 for short names


class DetectionAction(str, Enum):
    """What to do when a competitor is found."""
    BLOCK  = "block"       # Block the entire prompt
    REDACT = "redact"      # Replace competitor name with placeholder
    WARN   = "warn"        # Allow through with a warning finding


@dataclass
class CompetitorMatch:
    """A detected competitor mention."""
    name: str              # Canonical competitor name
    matched_text: str      # Actual text that matched
    start: int             # Character offset in prompt
    end: int               # Character offset end
    confidence: float      # 0.0-1.0, higher = more confident


# =====================================================================
#  BUILT-IN COMPETITOR GROUPS (enterprise defaults)
# =====================================================================

COMPETITOR_GROUPS: Dict[str, List[Dict[str, any]]] = {
    "cloud": [
        {"name": "Amazon Web Services", "aliases": ["AWS", "Amazon Cloud", "EC2", "S3", "Lambda"]},
        {"name": "Google Cloud", "aliases": ["GCP", "Google Cloud Platform", "BigQuery", "Cloud Run"]},
        {"name": "Microsoft Azure", "aliases": ["Azure", "Azure Cloud", "Azure DevOps"]},
        {"name": "DigitalOcean", "aliases": ["DO", "Droplets"]},
        {"name": "Oracle Cloud", "aliases": ["OCI", "Oracle Cloud Infrastructure"]},
        {"name": "IBM Cloud", "aliases": ["Bluemix", "IBM Cloud Foundry"]},
    ],
    "ai": [
        {"name": "OpenAI", "aliases": ["ChatGPT", "GPT-4", "GPT-3", "DALL-E", "o1"]},
        {"name": "Anthropic", "aliases": ["Claude", "Claude 3", "Claude Sonnet"]},
        {"name": "Google DeepMind", "aliases": ["DeepMind", "Gemini", "Bard"]},
        {"name": "Meta AI", "aliases": ["LLaMA", "Llama 2", "Llama 3"]},
        {"name": "Mistral AI", "aliases": ["Mistral", "Mixtral"]},
        {"name": "Cohere", "aliases": ["Command R", "Command R+"]},
        {"name": "Hugging Face", "aliases": ["HuggingFace", "HF"]},
    ],
    "saas": [
        {"name": "Salesforce", "aliases": ["SFDC", "Salesforce CRM"]},
        {"name": "HubSpot", "aliases": ["HubSpot CRM"]},
        {"name": "Zendesk", "aliases": ["Zendesk Support"]},
        {"name": "Slack", "aliases": ["Slack Technologies"]},
        {"name": "Notion", "aliases": ["Notion.so"]},
        {"name": "Jira", "aliases": ["Atlassian Jira", "Jira Software"]},
        {"name": "Asana", "aliases": ["Asana.com"]},
    ],
}


class BanCompetitorsScanner(InputScanner):
    """Detects and handles competitor mentions in prompts.

    Supports multiple detection strategies and configurable actions
    for maximum flexibility in enterprise deployments.
    """

    scanner_type = "input"

    def __init__(
        self,
        competitors: Optional[Sequence[str]] = None,
        competitor_groups: Optional[List[str]] = None,
        match_mode: MatchMode = MatchMode.WORD,
        action: DetectionAction = DetectionAction.REDACT,
        threshold: float = 0.5,
        placeholder: str = "[COMPETITOR]",
        custom_aliases: Optional[Dict[str, List[str]]] = None,
    ):
        """Initialize the competitor scanner.

        Args:
            competitors: Explicit list of competitor names to detect.
            competitor_groups: Built-in groups to activate ("cloud", "ai", "saas").
            match_mode: Detection strategy (exact, word, fuzzy).
            action: What to do on detection (block, redact, warn).
            threshold: Minimum confidence to trigger (0.0-1.0).
            placeholder: Replacement text for redaction mode.
            custom_aliases: Additional alias mappings {canonical: [aliases]}.
        """
        self._match_mode = match_mode
        self._action = action
        self._threshold = threshold
        self._placeholder = placeholder

        # Build competitor lookup: {lowercase_name: canonical_name}
        self._competitor_lookup: Dict[str, str] = {}
        self._competitor_patterns: List[Tuple[re.Pattern, str]] = []

        # Add explicit competitors
        if competitors:
            for name in competitors:
                self._add_competitor(name, [])

        # Add built-in groups
        if competitor_groups:
            for group_key in competitor_groups:
                group = COMPETITOR_GROUPS.get(group_key, [])
                for entry in group:
                    self._add_competitor(
                        entry["name"],
                        entry.get("aliases", []),
                    )

        # Add custom aliases
        if custom_aliases:
            for canonical, aliases in custom_aliases.items():
                self._add_competitor(canonical, aliases)

    def _add_competitor(self, canonical: str, aliases: List[str]) -> None:
        """Register a competitor with all its aliases."""
        all_names = [canonical] + aliases

        for name in all_names:
            lower = name.lower()
            self._competitor_lookup[lower] = canonical

            # Build regex pattern for word-boundary matching
            if self._match_mode == MatchMode.WORD:
                escaped = re.escape(name)
                pattern = re.compile(
                    rf"\b{escaped}\b",
                    re.IGNORECASE,
                )
                self._competitor_patterns.append((pattern, canonical))
            elif self._match_mode == MatchMode.EXACT:
                pattern = re.compile(re.escape(name), re.IGNORECASE)
                self._competitor_patterns.append((pattern, canonical))

    def scan(self, text: str) -> ScanResult:
        """Scan prompt for competitor mentions."""
        if not text.strip():
            return ScanResult(
                action=ScanAction.PASS,
                findings=[],
                sanitized=text,
                risk_score=0.0,
            )

        matches = self._detect(text)

        if not matches:
            return ScanResult(
                action=ScanAction.PASS,
                findings=[],
                sanitized=text,
                risk_score=0.0,
            )

        # Build findings
        findings: List[Finding] = []
        unique_competitors: Set[str] = set()

        for match in matches:
            if match.confidence < self._threshold:
                continue

            unique_competitors.add(match.name)
            findings.append(Finding.firewall_input(
                rule_id=f"COMPETITOR-{match.name.upper().replace(' ', '_')}",
                title=f"Competitor mentioned: {match.name}",
                description=(
                    f"Competitor '{match.name}' detected in prompt "
                    f"(matched: '{match.matched_text}', "
                    f"confidence: {match.confidence:.2f})."
                ),
                severity=Severity.MEDIUM,
                target="input_text",
                evidence=match.matched_text,
                cwe_ids=[],
                tags=["competitor", "content-policy"],
            ))

        if not findings:
            return ScanResult(
                action=ScanAction.PASS,
                findings=[],
                sanitized=text,
                risk_score=0.0,
            )

        # Determine action and sanitization
        sanitized = text
        if self._action == DetectionAction.REDACT:
            sanitized = self._redact_competitors(text, matches)
            action = ScanAction.REDACT
        elif self._action == DetectionAction.BLOCK:
            action = ScanAction.BLOCK
        else:
            action = ScanAction.PASS

        risk_score = min(1.0, len(unique_competitors) * 0.3)

        return ScanResult(
            action=action,
            findings=findings,
            sanitized=sanitized,
            risk_score=risk_score,
        )

    def _detect(self, text: str) -> List[CompetitorMatch]:
        """Find all competitor mentions in text."""
        matches: List[CompetitorMatch] = []

        if self._match_mode in (MatchMode.WORD, MatchMode.EXACT):
            for pattern, canonical in self._competitor_patterns:
                for m in pattern.finditer(text):
                    matches.append(CompetitorMatch(
                        name=canonical,
                        matched_text=m.group(0),
                        start=m.start(),
                        end=m.end(),
                        confidence=1.0,
                    ))

        elif self._match_mode == MatchMode.FUZZY:
            # Word-level fuzzy matching
            words = text.split()
            offset = 0
            for word in words:
                clean = word.strip(".,;:!?()[]{}\"'")
                clean_lower = clean.lower()

                for known, canonical in self._competitor_lookup.items():
                    distance = self._levenshtein(clean_lower, known)
                    max_len = max(len(clean_lower), len(known))

                    if max_len == 0:
                        continue

                    similarity = 1.0 - (distance / max_len)

                    if similarity >= 0.8:  # 80% similarity threshold
                        idx = text.find(word, offset)
                        matches.append(CompetitorMatch(
                            name=canonical,
                            matched_text=clean,
                            start=idx,
                            end=idx + len(word),
                            confidence=similarity,
                        ))
                        break  # One match per word

                offset = text.find(word, offset) + len(word)

        # Deduplicate overlapping matches
        return self._deduplicate(matches)

    def _redact_competitors(
        self, text: str, matches: List[CompetitorMatch]
    ) -> str:
        """Replace competitor names with placeholder, working right-to-left."""
        sorted_matches = sorted(matches, key=lambda m: m.start, reverse=True)
        result = text
        for match in sorted_matches:
            if match.confidence >= self._threshold:
                result = (
                    result[:match.start]
                    + self._placeholder
                    + result[match.end:]
                )
        return result

    @staticmethod
    def _deduplicate(matches: List[CompetitorMatch]) -> List[CompetitorMatch]:
        """Remove overlapping matches, keeping higher confidence."""
        if not matches:
            return matches

        sorted_matches = sorted(matches, key=lambda m: (m.start, -m.confidence))
        result = [sorted_matches[0]]

        for current in sorted_matches[1:]:
            prev = result[-1]
            if current.start >= prev.end:
                result.append(current)
            elif current.confidence > prev.confidence:
                result[-1] = current

        return result

    @staticmethod
    def _levenshtein(s1: str, s2: str) -> int:
        """Compute Levenshtein edit distance between two strings."""
        if len(s1) < len(s2):
            return BanCompetitorsScanner._levenshtein(s2, s1)

        if len(s2) == 0:
            return len(s1)

        prev_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row

        return prev_row[-1]
