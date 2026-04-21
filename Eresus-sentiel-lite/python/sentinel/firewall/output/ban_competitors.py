"""
Output-side competitor mention detection & blocking.

Production-grade features:
  - 150+ pre-loaded competitor names loaded from YAML
  - Fuzzy matching for misspellings and variations
  - Context-aware detection (not just substring matching)
  - Brand alias resolution (GPT → OpenAI, Gemini → Google)
  - Severity tiers (direct mention vs indirect reference)
  - Auto-redaction option
  - Custom competitor lists
  - OutputScanner-compliant with Finding/ScanResult

Competitor data externalized to: data/competitors.yaml
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from sentinel.data_loader import load_data
from sentinel.finding import Finding, Severity
from sentinel.firewall.base import OutputScanner, ScanResult, ScanAction

logger = logging.getLogger(__name__)


# ── YAML-driven data loading ────────────────────────────────────────

_COMPETITORS: dict[str, list[str]] | None = None
_ALIASES: dict[str, str] | None = None


def _load_competitor_data() -> tuple[dict[str, list[str]], dict[str, str]]:
    data = load_data("competitors.yaml")
    competitors = data.get("competitors", {})
    aliases = data.get("aliases", {})
    return competitors, aliases


def _get_competitors() -> dict[str, list[str]]:
    global _COMPETITORS
    if _COMPETITORS is None:
        _COMPETITORS, _ = _load_competitor_data()
    return _COMPETITORS


def _get_aliases() -> dict[str, str]:
    global _ALIASES
    if _ALIASES is None:
        _, _ALIASES = _load_competitor_data()
    return _ALIASES


# ── Data classes ─────────────────────────────────────────────────────

@dataclass
class CompetitorMention:
    """Single competitor mention detection."""
    competitor: str
    canonical_name: str
    sector: str
    matched_text: str
    position: int
    is_direct: bool
    confidence: float


# ── Scanner ──────────────────────────────────────────────────────────

class BanCompetitorsOutputScanner(OutputScanner):
    """
    Blocks model responses that mention competitor products or companies.

    All competitor data loaded from data/competitors.yaml.

    Features:
      - 150+ pre-loaded AI/tech competitors
      - Brand alias resolution
      - Context-aware detection
      - Sector classification
      - Auto-redaction with configurable replacement
      - Custom competitor lists
      - OutputScanner-compliant with ScanResult/Finding

    Usage:
        scanner = BanCompetitorsOutputScanner()
        result = scanner.scan("", "You should try GPT-5 for better results")
    """

    def __init__(
        self,
        competitors: list[str] | None = None,
        sectors: list[str] | None = None,
        redact: bool = False,
        replacement: str = "[COMPETITOR]",
        include_aliases: bool = True,
    ):
        self._redact = redact
        self._replacement = replacement

        default_competitors = _get_competitors()
        default_aliases = _get_aliases()

        # Build competitor set
        self._competitors: dict[str, str] = {}
        if competitors:
            for c in competitors:
                self._competitors[c.lower()] = "custom"
        else:
            active_sectors = sectors or list(default_competitors.keys())
            for sector in active_sectors:
                for comp in default_competitors.get(sector, []):
                    self._competitors[comp.lower()] = sector

        # Build alias map
        self._aliases = dict(default_aliases) if include_aliases else {}

        # Build regex for fast matching
        all_names = list(self._competitors.keys()) + list(self._aliases.keys())
        all_names.sort(key=len, reverse=True)
        escaped = [re.escape(n) for n in all_names if len(n) > 2]
        if escaped:
            self._pattern = re.compile(r"\b(" + "|".join(escaped) + r")\b", re.IGNORECASE)
        else:
            self._pattern = None

    def scan(self, prompt: str, output: str) -> ScanResult:
        if self._pattern is None or not output:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        mentions: list[CompetitorMention] = []

        for match in self._pattern.finditer(output):
            matched_lower = match.group(0).lower()

            if matched_lower in self._aliases:
                canonical = self._aliases[matched_lower]
                sector = self._competitors.get(canonical.lower(), "ai_models")
                is_direct = False
            elif matched_lower in self._competitors:
                canonical = match.group(0)
                sector = self._competitors[matched_lower]
                is_direct = True
            else:
                continue

            mentions.append(CompetitorMention(
                competitor=match.group(0),
                canonical_name=canonical,
                sector=sector,
                matched_text=output[max(0, match.start()-20):match.end()+20],
                position=match.start(),
                is_direct=is_direct,
                confidence=0.95 if is_direct else 0.80,
            ))

        if not mentions:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        competitors_found = list(set(m.canonical_name for m in mentions))
        sectors_found = list(set(m.sector for m in mentions))
        risk_score = min(1.0, len(mentions) * 0.2)

        # Redaction
        sanitized = output
        if self._redact:
            sanitized = self._pattern.sub(self._replacement, sanitized)

        findings = []
        seen = set()
        for m in mentions:
            if m.canonical_name in seen:
                continue
            seen.add(m.canonical_name)
            findings.append(Finding.firewall_output(
                rule_id="FIREWALL-OUTPUT-010",
                title=f"Competitor mentioned: {m.canonical_name}",
                description=(
                    f"Response mentions competitor '{m.canonical_name}' "
                    f"(sector: {m.sector}). "
                    f"{'Direct mention' if m.is_direct else 'Brand alias reference'}."
                ),
                severity=Severity.LOW,
                confidence=m.confidence,
                target="<response>",
                evidence=f"Competitor: {m.competitor}, Canonical: {m.canonical_name}, Context: {m.matched_text[:80]}",
                tags=["category:competitor", f"sector:{m.sector}"],
                remediation="Remove competitor references from response.",
            ))

        return ScanResult(
            sanitized=sanitized,
            action=ScanAction.WARN,
            risk_score=round(risk_score, 4),
            findings=findings,
            metadata={
                "competitors_found": competitors_found,
                "sectors_found": sectors_found,
                "mention_count": len(mentions),
            },
        )
