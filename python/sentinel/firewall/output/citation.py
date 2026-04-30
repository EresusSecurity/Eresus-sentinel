"""
Eresus Sentinel — Source Attribution / Citation Scanner (Output).

Detects unsourced claims, fabricated citations, and hallucinated references
in LLM responses.

Features:
  - DOI / arXiv / PMID format validation
  - URL format and structure checking
  - "According to" without verifiable source detection
  - Fabricated journal/author pattern detection
  - Citation completeness scoring
  - OutputScanner-compliant with Finding/ScanResult



"""

from __future__ import annotations

import logging
import re

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import OutputScanner, ScanAction, ScanResult

logger = logging.getLogger(__name__)


# ── Citation format patterns ──────────────────────────────────────

_DOI_PATTERN = re.compile(r"\bdoi\s*:\s*(10\.\d{4,}/[^\s]+)", re.I)
_ARXIV_PATTERN = re.compile(r"\barXiv\s*:\s*(\d{4}\.\d{4,5}(?:v\d+)?)", re.I)
_PMID_PATTERN = re.compile(r"\bPMID\s*:\s*(\d{7,8})", re.I)
_URL_CITATION = re.compile(r"(?:source|reference|see|from|available at)\s*:\s*(https?://[^\s)<]+)", re.I)

# "According to" without specific source
_VAGUE_ATTRIBUTION = re.compile(
    r"\b(?:according to|based on|as (?:stated|reported|noted) (?:by|in))\s+"
    r"(?:some|many|various|numerous|several|multiple|certain|a number of)\s+"
    r"(?:studies|experts?|sources?|researchers?|reports?|articles?|scientists?)\b",
    re.I,
)

# Specific attribution (good)
_SPECIFIC_ATTRIBUTION = re.compile(
    r"\b(?:according to|based on|as (?:stated|reported) (?:by|in))\s+"
    r"(?:[A-Z][a-z]+(?:\s+(?:et\s+al\.?|and\s+[A-Z][a-z]+))?|"
    r"the\s+(?:WHO|CDC|FDA|NIH|EPA|NIST|IEEE|ACM))\b",
)

# Fabricated citation patterns
_FAKE_JOURNAL = re.compile(
    r"(?:Journal of (?:Advanced|Modern|International|Global)\s+(?:Studies|Research|Science|Technology))\s*"
    r"(?:\(\d{4}\)|\d{4})",
    re.I,
)

_FAKE_AUTHOR = re.compile(
    r"(?:Dr\.\s+)?(?:Smith|Johnson|Williams|Brown|Jones|Davis)\s+(?:et\s+al\.?)\s*"
    r"\(\d{4}\)",
)

# Hedged claims that should have citations
_UNSOURCED_CLAIMS = [
    re.compile(r"\b(?:studies (?:show|have shown|suggest|indicate|prove|confirm))\b", re.I),
    re.compile(r"\b(?:research (?:shows|has shown|suggests|indicates|confirms|proves))\b", re.I),
    re.compile(r"\b(?:scientists (?:have found|discovered|believe|agree))\b", re.I),
    re.compile(r"\b(?:it (?:has been|is) (?:proven|demonstrated|established|shown) that)\b", re.I),
    re.compile(r"\b(?:evidence (?:shows|suggests|indicates|supports))\b", re.I),
    re.compile(r"\b(?:data (?:shows|suggests|indicates|reveals))\b", re.I),
]


class CitationScanner(OutputScanner):
    """
    Detects unsourced claims and fabricated citations in LLM outputs.

    Features:
      - DOI/arXiv/PMID format validation
      - Vague attribution detection ("according to some studies")
      - Fabricated journal/author detection
      - Unsourced claim flagging
      - Citation completeness scoring

    Usage:
        scanner = CitationScanner()
        result = scanner.scan(prompt, response)
    """

    def __init__(
        self,
        require_citations: bool = False,
        flag_vague: bool = True,
    ):
        self._require_citations = require_citations
        self._flag_vague = flag_vague

    def scan(self, prompt: str, output: str) -> ScanResult:
        if not output or len(output.strip()) < 30:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        findings = []

        # Count formal citations
        dois = _DOI_PATTERN.findall(output)
        arxivs = _ARXIV_PATTERN.findall(output)
        pmids = _PMID_PATTERN.findall(output)
        url_refs = _URL_CITATION.findall(output)
        formal_citations = len(dois) + len(arxivs) + len(pmids) + len(url_refs)

        # Vague attribution
        vague_matches = list(_VAGUE_ATTRIBUTION.finditer(output))
        if self._flag_vague and vague_matches:
            for match in vague_matches[:3]:
                findings.append(Finding.firewall_output(
                    rule_id="FIREWALL-OUTPUT-110",
                    title="Vague attribution detected",
                    description=(
                        f"Response uses vague attribution without specific source: "
                        f"'{match.group(0)[:80]}'"
                    ),
                    severity=Severity.LOW,
                    confidence=0.7,
                    target="<response>",
                    evidence=f"Match: {match.group(0)[:120]}",
                    tags=["category:citation", "citation:vague_attribution"],
                    remediation="Replace with specific source or add caveat.",
                ))

        # Fabricated citation detection
        fake_journals = list(_FAKE_JOURNAL.finditer(output))
        for match in fake_journals:
            findings.append(Finding.firewall_output(
                rule_id="FIREWALL-OUTPUT-111",
                title="Possibly fabricated journal citation",
                description=(
                    f"Response cites a potentially fabricated journal: "
                    f"'{match.group(0)[:100]}'"
                ),
                severity=Severity.MEDIUM,
                confidence=0.75,
                target="<response>",
                evidence=f"Journal: {match.group(0)[:120]}",
                tags=["category:citation", "citation:fabricated_journal"],
                remediation="Verify journal exists. Use real publication references.",
            ))

        fake_authors = list(_FAKE_AUTHOR.finditer(output))
        for match in fake_authors:
            findings.append(Finding.firewall_output(
                rule_id="FIREWALL-OUTPUT-112",
                title="Generic author citation (possible hallucination)",
                description=(
                    f"Response cites a generic author name: "
                    f"'{match.group(0)[:80]}'"
                ),
                severity=Severity.LOW,
                confidence=0.6,
                target="<response>",
                evidence=f"Author: {match.group(0)[:100]}",
                tags=["category:citation", "citation:generic_author"],
                remediation="Verify author and publication exist.",
            ))

        # Unsourced claims
        unsourced_count = 0
        for pattern in _UNSOURCED_CLAIMS:
            matches = list(pattern.finditer(output))
            unsourced_count += len(matches)

        if unsourced_count > 0 and formal_citations == 0:
            findings.append(Finding.firewall_output(
                rule_id="FIREWALL-OUTPUT-113",
                title=f"Unsourced claims: {unsourced_count} claims, 0 citations",
                description=(
                    f"Response makes {unsourced_count} claims referencing "
                    f"studies/research but provides no formal citations."
                ),
                severity=Severity.MEDIUM if unsourced_count > 3 else Severity.LOW,
                confidence=min(1.0, 0.5 + unsourced_count * 0.1),
                target="<response>",
                evidence=f"Unsourced claims: {unsourced_count}, Formal citations: 0",
                tags=["category:citation", "citation:unsourced"],
                remediation="Add specific citations or soften claims.",
            ))

        if not findings:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        max_confidence = max(f.confidence for f in findings)
        return ScanResult(
            sanitized=output,
            action=ScanAction.WARN,
            risk_score=round(max_confidence * 0.5, 4),
            findings=findings,
            metadata={
                "formal_citations": formal_citations,
                "vague_attributions": len(vague_matches),
                "unsourced_claims": unsourced_count,
                "fake_journals": len(fake_journals),
            },
        )
