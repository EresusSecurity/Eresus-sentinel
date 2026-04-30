"""
Malicious URL Scanner.

Detects malicious URLs (phishing, malware, defacement) in LLM outputs
before they reach the user.

Capabilities:
- URL extraction via regex
- ML-based classification using CodeBERT (when available)
- Blocklist-based fallback
"""

from __future__ import annotations

import logging
import re
from typing import Optional
from urllib.parse import urlparse

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import OutputScanner, ScanAction, ScanResult

logger = logging.getLogger(__name__)

# URL extraction regex
URL_PATTERN = re.compile(
    r"https?://[^\s<>\"'\)\]\}]{5,}|"
    r"www\.[^\s<>\"'\)\]\}]{5,}",
    re.IGNORECASE,
)

# Known malicious TLD patterns
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",  # Free TLDs heavily abused
    ".xyz", ".top", ".work", ".click",
    ".zip", ".mov",  # Confusable with file extensions
}

# Known phishing domain patterns
PHISHING_PATTERNS = [
    re.compile(r"(?i)login.*(?:secure|verify|update|confirm)"),
    re.compile(r"(?i)(?:paypal|apple|google|microsoft|amazon).*(?:verify|secure|login)"),
    re.compile(r"(?i)(?:account|billing|payment).*(?:update|verify|confirm)"),
    re.compile(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"),  # Raw IP URLs
]

# Suspicious URL path patterns
SUSPICIOUS_PATHS = [
    "/wp-admin/", "/admin/login", "/.env",
    "/phpmyadmin/", "/shell", "/cmd",
    "/exec", "/eval", "/../", "/etc/passwd",
]

DEFAULT_MODEL = "DunnBC22/codebert-base-Malicious_URLs"


class MaliciousURLScanner(OutputScanner):
    """
    Detects malicious URLs in LLM outputs.

    Three-tier detection:
    1. ML classifier (CodeBERT, if transformers installed)
    2. Heuristic pattern matching (phishing patterns, suspicious TLDs)
    3. Blocklist checking

    Pipeline: extract all URLs → classify each → aggregate.
    """

    def __init__(
        self,
        model_path: str = DEFAULT_MODEL,
        threshold: float = 0.7,
        use_ml: bool = True,
        blocklist: Optional[set[str]] = None,
    ):
        self._model_path = model_path
        self._threshold = threshold
        self._use_ml = use_ml
        self._blocklist = blocklist or set()
        self._classifier = None
        self._loaded = False

    def scan(self, prompt: str, output: str) -> ScanResult:
        """Scan LLM output for malicious URLs."""
        if not output:
            return ScanResult(
                sanitized=output,
                action=ScanAction.PASS,
                risk_score=0.0,
            )

        urls = self._extract_urls(output)
        if not urls:
            return ScanResult(
                sanitized=output,
                action=ScanAction.PASS,
                risk_score=0.0,
            )

        findings = []
        max_risk = 0.0

        for url in urls:
            result = self._classify_url(url)
            if result:
                category, confidence = result
                findings.append(Finding.firewall_output(
                    rule_id="FIREWALL-OUTPUT-001",
                    title=f"Malicious URL detected: {category}",
                    description=(
                        f"The LLM response contains a potentially malicious URL "
                        f"classified as '{category}' with {confidence:.0%} confidence: "
                        f"{url[:100]}"
                    ),
                    severity=Severity.HIGH if confidence > 0.85 else Severity.MEDIUM,
                    confidence=confidence,
                    target="<output>",
                    evidence=f"URL: {url}, Category: {category}, Confidence: {confidence:.3f}",
                    cwe_ids=["CWE-601"],  # URL Redirection to Untrusted Site
                    tags=["owasp:llm02"],
                    remediation="Remove or replace the malicious URL in the response.",
                ))
                max_risk = max(max_risk, confidence)

        if not findings:
            return ScanResult(
                sanitized=output,
                action=ScanAction.PASS,
                risk_score=0.0,
            )

        return ScanResult(
            sanitized=output,
            action=ScanAction.WARN if max_risk < 0.85 else ScanAction.BLOCK,
            risk_score=max_risk,
            findings=findings,
        )

    def _extract_urls(self, text: str) -> list[str]:
        """Extract all URLs from text."""
        urls = URL_PATTERN.findall(text)
        # Deduplicate while preserving order
        seen = set()
        unique = []
        for url in urls:
            # Clean trailing punctuation
            url = url.rstrip(".,;:!?)")
            if url not in seen:
                seen.add(url)
                unique.append(url)
        return unique

    def _classify_url(self, url: str) -> Optional[tuple[str, float]]:
        """
        Classify a URL as malicious or benign.
        Returns (category, confidence) or None if benign.
        """
        # Tier 1: Blocklist
        parsed = urlparse(url if "://" in url else f"https://{url}")
        domain = parsed.hostname or ""

        if domain in self._blocklist:
            return ("blocklisted", 1.0)

        # Tier 2: Heuristic patterns
        heuristic_result = self._heuristic_check(url, domain, parsed.path)
        if heuristic_result:
            return heuristic_result

        # Tier 3: ML classifier (if available)
        if self._use_ml:
            ml_result = self._ml_classify(url)
            if ml_result:
                return ml_result

        return None

    def _heuristic_check(
        self, url: str, domain: str, path: str
    ) -> Optional[tuple[str, float]]:
        """Heuristic URL classification."""
        # Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                return ("suspicious_tld", 0.6)

        # Phishing patterns
        for pattern in PHISHING_PATTERNS:
            if pattern.search(domain):
                return ("phishing", 0.75)

        # Suspicious paths
        path_lower = path.lower()
        for suspicious_path in SUSPICIOUS_PATHS:
            if suspicious_path in path_lower:
                return ("suspicious_path", 0.7)

        # Raw IP address URL
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
            return ("ip_address", 0.5)

        # Very long subdomain (common in phishing)
        if domain.count(".") > 4:
            return ("excessive_subdomains", 0.55)

        return None

    def _ml_classify(self, url: str) -> Optional[tuple[str, float]]:
        """Classify URL using ML model."""
        if not self._loaded:
            self._loaded = True
            try:
                from transformers import (
                    AutoModelForSequenceClassification,
                    AutoTokenizer,
                    TextClassificationPipeline,
                )
                tokenizer = AutoTokenizer.from_pretrained(self._model_path)
                model = AutoModelForSequenceClassification.from_pretrained(self._model_path)
                self._classifier = TextClassificationPipeline(
                    model=model, tokenizer=tokenizer,
                    top_k=None, truncation=True, max_length=512,
                )
            except Exception as e:
                logger.debug("ML URL classifier unavailable: %s", e)
                return None

        if not self._classifier:
            return None

        try:
            results = self._classifier(url)
            for result_set in results:
                if isinstance(result_set, list):
                    for item in result_set:
                        label = item.get("label", "").lower()
                        score = item.get("score", 0.0)
                        if label in ("malware", "phishing", "defacement") and score > self._threshold:
                            return (label, score)
                elif isinstance(result_set, dict):
                    label = result_set.get("label", "").lower()
                    score = result_set.get("score", 0.0)
                    if label in ("malware", "phishing", "defacement") and score > self._threshold:
                        return (label, score)
        except Exception as e:
            logger.warning("ML URL classification error: %s", e)

        return None
