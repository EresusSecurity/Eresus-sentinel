"""
Eresus Sentinel — Regulatory Compliance Scanner (Output).

Detects regulatory violations in LLM responses that could create
legal liability.

Features:
  - GDPR compliance: personal data handling violations
  - HIPAA: medical diagnosis/treatment language without disclaimer
  - Financial: investment advice without proper disclaimers
  - Legal: unauthorized legal counsel patterns
  - Age verification: content requiring age restrictions
  - Disclaimer enforcement: missing required disclaimers
  - OutputScanner-compliant with Finding/ScanResult



"""

from __future__ import annotations

import logging
import re

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import OutputScanner, ScanAction, ScanResult

logger = logging.getLogger(__name__)


_COMPLIANCE_RULES: dict[str, list[tuple[re.Pattern, float, str, str]]] = {
    # (pattern, severity, description, remediation)
    "hipaa_medical": [
        (re.compile(r"\b(?:you (?:have|suffer from|are diagnosed with)|your diagnosis is|I diagnose you with)\b", re.I),
         0.9, "Direct medical diagnosis without disclaimer", "Add medical disclaimer. Direct user to healthcare professional."),
        (re.compile(r"\b(?:take|prescribe|recommend)\s+\d+\s*(?:mg|ml|tablets?|pills?|capsules?)\s+(?:of|daily|twice)\b", re.I),
         0.95, "Specific medication dosage recommendation", "Remove dosage. Add 'consult your doctor' disclaimer."),
        (re.compile(r"\b(?:stop taking|discontinue|reduce (?:your )?(?:dosage|medication))\b", re.I),
         0.9, "Medication discontinuation advice", "Never advise medication changes without medical supervision."),
        (re.compile(r"\b(?:your (?:blood pressure|heart rate|lab results|test results) (?:show|indicate|suggest))\b", re.I),
         0.8, "Medical results interpretation", "Refer to healthcare provider for result interpretation."),
    ],
    "financial_advice": [
        (re.compile(r"\b(?:you should (?:buy|sell|invest in|short)|I recommend (?:buying|selling|investing))\b", re.I),
         0.85, "Direct investment recommendation", "Add financial disclaimer. State 'not financial advice'."),
        (re.compile(r"\b(?:guaranteed (?:return|profit|income)|risk[- ]free (?:investment|return))\b", re.I),
         0.95, "Guaranteed returns claim (illegal in most jurisdictions)", "Remove guaranteed return language. All investments carry risk."),
        (re.compile(r"\b(?:this stock will|the market will (?:definitely|certainly)|price will (?:go up|increase|rise))\b", re.I),
         0.85, "Market prediction stated as fact", "Use hedging language. State predictions are not guaranteed."),
        (re.compile(r"\b(?:insider (?:information|tip|knowledge)|non-public (?:information|data))\b", re.I),
         0.98, "Reference to insider information (SEC violation)", "Remove immediately. Insider trading references are illegal."),
    ],
    "legal_counsel": [
        (re.compile(r"\b(?:I advise you to (?:sue|file|plead)|you should (?:sue|press charges|file a lawsuit))\b", re.I),
         0.8, "Unauthorized legal counsel", "Add legal disclaimer. Recommend consulting an attorney."),
        (re.compile(r"\b(?:this constitutes|you have a case for|grounds for (?:a )?lawsuit|legally binding)\b", re.I),
         0.75, "Legal conclusion without qualification", "State this is not legal advice. Consult a licensed attorney."),
        (re.compile(r"\b(?:statute of limitations is|the law (?:requires|states) that you)\b", re.I),
         0.7, "Specific legal interpretation", "Note that laws vary by jurisdiction and change over time."),
    ],
    "gdpr_privacy": [
        (re.compile(r"\b(?:their (?:home )?address is|lives at|phone number is|email is)\b.{0,50}\b(?:\d|@)\b", re.I),
         0.95, "Personal data disclosure (GDPR Art. 5)", "Remove PII. Never disclose personal data without consent."),
        (re.compile(r"\b(?:social security|SSN|national insurance|tax (?:ID|identification))\s*(?:number|#)?\s*(?:is|:)\s*\d", re.I),
         0.99, "Government ID disclosure (critical GDPR violation)", "Remove immediately. Government IDs must never be disclosed."),
    ],
    "age_restricted": [
        (re.compile(r"\b(?:instructions for|how to|guide to)\s+(?:making|brewing|distilling)\s+(?:alcohol|beer|wine|moonshine)\b", re.I),
         0.6, "Alcohol production instructions (age-restricted)", "Add age verification notice."),
        (re.compile(r"\b(?:gambling|betting)\s+(?:strategy|tips|how to win)\b", re.I),
         0.6, "Gambling advice (age-restricted)", "Add gambling disclaimer and age restriction notice."),
    ],
    "disclaimer_missing": [
        (re.compile(r"\b(?:this (?:is|will) (?:cure|treat|heal)|proven to (?:cure|treat|eliminate))\b", re.I),
         0.9, "Health claim without evidence disclaimer", "Add FDA/evidence disclaimer."),
        (re.compile(r"\b(?:100% (?:safe|effective|guaranteed)|no side effects|completely (?:safe|harmless))\b", re.I),
         0.85, "Absolute safety/efficacy claim", "Remove absolute claims. Nothing is 100% safe or effective."),
    ],
}


class ComplianceScanner(OutputScanner):
    """
    Detects regulatory compliance violations in LLM responses.

    Categories:
      - HIPAA: medical advice, dosage, diagnosis
      - Financial: investment advice, guaranteed returns
      - Legal: unauthorized counsel
      - GDPR: personal data disclosure
      - Age-restricted content
      - Missing disclaimers

    Usage:
        scanner = ComplianceScanner()
        result = scanner.scan(prompt, response)
    """

    def __init__(
        self,
        categories: list[str] | None = None,
        threshold: float = 0.6,
    ):
        self._categories = categories or list(_COMPLIANCE_RULES.keys())
        self._threshold = threshold

    _NEGATION_WINDOW = re.compile(
        r"(?i)(?:not|never|don'?t|shouldn'?t|cannot|should not|must not|"
        r"it(?:'s| is) (?:wrong|incorrect|inappropriate|unethical|illegal) to|"
        r"avoid|refrain from|example of what not to|"
        r"for (?:example|instance)|such as|e\.g\.|"
        r"[\"\u201c\u2018].{0,120}[\"\u201d\u2019])"
    )

    def scan(self, prompt: str, output: str) -> ScanResult:
        if not output or len(output.strip()) < 15:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        findings = []
        for category in self._categories:
            rules = _COMPLIANCE_RULES.get(category, [])
            for pattern, severity, description, remediation in rules:
                match = pattern.search(output)
                if match and severity >= self._threshold:
                    start = max(0, match.start() - 80)
                    context_window = output[start:match.start()]
                    if self._NEGATION_WINDOW.search(context_window):
                        severity = max(0.0, severity - 0.3)
                        if severity < self._threshold:
                            continue

                    findings.append(Finding.firewall_output(
                        rule_id="FIREWALL-OUTPUT-100",
                        title=f"Compliance violation: {category}",
                        description=f"{description}. Match: '{match.group(0)[:80]}'",
                        severity=Severity.HIGH if severity >= 0.9 else Severity.MEDIUM,
                        confidence=severity,
                        target="<response>",
                        evidence=f"Category: {category}, Pattern: {match.group(0)[:120]}",
                        cwe_ids=["CWE-1021"],
                        tags=["category:compliance", f"regulation:{category}"],
                        remediation=remediation,
                    ))

        if not findings:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        max_confidence = max(f.confidence for f in findings)
        categories_found = list(set(
            t.split(":")[-1] for f in findings for t in f.tags if t.startswith("regulation:")
        ))

        action = ScanAction.BLOCK if max_confidence >= 0.95 else ScanAction.WARN

        return ScanResult(
            sanitized=output,
            action=action,
            risk_score=round(max_confidence * 0.9, 4),
            findings=findings,
            metadata={
                "violations": categories_found,
                "finding_count": len(findings),
            },
        )
