"""Compliance framework mapper -- maps findings to regulatory frameworks.

Supports:
- NIST AI RMF (AI 100-1)
- OWASP LLM Top 10 2025
- OWASP Agentic AI Top 10
- EU AI Act risk categories
- MITRE ATLAS
- ISO 42001 (AI management system)
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ComplianceControl:
    framework: str
    control_id: str
    name: str
    description: str
    subcategory: str = ""


@dataclass
class ComplianceMapping:
    finding_category: str
    controls: list[ComplianceControl] = field(default_factory=list)
    gap_analysis: str = ""
    risk_level: str = ""


NIST_AI_RMF_CONTROLS: list[ComplianceControl] = [
    ComplianceControl("NIST AI RMF", "GOVERN-1.1", "Legal and regulatory requirements",
                      "Identify applicable legal and regulatory requirements for AI systems"),
    ComplianceControl("NIST AI RMF", "GOVERN-1.2", "Trustworthy AI characteristics",
                      "Align AI system properties with trustworthiness characteristics"),
    ComplianceControl("NIST AI RMF", "GOVERN-2.1", "Roles and responsibilities",
                      "Define roles and responsibilities for AI risk management"),
    ComplianceControl("NIST AI RMF", "GOVERN-3.1", "Risk management integration",
                      "Integrate AI risk management into organizational processes"),
    ComplianceControl("NIST AI RMF", "GOVERN-4.1", "Organizational practices",
                      "Establish organizational practices for AI risk management"),
    ComplianceControl("NIST AI RMF", "MAP-1.1", "Intended purpose",
                      "Document the intended purpose and context of the AI system"),
    ComplianceControl("NIST AI RMF", "MAP-1.5", "Organizational risk tolerances",
                      "Define risk tolerances for AI system deployment"),
    ComplianceControl("NIST AI RMF", "MAP-2.1", "Categorize AI system",
                      "Categorize the AI system according to its risk profile"),
    ComplianceControl("NIST AI RMF", "MAP-2.3", "Scientific integrity",
                      "Ensure scientific integrity of AI system claims"),
    ComplianceControl("NIST AI RMF", "MAP-3.1", "Benefits and costs",
                      "Assess potential benefits and costs of the AI system"),
    ComplianceControl("NIST AI RMF", "MAP-5.1", "Impact assessment",
                      "Assess positive and negative impacts of the AI system"),
    ComplianceControl("NIST AI RMF", "MEASURE-1.1", "Appropriate methods and metrics",
                      "Use appropriate methods and metrics for AI risk assessment"),
    ComplianceControl("NIST AI RMF", "MEASURE-2.1", "Evaluation of AI system",
                      "Conduct evaluation and testing of the AI system"),
    ComplianceControl("NIST AI RMF", "MEASURE-2.3", "AI system performance",
                      "Measure AI system performance and behavior"),
    ComplianceControl("NIST AI RMF", "MEASURE-2.5", "Bias testing",
                      "Test for harmful bias in AI system outputs"),
    ComplianceControl("NIST AI RMF", "MEASURE-2.6", "Safety testing",
                      "Conduct safety testing including red teaming"),
    ComplianceControl("NIST AI RMF", "MEASURE-2.7", "Security testing",
                      "Assess AI system security and resilience"),
    ComplianceControl("NIST AI RMF", "MEASURE-2.9", "Robustness testing",
                      "Test AI system robustness against adversarial inputs"),
    ComplianceControl("NIST AI RMF", "MEASURE-2.11", "Fairness assessment",
                      "Assess fairness of AI system outputs across populations"),
    ComplianceControl("NIST AI RMF", "MEASURE-3.1", "Feedback mechanisms",
                      "Implement feedback mechanisms for post-deployment monitoring"),
    ComplianceControl("NIST AI RMF", "MANAGE-1.1", "Risk prioritization",
                      "Prioritize identified AI risks for treatment"),
    ComplianceControl("NIST AI RMF", "MANAGE-2.1", "Risk response",
                      "Plan and implement responses to AI risks"),
    ComplianceControl("NIST AI RMF", "MANAGE-3.1", "Risk monitoring",
                      "Monitor AI risks on an ongoing basis"),
    ComplianceControl("NIST AI RMF", "MANAGE-4.1", "Risk documentation",
                      "Document and communicate AI risk management activities"),
]

EU_AI_ACT_CONTROLS: list[ComplianceControl] = [
    ComplianceControl("EU AI Act", "ART-9", "Risk management system",
                      "Establish a risk management system for high-risk AI"),
    ComplianceControl("EU AI Act", "ART-10", "Data governance",
                      "Ensure quality of training and validation datasets"),
    ComplianceControl("EU AI Act", "ART-11", "Technical documentation",
                      "Maintain technical documentation for the AI system"),
    ComplianceControl("EU AI Act", "ART-13", "Transparency",
                      "Design AI systems to enable appropriate transparency"),
    ComplianceControl("EU AI Act", "ART-14", "Human oversight",
                      "Design AI systems for effective human oversight"),
    ComplianceControl("EU AI Act", "ART-15", "Accuracy, robustness, cybersecurity",
                      "Achieve appropriate levels of accuracy, robustness, and cybersecurity"),
    ComplianceControl("EU AI Act", "ART-52", "Transparency for AI interaction",
                      "Notify users they are interacting with an AI system"),
    ComplianceControl("EU AI Act", "ART-5", "Prohibited practices",
                      "Do not deploy AI systems with unacceptable risk"),
]

ISO_42001_CONTROLS: list[ComplianceControl] = [
    ComplianceControl("ISO 42001", "6.1.2", "AI risk assessment",
                      "Process for identifying and assessing AI-specific risks"),
    ComplianceControl("ISO 42001", "6.1.3", "AI risk treatment",
                      "Apply appropriate controls to treat AI risks"),
    ComplianceControl("ISO 42001", "A.5.2", "AI system impact assessment",
                      "Conduct impact assessments for AI systems"),
    ComplianceControl("ISO 42001", "A.6.2", "Data for AI systems",
                      "Ensure quality and integrity of data used in AI systems"),
    ComplianceControl("ISO 42001", "A.7.2", "AI system testing",
                      "Test AI systems before deployment"),
    ComplianceControl("ISO 42001", "A.8.2", "AI system monitoring",
                      "Monitor AI system performance and behavior"),
    ComplianceControl("ISO 42001", "A.9.3", "Third-party AI components",
                      "Manage risks from third-party AI components"),
]

FINDING_TO_CONTROL_MAP: dict[str, list[str]] = {
    "prompt_injection": [
        "MEASURE-2.6", "MEASURE-2.7", "MEASURE-2.9", "ART-15",
    ],
    "data_leak": [
        "GOVERN-1.1", "MEASURE-2.6", "ART-13", "ART-15",
    ],
    "supply_chain": [
        "MAP-2.1", "MEASURE-2.7", "ART-10", "A.9.3",
    ],
    "bias": [
        "MEASURE-2.5", "MEASURE-2.11", "GOVERN-1.2", "ART-10",
    ],
    "safety": [
        "MEASURE-2.6", "MANAGE-2.1", "ART-9", "ART-14",
    ],
    "poisoning": [
        "MEASURE-2.9", "MAP-2.1", "ART-10", "A.6.2",
    ],
    "evasion": [
        "MEASURE-2.9", "MEASURE-2.7", "ART-15",
    ],
    "tool_manipulation": [
        "MEASURE-2.7", "MANAGE-2.1", "ART-14",
    ],
    "privilege_escalation": [
        "MEASURE-2.7", "GOVERN-2.1", "ART-14",
    ],
    "exfiltration": [
        "GOVERN-1.1", "MEASURE-2.6", "MANAGE-2.1", "ART-15",
    ],
    "sandbox_escape": [
        "MEASURE-2.7", "MANAGE-2.1", "ART-15",
    ],
    "verifier_sabotage": [
        "MEASURE-2.1", "MEASURE-2.3", "A.7.2",
    ],
    "harmful_content": [
        "MEASURE-2.6", "GOVERN-1.1", "ART-5", "ART-52",
    ],
    "hallucination": [
        "MEASURE-2.3", "MAP-2.3", "ART-13",
    ],
    "denial_of_service": [
        "MEASURE-2.7", "MANAGE-3.1", "ART-15",
    ],
}


class ComplianceMapper:

    def __init__(self):
        self._all_controls: dict[str, ComplianceControl] = {}
        for ctrl in NIST_AI_RMF_CONTROLS + EU_AI_ACT_CONTROLS + ISO_42001_CONTROLS:
            self._all_controls[ctrl.control_id] = ctrl

    def map_finding(self, finding_category: str) -> ComplianceMapping:
        control_ids = FINDING_TO_CONTROL_MAP.get(finding_category, [])
        controls = [
            self._all_controls[cid]
            for cid in control_ids
            if cid in self._all_controls
        ]
        return ComplianceMapping(
            finding_category=finding_category,
            controls=controls,
            risk_level=self._assess_risk(finding_category),
        )

    def map_findings_batch(self, categories: list[str]) -> list[ComplianceMapping]:
        return [self.map_finding(cat) for cat in categories]

    def gap_analysis(self, covered_controls: set[str]) -> list[ComplianceControl]:
        all_ids = set(self._all_controls.keys())
        missing = all_ids - covered_controls
        return [self._all_controls[cid] for cid in sorted(missing)]

    def coverage_report(self, finding_categories: list[str]) -> dict:
        covered = set()
        for cat in finding_categories:
            ids = FINDING_TO_CONTROL_MAP.get(cat, [])
            covered.update(ids)
        total = len(self._all_controls)
        num_covered = len(covered & set(self._all_controls.keys()))
        return {
            "total_controls": total,
            "covered_controls": num_covered,
            "coverage_pct": round(num_covered / max(total, 1) * 100, 1),
            "missing_controls": self.gap_analysis(covered),
            "frameworks": {
                "NIST AI RMF": len([c for c in covered if c.startswith(("GOVERN", "MAP", "MEASURE", "MANAGE"))]),
                "EU AI Act": len([c for c in covered if c.startswith("ART")]),
                "ISO 42001": len([c for c in covered if c.startswith(("A.", "6."))]),
            },
        }

    @staticmethod
    def _assess_risk(category: str) -> str:
        critical_cats = {"prompt_injection", "supply_chain", "sandbox_escape", "exfiltration", "harmful_content"}
        high_cats = {"data_leak", "poisoning", "tool_manipulation", "privilege_escalation", "verifier_sabotage"}
        if category in critical_cats:
            return "CRITICAL"
        elif category in high_cats:
            return "HIGH"
        return "MEDIUM"

    def all_frameworks(self) -> list[str]:
        return sorted({c.framework for c in self._all_controls.values()})
