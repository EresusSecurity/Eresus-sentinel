"""Eresus Sentinel — unified threat classification system.

Provides programmatic mapping between OWASP LLM Top 10 (2025),
OWASP Agentic AI Top 10, MITRE ATLAS techniques, CWE identifiers,
and AITech industry taxonomy codes. Supports runtime extension via
SENTINEL_THREAT_MAPPING_PATH environment variable.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class ThreatFramework(Enum):
    OWASP_LLM = auto()
    OWASP_AGENTIC = auto()
    MITRE_ATLAS = auto()
    NIST_AI_RMF = auto()
    CWE = auto()
    AITECH = auto()


class ThreatSeverity(Enum):
    INFORMATIONAL = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class ThreatMapping:
    framework: ThreatFramework
    identifier: str
    name: str
    description: str = ""


@dataclass
class ThreatCategory:
    category_id: str
    name: str
    severity: ThreatSeverity
    description: str
    mappings: list[ThreatMapping] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# OWASP LLM TOP 10 (2025)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

OWASP_LLM_TOP_10 = [
    ThreatCategory(
        category_id="LLM01", name="Prompt Injection",
        severity=ThreatSeverity.CRITICAL,
        description="Manipulation of LLM via crafted inputs to bypass safety controls",
        mappings=[
            ThreatMapping(ThreatFramework.MITRE_ATLAS, "AML.T0051", "LLM Prompt Injection"),
            ThreatMapping(ThreatFramework.CWE, "CWE-77", "Command Injection"),
            ThreatMapping(ThreatFramework.NIST_AI_RMF, "MS-2.6-003", "Prompt Injection"),
            ThreatMapping(ThreatFramework.AITECH, "AITech-1.1", "Direct Prompt Injection"),
        ],
        mitigations=["Input validation", "Prompt boundary enforcement", "Output filtering", "Instruction hierarchy"],
        tags=["injection", "prompt", "jailbreak", "direct", "indirect"],
    ),
    ThreatCategory(
        category_id="LLM02", name="Sensitive Information Disclosure",
        severity=ThreatSeverity.HIGH,
        description="LLM reveals confidential data through responses",
        mappings=[
            ThreatMapping(ThreatFramework.CWE, "CWE-200", "Exposure of Sensitive Information"),
            ThreatMapping(ThreatFramework.MITRE_ATLAS, "AML.T0024", "Exfiltration via ML Inference"),
            ThreatMapping(ThreatFramework.AITECH, "AITech-8.2", "Data Exfiltration / Exposure"),
        ],
        mitigations=["PII filtering", "Output sanitization", "Data loss prevention", "Redaction pipelines"],
        tags=["data_leak", "pii", "confidential", "exposure"],
    ),
    ThreatCategory(
        category_id="LLM03", name="Supply Chain Vulnerabilities",
        severity=ThreatSeverity.HIGH,
        description="Compromised ML components in the supply chain",
        mappings=[
            ThreatMapping(ThreatFramework.MITRE_ATLAS, "AML.T0010", "ML Supply Chain Compromise"),
            ThreatMapping(ThreatFramework.CWE, "CWE-829", "Inclusion of Untrusted Functionality"),
            ThreatMapping(ThreatFramework.AITECH, "AITech-9.3", "Dependency / Plugin Compromise"),
        ],
        mitigations=["Model provenance verification", "Dependency scanning", "SBOM for models", "Signature verification"],
        tags=["supply_chain", "dependency", "model_poisoning"],
    ),
    ThreatCategory(
        category_id="LLM04", name="Data and Model Poisoning",
        severity=ThreatSeverity.CRITICAL,
        description="Corruption of training data or fine-tuned models",
        mappings=[
            ThreatMapping(ThreatFramework.MITRE_ATLAS, "AML.T0020", "Poisoning Training Data"),
            ThreatMapping(ThreatFramework.CWE, "CWE-1321", "Improperly Controlled Modification of Object Prototype"),
        ],
        mitigations=["Data validation", "Model integrity checks", "Anomaly detection", "Watermarking"],
        tags=["poisoning", "training", "backdoor"],
    ),
    ThreatCategory(
        category_id="LLM05", name="Improper Output Handling",
        severity=ThreatSeverity.HIGH,
        description="Failure to validate/sanitize LLM outputs before downstream use",
        mappings=[
            ThreatMapping(ThreatFramework.CWE, "CWE-74", "Injection"),
            ThreatMapping(ThreatFramework.CWE, "CWE-79", "Cross-site Scripting"),
            ThreatMapping(ThreatFramework.AITECH, "AITech-9.1", "Model or Agentic System Manipulation"),
        ],
        mitigations=["Output encoding", "Content security policies", "Sandboxed execution", "Template escaping"],
        tags=["output", "injection", "xss", "ssti"],
    ),
    ThreatCategory(
        category_id="LLM06", name="Excessive Agency",
        severity=ThreatSeverity.HIGH,
        description="LLM granted excessive permissions or autonomy",
        mappings=[
            ThreatMapping(ThreatFramework.CWE, "CWE-250", "Execution with Unnecessary Privileges"),
            ThreatMapping(ThreatFramework.AITECH, "AITech-12.1", "Tool Exploitation"),
        ],
        mitigations=["Least privilege", "Human-in-the-loop", "Action approval gates", "Capability-based security"],
        tags=["agency", "permissions", "autonomy", "tool"],
    ),
    ThreatCategory(
        category_id="LLM07", name="System Prompt Leakage",
        severity=ThreatSeverity.MEDIUM,
        description="Extraction of system prompts and hidden instructions",
        mappings=[
            ThreatMapping(ThreatFramework.MITRE_ATLAS, "AML.T0044", "Full ML Model Access"),
            ThreatMapping(ThreatFramework.CWE, "CWE-200", "Information Exposure"),
        ],
        mitigations=["Prompt shielding", "Response monitoring", "Canary detection", "Output filtering"],
        tags=["prompt_leak", "extraction", "reconnaissance"],
    ),
    ThreatCategory(
        category_id="LLM08", name="Vector and Embedding Weaknesses",
        severity=ThreatSeverity.MEDIUM,
        description="Exploitation of RAG vector stores and embeddings",
        mappings=[
            ThreatMapping(ThreatFramework.MITRE_ATLAS, "AML.T0043", "Craft Adversarial Data"),
        ],
        mitigations=["Embedding validation", "Retrieval filtering", "Source verification", "Cosine similarity thresholds"],
        tags=["rag", "embedding", "vector", "retrieval"],
    ),
    ThreatCategory(
        category_id="LLM09", name="Misinformation",
        severity=ThreatSeverity.MEDIUM,
        description="Generation of false or misleading information",
        mitigations=["Factuality checks", "Source citation", "Confidence scoring", "Grounding"],
        tags=["hallucination", "factuality", "misinformation"],
    ),
    ThreatCategory(
        category_id="LLM10", name="Unbounded Consumption",
        severity=ThreatSeverity.MEDIUM,
        description="Denial of service through resource exhaustion",
        mappings=[
            ThreatMapping(ThreatFramework.CWE, "CWE-400", "Uncontrolled Resource Consumption"),
            ThreatMapping(ThreatFramework.AITECH, "AITech-13.1", "Disruption of Availability"),
        ],
        mitigations=["Rate limiting", "Token budgets", "Timeout enforcement", "Cost controls"],
        tags=["dos", "resource", "cost", "exhaustion"],
    ),
]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# OWASP AGENTIC AI TOP 10
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

OWASP_AGENTIC_TOP_10 = [
    ThreatCategory(
        category_id="AGENT01", name="Tool Manipulation",
        severity=ThreatSeverity.CRITICAL,
        description="Exploiting tool calling mechanisms for unauthorized actions",
        mappings=[
            ThreatMapping(ThreatFramework.AITECH, "AITech-12.1", "Tool Exploitation"),
            ThreatMapping(ThreatFramework.AITECH, "AISubtech-12.1.2", "Tool Poisoning"),
        ],
        mitigations=["Tool call validation", "Parameter sanitization", "Allowlists", "Schema enforcement"],
        tags=["tool", "function_call", "mcp", "poisoning"],
    ),
    ThreatCategory(
        category_id="AGENT02", name="Privilege Escalation",
        severity=ThreatSeverity.CRITICAL,
        description="Agent gaining elevated access beyond intended scope",
        mappings=[
            ThreatMapping(ThreatFramework.CWE, "CWE-269", "Improper Privilege Management"),
        ],
        mitigations=["RBAC enforcement", "Capability-based security", "Audit logging", "Least privilege"],
        tags=["privilege", "rbac", "escalation"],
    ),
    ThreatCategory(
        category_id="AGENT03", name="Memory Poisoning",
        severity=ThreatSeverity.HIGH,
        description="Corrupting agent memory/context to influence future behavior",
        mitigations=["Memory integrity checks", "Conversation isolation", "Context validation", "TTL expiry"],
        tags=["memory", "context", "poisoning"],
    ),
    ThreatCategory(
        category_id="AGENT04", name="Cascading Hallucination",
        severity=ThreatSeverity.HIGH,
        description="Hallucinated outputs propagating through agent chains",
        mitigations=["Inter-agent validation", "Fact checking", "Chain verification", "Confidence gating"],
        tags=["hallucination", "multi_agent", "cascade"],
    ),
    ThreatCategory(
        category_id="AGENT05", name="Cross-Agent Contamination",
        severity=ThreatSeverity.HIGH,
        description="Malicious data spreading between agents in multi-agent systems",
        mitigations=["Agent isolation", "Trust boundaries", "Input validation", "Namespace separation"],
        tags=["multi_agent", "contamination", "isolation"],
    ),
    ThreatCategory(
        category_id="AGENT06", name="Implicit Trust Exploitation",
        severity=ThreatSeverity.HIGH,
        description="Exploiting trust relationships between system components",
        mitigations=["Zero-trust architecture", "Mutual authentication", "Trust verification", "TLS pinning"],
        tags=["trust", "authentication", "implicit"],
    ),
    ThreatCategory(
        category_id="AGENT07", name="Data Exfiltration via Tools",
        severity=ThreatSeverity.CRITICAL,
        description="Using tool calls to exfiltrate sensitive data",
        mappings=[
            ThreatMapping(ThreatFramework.AITECH, "AITech-8.2", "Data Exfiltration / Exposure"),
            ThreatMapping(ThreatFramework.AITECH, "AISubtech-8.2.3", "Data Exfiltration via Agent Tooling"),
        ],
        mitigations=["DLP integration", "Outbound filtering", "Tool output monitoring", "Data classification"],
        tags=["exfiltration", "tool", "data_loss", "dlp"],
    ),
    ThreatCategory(
        category_id="AGENT08", name="Unsafe Code Execution",
        severity=ThreatSeverity.CRITICAL,
        description="Agent executing malicious or unintended code",
        mappings=[
            ThreatMapping(ThreatFramework.AITECH, "AITech-9.1", "Model or Agentic System Manipulation"),
            ThreatMapping(ThreatFramework.AITECH, "AISubtech-9.1.1", "Code Execution"),
            ThreatMapping(ThreatFramework.CWE, "CWE-94", "Improper Control of Generation of Code"),
        ],
        mitigations=["Sandbox execution", "Code review", "Static analysis", "SAST/DAST integration"],
        tags=["code_execution", "sandbox", "rce"],
    ),
    ThreatCategory(
        category_id="AGENT09", name="Autonomous Decision Drift",
        severity=ThreatSeverity.MEDIUM,
        description="Agent behavior diverging from intended objectives over time",
        mitigations=["Behavioral monitoring", "Goal alignment checks", "Human oversight", "Drift detection"],
        tags=["alignment", "drift", "autonomy"],
    ),
    ThreatCategory(
        category_id="AGENT10", name="Insufficient Logging",
        severity=ThreatSeverity.MEDIUM,
        description="Inadequate audit trails for agent actions",
        mappings=[
            ThreatMapping(ThreatFramework.CWE, "CWE-778", "Insufficient Logging"),
        ],
        mitigations=["Comprehensive logging", "OTEL tracing", "Audit trails", "SIEM integration"],
        tags=["logging", "audit", "observability"],
    ),
]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# MITRE ATLAS TECHNIQUES
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

MITRE_ATLAS_TECHNIQUES = [
    ThreatCategory(
        category_id="AML.T0043", name="Craft Adversarial Data",
        severity=ThreatSeverity.HIGH,
        description="Creating adversarial inputs to deceive ML models",
        tags=["evasion", "adversarial"],
    ),
    ThreatCategory(
        category_id="AML.T0020", name="Poison Training Data",
        severity=ThreatSeverity.CRITICAL,
        description="Injecting malicious data into training sets",
        tags=["poisoning", "training"],
    ),
    ThreatCategory(
        category_id="AML.T0010", name="ML Supply Chain Compromise",
        severity=ThreatSeverity.HIGH,
        description="Compromising ML models or dependencies in the supply chain",
        tags=["supply_chain"],
    ),
    ThreatCategory(
        category_id="AML.T0024", name="Exfiltration via ML Inference",
        severity=ThreatSeverity.HIGH,
        description="Extracting sensitive data through model queries",
        tags=["exfiltration", "inference"],
    ),
    ThreatCategory(
        category_id="AML.T0051", name="LLM Prompt Injection",
        severity=ThreatSeverity.CRITICAL,
        description="Injecting adversarial prompts into LLM interactions",
        tags=["prompt_injection", "llm"],
    ),
    ThreatCategory(
        category_id="AML.T0044", name="Full ML Model Access",
        severity=ThreatSeverity.CRITICAL,
        description="Complete access to model weights and parameters",
        tags=["model_theft", "ip_theft"],
    ),
    ThreatCategory(
        category_id="AML.T0040", name="ML Model Inference API Access",
        severity=ThreatSeverity.MEDIUM,
        description="Access to model inference APIs for probing",
        tags=["api", "reconnaissance"],
    ),
    ThreatCategory(
        category_id="AML.T0042", name="Verify Attack",
        severity=ThreatSeverity.LOW,
        description="Confirming successful attack on ML system",
        tags=["verification"],
    ),
    ThreatCategory(
        category_id="AML.T0045", name="Extract ML Model",
        severity=ThreatSeverity.HIGH,
        description="Model stealing through repeated API queries",
        tags=["model_theft", "extraction"],
    ),
    ThreatCategory(
        category_id="AML.T0047", name="Evade ML Model",
        severity=ThreatSeverity.HIGH,
        description="Crafting inputs to evade ML-based detection",
        tags=["evasion", "adversarial"],
    ),
]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# AITech INDUSTRY TAXONOMY
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

AITECH_TAXONOMY: dict[str, dict[str, Any]] = {
    "AITech-1.1": {
        "name": "Direct Prompt Injection",
        "category": "prompt_injection",
        "severity": "HIGH",
        "subtechs": {
            "AISubtech-1.1.1": "Instruction Manipulation",
        },
    },
    "AITech-1.2": {
        "name": "Indirect Prompt Injection",
        "category": "prompt_injection",
        "severity": "HIGH",
        "subtechs": {
            "AISubtech-1.2.1": "Instruction Manipulation via External Data",
        },
    },
    "AITech-2.1": {
        "name": "Jailbreak",
        "category": "social_engineering",
        "severity": "HIGH",
        "subtechs": {},
    },
    "AITech-4.3": {
        "name": "Protocol Manipulation",
        "category": "skill_discovery_abuse",
        "severity": "MEDIUM",
        "subtechs": {
            "AISubtech-4.3.5": "Capability Inflation",
        },
    },
    "AITech-8.2": {
        "name": "Data Exfiltration / Exposure",
        "category": "data_exfiltration",
        "severity": "HIGH",
        "subtechs": {
            "AISubtech-8.2.2": "LLM Data Leakage",
            "AISubtech-8.2.3": "Data Exfiltration via Agent Tooling",
        },
    },
    "AITech-9.1": {
        "name": "Model or Agentic System Manipulation",
        "category": "command_injection",
        "severity": "CRITICAL",
        "subtechs": {
            "AISubtech-9.1.1": "Code Execution",
            "AISubtech-9.1.2": "Unauthorized System Access",
            "AISubtech-9.1.4": "Injection Attacks (SQL, Command, XSS)",
        },
    },
    "AITech-9.2": {
        "name": "Detection Evasion",
        "category": "obfuscation",
        "severity": "HIGH",
        "subtechs": {
            "AISubtech-9.2.1": "Obfuscation Vulnerabilities",
        },
    },
    "AITech-9.3": {
        "name": "Dependency / Plugin Compromise",
        "category": "supply_chain_attack",
        "severity": "HIGH",
        "subtechs": {
            "AISubtech-9.3.1": "Malicious Package / Tool Injection",
        },
    },
    "AITech-12.1": {
        "name": "Tool Exploitation",
        "category": "unauthorized_tool_use",
        "severity": "HIGH",
        "subtechs": {
            "AISubtech-12.1.2": "Tool Poisoning",
            "AISubtech-12.1.3": "Unsafe System / Browser / File Execution",
            "AISubtech-12.1.4": "Tool Shadowing",
        },
    },
    "AITech-13.1": {
        "name": "Disruption of Availability",
        "category": "resource_abuse",
        "severity": "MEDIUM",
        "subtechs": {
            "AISubtech-13.1.1": "Compute Exhaustion",
        },
    },
    "AITech-15.1": {
        "name": "Harmful Content",
        "category": "harmful_content",
        "severity": "MEDIUM",
        "subtechs": {
            "AISubtech-15.1.12": "Scams and Deception",
        },
    },
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CWE CROSS-REFERENCE DATABASE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CWE_DATABASE: dict[str, dict[str, str]] = {
    "CWE-22": {"name": "Improper Limitation of a Pathname to a Restricted Directory", "category": "path_traversal"},
    "CWE-74": {"name": "Injection", "category": "injection"},
    "CWE-77": {"name": "Command Injection", "category": "command_injection"},
    "CWE-78": {"name": "OS Command Injection", "category": "command_injection"},
    "CWE-79": {"name": "Cross-site Scripting (XSS)", "category": "xss"},
    "CWE-89": {"name": "SQL Injection", "category": "sql_injection"},
    "CWE-90": {"name": "LDAP Injection", "category": "ldap_injection"},
    "CWE-94": {"name": "Improper Control of Code Generation", "category": "code_injection"},
    "CWE-95": {"name": "Eval Injection", "category": "code_injection"},
    "CWE-113": {"name": "HTTP Response Splitting", "category": "header_injection"},
    "CWE-116": {"name": "Improper Encoding or Escaping of Output", "category": "encoding"},
    "CWE-117": {"name": "Improper Output Neutralization for Logs", "category": "log_injection"},
    "CWE-200": {"name": "Exposure of Sensitive Information", "category": "information_disclosure"},
    "CWE-250": {"name": "Execution with Unnecessary Privileges", "category": "privilege_escalation"},
    "CWE-265": {"name": "Privilege Issues", "category": "sandbox_escape"},
    "CWE-269": {"name": "Improper Privilege Management", "category": "privilege_escalation"},
    "CWE-287": {"name": "Improper Authentication", "category": "authentication"},
    "CWE-352": {"name": "Cross-Site Request Forgery (CSRF)", "category": "csrf"},
    "CWE-400": {"name": "Uncontrolled Resource Consumption", "category": "dos"},
    "CWE-489": {"name": "Active Debug Code", "category": "misconfiguration"},
    "CWE-502": {"name": "Deserialization of Untrusted Data", "category": "deserialization"},
    "CWE-601": {"name": "URL Redirection to Untrusted Site", "category": "open_redirect"},
    "CWE-643": {"name": "Improper Neutralization of Data within XPath Expressions", "category": "xpath_injection"},
    "CWE-644": {"name": "Improper Neutralization of HTTP Headers", "category": "header_injection"},
    "CWE-674": {"name": "Uncontrolled Recursion", "category": "dos"},
    "CWE-770": {"name": "Allocation of Resources Without Limits", "category": "dos"},
    "CWE-778": {"name": "Insufficient Logging", "category": "logging"},
    "CWE-798": {"name": "Use of Hard-coded Credentials", "category": "credential_exposure"},
    "CWE-829": {"name": "Inclusion of Untrusted Functionality", "category": "supply_chain"},
    "CWE-917": {"name": "Improper Neutralization of Expression Language", "category": "el_injection"},
    "CWE-918": {"name": "Server-Side Request Forgery (SSRF)", "category": "ssrf"},
    "CWE-943": {"name": "Improper Neutralization in NoSQL Query", "category": "nosql_injection"},
    "CWE-1321": {"name": "Improperly Controlled Modification of Object Prototype", "category": "prototype_pollution"},
    "CWE-1336": {"name": "Server-Side Template Injection (SSTI)", "category": "ssti"},
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# YAML OVERLAY SUPPORT
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_THREAT_MAPPING_ENV_VAR = "SENTINEL_THREAT_MAPPING_PATH"
_mapping_source = "builtin"


def _load_custom_mapping() -> dict[str, Any]:
    path = os.getenv(_THREAT_MAPPING_ENV_VAR)
    if not path:
        return {}
    p = Path(path)
    if not p.is_file():
        logger.warning("Custom threat mapping not found: %s", path)
        return {}
    try:
        payload = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("Payload must be a JSON object")
        logger.info("Loaded custom threat mappings from %s", p)
        return payload
    except Exception as exc:
        logger.warning("Failed to load custom threat mapping %s: %s", path, exc)
        return {}


def _apply_custom_aitech(payload: dict[str, Any]) -> None:
    global AITECH_TAXONOMY
    overrides = payload.get("aitech_taxonomy", {})
    if isinstance(overrides, dict):
        for code, info in overrides.items():
            if isinstance(info, dict):
                if code in AITECH_TAXONOMY:
                    AITECH_TAXONOMY[code].update(info)
                else:
                    AITECH_TAXONOMY[code] = info


def _apply_custom_cwe(payload: dict[str, Any]) -> None:
    global CWE_DATABASE
    overrides = payload.get("cwe_database", {})
    if isinstance(overrides, dict):
        for cwe_id, info in overrides.items():
            if isinstance(info, dict):
                CWE_DATABASE[cwe_id] = info


_custom_payload = _load_custom_mapping()
if _custom_payload:
    _apply_custom_aitech(_custom_payload)
    _apply_custom_cwe(_custom_payload)
    _mapping_source = os.getenv(_THREAT_MAPPING_ENV_VAR, "builtin")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# UNIFIED TAXONOMY ENGINE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class ThreatTaxonomy:

    def __init__(self) -> None:
        self._categories: dict[str, ThreatCategory] = {}
        for cat in OWASP_LLM_TOP_10 + OWASP_AGENTIC_TOP_10 + MITRE_ATLAS_TECHNIQUES:
            self._categories[cat.category_id] = cat

    def lookup(self, category_id: str) -> ThreatCategory | None:
        return self._categories.get(category_id)

    def search_by_tag(self, tag: str) -> list[ThreatCategory]:
        return [c for c in self._categories.values() if tag in c.tags]

    def search_by_severity(self, min_severity: ThreatSeverity) -> list[ThreatCategory]:
        return [c for c in self._categories.values() if c.severity.value >= min_severity.value]

    def get_mappings_for(self, category_id: str) -> list[ThreatMapping]:
        cat = self.lookup(category_id)
        return list(cat.mappings) if cat else []

    def all_categories(self) -> list[ThreatCategory]:
        return list(self._categories.values())

    def map_finding_to_threats(
        self, finding_type: str, tags: list[str] | None = None,
    ) -> list[ThreatCategory]:
        results = []
        search_tags = set(tags or [])
        search_tags.add(finding_type)
        for cat in self._categories.values():
            if search_tags & set(cat.tags):
                results.append(cat)
        return results

    def map_cwe_to_threats(self, cwe_id: str) -> list[ThreatCategory]:
        results = []
        for cat in self._categories.values():
            for mapping in cat.mappings:
                if mapping.framework == ThreatFramework.CWE and mapping.identifier == cwe_id:
                    results.append(cat)
                    break
        return results

    def map_aitech_to_threats(self, aitech_code: str) -> list[ThreatCategory]:
        results = []
        for cat in self._categories.values():
            for mapping in cat.mappings:
                if mapping.framework == ThreatFramework.AITECH and mapping.identifier == aitech_code:
                    results.append(cat)
                    break
        return results

    def get_full_mapping(self, category_id: str) -> dict[str, Any]:
        cat = self.lookup(category_id)
        if not cat:
            return {}
        result: dict[str, Any] = {
            "category_id": cat.category_id,
            "name": cat.name,
            "severity": cat.severity.name,
            "description": cat.description,
            "mitigations": cat.mitigations,
            "tags": cat.tags,
            "frameworks": {},
        }
        for m in cat.mappings:
            fw_name = m.framework.name.lower()
            if fw_name not in result["frameworks"]:
                result["frameworks"][fw_name] = []
            result["frameworks"][fw_name].append({
                "id": m.identifier,
                "name": m.name,
                "description": m.description,
            })
        return result

    def resolve_cwe(self, cwe_id: str) -> dict[str, str]:
        return CWE_DATABASE.get(cwe_id, {"name": "Unknown", "category": "unknown"})

    def resolve_aitech(self, aitech_code: str) -> dict[str, Any]:
        return AITECH_TAXONOMY.get(aitech_code, {
            "name": "Unknown",
            "category": "unknown",
            "severity": "MEDIUM",
        })

    def get_cross_framework_mappings(self, cwe_id: str) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {
            "owasp_llm": [],
            "owasp_agentic": [],
            "mitre_atlas": [],
            "aitech": [],
        }
        for cat in self._categories.values():
            for m in cat.mappings:
                if m.framework == ThreatFramework.CWE and m.identifier == cwe_id:
                    if cat.category_id.startswith("LLM"):
                        result["owasp_llm"].append(cat.category_id)
                    elif cat.category_id.startswith("AGENT"):
                        result["owasp_agentic"].append(cat.category_id)
                    elif cat.category_id.startswith("AML"):
                        result["mitre_atlas"].append(cat.category_id)
                    for mm in cat.mappings:
                        if mm.framework == ThreatFramework.AITECH:
                            result["aitech"].append(mm.identifier)
        return result

    @staticmethod
    def get_mapping_source() -> str:
        return _mapping_source

    def export_sarif_taxonomy(self) -> dict[str, Any]:
        taxa = []
        for cat in self._categories.values():
            taxa.append({
                "id": cat.category_id,
                "name": cat.name,
                "shortDescription": {"text": cat.description},
                "defaultConfiguration": {
                    "level": _severity_to_sarif(cat.severity),
                },
            })
        return {
            "name": "EresusSentinel",
            "version": "0.1.0",
            "taxa": taxa,
        }


def _severity_to_sarif(severity: ThreatSeverity) -> str:
    return {
        ThreatSeverity.INFORMATIONAL: "note",
        ThreatSeverity.LOW: "note",
        ThreatSeverity.MEDIUM: "warning",
        ThreatSeverity.HIGH: "error",
        ThreatSeverity.CRITICAL: "error",
    }.get(severity, "warning")
