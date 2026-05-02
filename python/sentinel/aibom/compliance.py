"""AIBOM compliance and policy checking.

Provides rules for:
  - Eresus internal baseline (AIBOM-C-*)
  - EU AI Act (EU-AIA-*)
  - OWASP Agentic Top 10 2025 (OWASP-AT10-*)
  - NIST AI RMF 1.0 (NIST-AIRLMF-*)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from sentinel.aibom.models import AIBOMResult, AIComponent, AIComponentType


@dataclass
class ComplianceRule:
    id: str
    title: str
    check: Callable[[AIBOMResult], list[AIComponent]]
    framework: str = "eresus"
    severity: str = "medium"
    remediation: str = ""


@dataclass
class ComplianceResult:
    rule: ComplianceRule
    violators: list[AIComponent] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.violators


def _metadata(component: AIComponent) -> dict:
    """Return component metadata across old and new AIBOM component models."""
    raw = getattr(component, "metadata", None) or getattr(component, "properties", {}) or {}
    return raw if isinstance(raw, dict) else {}


# ── Eresus Baseline ───────────────────────────────────────────

def rule_no_shadow_ai() -> ComplianceRule:
    return ComplianceRule(
        id="AIBOM-C-001",
        title="No shadow AI usage",
        check=lambda r: [c for c in r.components if c.type == AIComponentType.SHADOW_AI],
        severity="high",
        remediation="Route all AI calls through approved SDKs.",
    )


def rule_endpoints_authorized() -> ComplianceRule:
    def check(r: AIBOMResult) -> list[AIComponent]:
        endpoints = [c for c in r.components if c.type == AIComponentType.ENDPOINT]
        authorized_ids = {rel.target_id for rel in r.relationships if rel.type.value == "authorized_by"}
        return [e for e in endpoints if e.id not in authorized_ids and not any(
            r2.source_id == e.id for r2 in r.relationships
        )]

    return ComplianceRule(
        id="AIBOM-C-002",
        title="Endpoints must have identifiable credentials",
        check=check,
        severity="medium",
    )


def rule_no_unpinned_models() -> ComplianceRule:
    return ComplianceRule(
        id="AIBOM-C-003",
        title="Local model files should have hash digests",
        check=lambda r: [c for c in r.components if c.type.value.startswith("model.") and c.path and not c.hashes],
        severity="low",
    )


# ── EU AI Act ─────────────────────────────────────────────────
# Reference: Regulation (EU) 2024/1689, Annex III + Chapter III

def rule_euaia_prohibited_ai_practices() -> ComplianceRule:
    """Art. 5 — Prohibited AI practices (social scoring, subliminal manipulation)."""
    PROHIBITED_TAGS = frozenset({
        "social_scoring", "emotion_recognition_workplace", "real_time_biometric",
        "subliminal_manipulation", "exploitation_of_vulnerabilities",
    })
    def check(r: AIBOMResult) -> list[AIComponent]:
        return [
            c for c in r.components
            if any(t in PROHIBITED_TAGS for t in _metadata(c).get("tags", []))
        ]
    return ComplianceRule(
        id="EU-AIA-001",
        title="EU AI Act Art.5 — No prohibited AI practices",
        check=check,
        framework="eu_ai_act",
        severity="critical",
        remediation="Remove or replace any prohibited-practice AI components per Regulation (EU) 2024/1689 Art. 5.",
    )


def rule_euaia_high_risk_documentation() -> ComplianceRule:
    """Art. 11 — High-risk AI systems must have technical documentation."""
    HIGH_RISK_TYPES = frozenset({
        AIComponentType.MODEL_LLM, AIComponentType.AGENT,
        AIComponentType.AGENT_REACT, AIComponentType.AGENT_PLANNER,
    })
    def check(r: AIBOMResult) -> list[AIComponent]:
        return [
            c for c in r.components
            if c.type in HIGH_RISK_TYPES
            and not _metadata(c).get("technical_documentation")
            and _metadata(c).get("risk_class", "") in ("high", "unacceptable")
        ]
    return ComplianceRule(
        id="EU-AIA-002",
        title="EU AI Act Art.11 — High-risk systems require technical documentation",
        check=check,
        framework="eu_ai_act",
        severity="high",
        remediation="Attach technical_documentation metadata to all high-risk AI components (Art. 11, Annex IV).",
    )


def rule_euaia_transparency_obligation() -> ComplianceRule:
    """Art. 50 — Transparency obligations for certain AI systems (chatbots, deep fakes)."""
    def check(r: AIBOMResult) -> list[AIComponent]:
        return [
            c for c in r.components
            if c.type in (AIComponentType.MODEL_LLM, AIComponentType.AGENT)
            and not _metadata(c).get("user_disclosure")
        ]
    return ComplianceRule(
        id="EU-AIA-003",
        title="EU AI Act Art.50 — Transparency: users must be informed of AI interaction",
        check=check,
        framework="eu_ai_act",
        severity="high",
        remediation="Set user_disclosure=true in component metadata and implement disclosure UI.",
    )


def rule_euaia_human_oversight() -> ComplianceRule:
    """Art. 14 — Human oversight measures for high-risk AI."""
    def check(r: AIBOMResult) -> list[AIComponent]:
        return [
            c for c in r.components
            if c.type in (AIComponentType.AGENT_REACT, AIComponentType.AGENT_PLANNER)
            and not _metadata(c).get("human_oversight_mechanism")
        ]
    return ComplianceRule(
        id="EU-AIA-004",
        title="EU AI Act Art.14 — Autonomous agents require human oversight mechanism",
        check=check,
        framework="eu_ai_act",
        severity="high",
        remediation="Define human_oversight_mechanism for all autonomous agent components.",
    )


def rule_euaia_data_governance() -> ComplianceRule:
    """Art. 10 — Data governance: training data must be documented and assessed for bias."""
    def check(r: AIBOMResult) -> list[AIComponent]:
        return [
            c for c in r.components
            if c.type == AIComponentType.DATASET
            and not _metadata(c).get("bias_assessment")
        ]
    return ComplianceRule(
        id="EU-AIA-005",
        title="EU AI Act Art.10 — Training datasets require bias assessment",
        check=check,
        framework="eu_ai_act",
        severity="medium",
        remediation="Perform and document bias assessment for all training datasets (Art. 10.2).",
    )


# ── OWASP Agentic Top 10 2025 ─────────────────────────────────
# Reference: https://owasp.org/www-project-agentic-ai-security/

def rule_owasp_at10_prompt_injection() -> ComplianceRule:
    """AT10:2025-01 — Prompt injection via unvalidated tool inputs."""
    def check(r: AIBOMResult) -> list[AIComponent]:
        return [
            c for c in r.components
            if c.type in (AIComponentType.MCP_TOOL, AIComponentType.TOOL, AIComponentType.PLUGIN)
            and not _metadata(c).get("input_validation")
        ]
    return ComplianceRule(
        id="OWASP-AT10-001",
        title="OWASP Agentic Top10 #1 — Tool inputs require prompt injection guard",
        check=check,
        framework="owasp_agentic_top10",
        severity="critical",
        remediation="Add input_validation metadata to all tool/plugin components and wire a firewall scanner.",
    )


def rule_owasp_at10_tool_misuse() -> ComplianceRule:
    """AT10:2025-03 — Excessive tool permissions (privilege escalation)."""
    def check(r: AIBOMResult) -> list[AIComponent]:
        return [
            c for c in r.components
            if c.type in (AIComponentType.MCP_TOOL, AIComponentType.TOOL)
            and "*" in str(_metadata(c).get("permissions", []))
        ]
    return ComplianceRule(
        id="OWASP-AT10-003",
        title="OWASP Agentic Top10 #3 — Tools must not have wildcard permissions",
        check=check,
        framework="owasp_agentic_top10",
        severity="high",
        remediation="Replace wildcard permissions with least-privilege scopes.",
    )


def rule_owasp_at10_supply_chain() -> ComplianceRule:
    """AT10:2025-05 — Unverified model supply chain (unsigned/unhashed models)."""
    def check(r: AIBOMResult) -> list[AIComponent]:
        return [
            c for c in r.components
            if c.type.value.startswith("model.")
            and not (c.hashes or _metadata(c).get("signature"))
        ]
    return ComplianceRule(
        id="OWASP-AT10-005",
        title="OWASP Agentic Top10 #5 — All models must have cryptographic hashes or signatures",
        check=check,
        framework="owasp_agentic_top10",
        severity="high",
        remediation="Pin model artifacts to sha256 digests in AIBOM and verify before loading.",
    )


def rule_owasp_at10_data_exfil() -> ComplianceRule:
    """AT10:2025-07 — Sensitive data exfiltration via unmonitored agent actions."""
    def check(r: AIBOMResult) -> list[AIComponent]:
        return [
            c for c in r.components
            if c.type == AIComponentType.ENDPOINT
            and not _metadata(c).get("egress_monitoring")
        ]
    return ComplianceRule(
        id="OWASP-AT10-007",
        title="OWASP Agentic Top10 #7 — External endpoints require egress monitoring",
        check=check,
        framework="owasp_agentic_top10",
        severity="high",
        remediation="Enable egress_monitoring on all external endpoints used by agents.",
    )


def rule_owasp_at10_memory_poisoning() -> ComplianceRule:
    """AT10:2025-08 — Vector store / memory poisoning."""
    def check(r: AIBOMResult) -> list[AIComponent]:
        return [
            c for c in r.components
            if c.type in (AIComponentType.VECTOR_STORE, AIComponentType.EMBEDDING_INDEX)
            and not _metadata(c).get("write_access_control")
        ]
    return ComplianceRule(
        id="OWASP-AT10-008",
        title="OWASP Agentic Top10 #8 — Vector stores require write-access control",
        check=check,
        framework="owasp_agentic_top10",
        severity="high",
        remediation="Restrict write access to vector stores; audit injection paths.",
    )


# ── OWASP LLM Top 10 ──────────────────────────────────────────

def rule_owasp_llm_prompt_injection() -> ComplianceRule:
    def check(r: AIBOMResult) -> list[AIComponent]:
        return [
            c for c in r.components
            if c.type in (
                AIComponentType.AGENT,
                AIComponentType.AGENT_REACT,
                AIComponentType.AGENT_PLANNER,
                AIComponentType.TOOL,
                AIComponentType.MCP_TOOL,
                AIComponentType.PROMPT_TEMPLATE,
            )
            and not _metadata(c).get("input_validation")
        ]
    return ComplianceRule(
        id="OWASP-LLM-001",
        title="OWASP LLM01 — Prompt injection controls required",
        check=check,
        framework="owasp_llm_top10",
        severity="critical",
        remediation="Add input_validation metadata and wire prompt firewall checks for prompts, agents, and tools.",
    )


def rule_owasp_llm_sensitive_info() -> ComplianceRule:
    def check(r: AIBOMResult) -> list[AIComponent]:
        return [
            c for c in r.components
            if c.type in (AIComponentType.SECRET, AIComponentType.ENDPOINT, AIComponentType.API_KEY_REF)
            and not _metadata(c).get("redaction")
        ]
    return ComplianceRule(
        id="OWASP-LLM-002",
        title="OWASP LLM02 — Sensitive information disclosure controls required",
        check=check,
        framework="owasp_llm_top10",
        severity="high",
        remediation="Add redaction=true or secret-manager references for sensitive components.",
    )


def rule_owasp_llm_supply_chain() -> ComplianceRule:
    def check(r: AIBOMResult) -> list[AIComponent]:
        return [
            c for c in r.components
            if (c.type.value.startswith("model.") or c.type in (AIComponentType.PLUGIN, AIComponentType.SKILL))
            and not (c.hashes or _metadata(c).get("signature"))
        ]
    return ComplianceRule(
        id="OWASP-LLM-003",
        title="OWASP LLM03 — Supply-chain components require hash or signature",
        check=check,
        framework="owasp_llm_top10",
        severity="high",
        remediation="Pin model/plugin artifacts to hashes or verified signatures.",
    )


def rule_owasp_llm_data_poisoning() -> ComplianceRule:
    def check(r: AIBOMResult) -> list[AIComponent]:
        return [
            c for c in r.components
            if c.type == AIComponentType.DATASET
            and not _metadata(c).get("data_lineage")
        ]
    return ComplianceRule(
        id="OWASP-LLM-004",
        title="OWASP LLM04 — Training data lineage required",
        check=check,
        framework="owasp_llm_top10",
        severity="medium",
        remediation="Document data_lineage and poisoning checks for training or fine-tuning datasets.",
    )


def rule_owasp_llm_output_handling() -> ComplianceRule:
    def check(r: AIBOMResult) -> list[AIComponent]:
        return [
            c for c in r.components
            if c.type in (AIComponentType.TOOL, AIComponentType.MCP_TOOL, AIComponentType.ENDPOINT)
            and not _metadata(c).get("output_validation")
        ]
    return ComplianceRule(
        id="OWASP-LLM-005",
        title="OWASP LLM05 — Output handling controls required",
        check=check,
        framework="owasp_llm_top10",
        severity="high",
        remediation="Add output_validation metadata for tool calls, endpoints, and downstream sinks.",
    )


def rule_owasp_llm_excessive_agency() -> ComplianceRule:
    def check(r: AIBOMResult) -> list[AIComponent]:
        return [
            c for c in r.components
            if c.type in (AIComponentType.AGENT, AIComponentType.AGENT_REACT, AIComponentType.AGENT_PLANNER, AIComponentType.TOOL)
            and ("*" in str(_metadata(c).get("permissions", [])) or not _metadata(c).get("human_approval"))
        ]
    return ComplianceRule(
        id="OWASP-LLM-006",
        title="OWASP LLM06 — Excessive agency controls required",
        check=check,
        framework="owasp_llm_top10",
        severity="high",
        remediation="Use least-privilege permissions and human_approval metadata for high-impact actions.",
    )


def rule_owasp_llm_system_prompt_leakage() -> ComplianceRule:
    def check(r: AIBOMResult) -> list[AIComponent]:
        return [
            c for c in r.components
            if c.type == AIComponentType.PROMPT_TEMPLATE
            and not _metadata(c).get("prompt_secrets_reviewed")
        ]
    return ComplianceRule(
        id="OWASP-LLM-007",
        title="OWASP LLM07 — Prompt secret review required",
        check=check,
        framework="owasp_llm_top10",
        severity="medium",
        remediation="Set prompt_secrets_reviewed=true after removing credentials and hidden policy secrets.",
    )


def rule_owasp_llm_vector_weakness() -> ComplianceRule:
    def check(r: AIBOMResult) -> list[AIComponent]:
        return [
            c for c in r.components
            if c.type in (AIComponentType.VECTOR_STORE, AIComponentType.EMBEDDING_INDEX)
            and not _metadata(c).get("write_access_control")
        ]
    return ComplianceRule(
        id="OWASP-LLM-008",
        title="OWASP LLM08 — Vector and embedding stores require write controls",
        check=check,
        framework="owasp_llm_top10",
        severity="high",
        remediation="Restrict vector-store writes and audit retrieval poisoning paths.",
    )


def rule_owasp_llm_misinformation() -> ComplianceRule:
    def check(r: AIBOMResult) -> list[AIComponent]:
        return [
            c for c in r.components
            if c.type in (AIComponentType.MODEL_LLM, AIComponentType.AGENT)
            and not _metadata(c).get("evaluation_report")
        ]
    return ComplianceRule(
        id="OWASP-LLM-009",
        title="OWASP LLM09 — Evaluation report required for misinformation risk",
        check=check,
        framework="owasp_llm_top10",
        severity="medium",
        remediation="Attach evaluation_report metadata covering factuality and task-specific risk.",
    )


def rule_owasp_llm_unbounded_consumption() -> ComplianceRule:
    def check(r: AIBOMResult) -> list[AIComponent]:
        return [
            c for c in r.components
            if c.type in (AIComponentType.ENDPOINT, AIComponentType.AGENT, AIComponentType.MODEL_LLM)
            and not _metadata(c).get("rate_limit")
        ]
    return ComplianceRule(
        id="OWASP-LLM-010",
        title="OWASP LLM10 — Unbounded consumption controls required",
        check=check,
        framework="owasp_llm_top10",
        severity="medium",
        remediation="Define rate_limit or budget controls for LLM endpoints and agent loops.",
    )


# ── NIST AI RMF 1.0 ───────────────────────────────────────────
# Reference: https://airc.nist.gov/RMF/Overview

def rule_nist_govern_risk_policy() -> ComplianceRule:
    """GOVERN 1.1 — Policies for AI risk must exist at the component level."""
    def check(r: AIBOMResult) -> list[AIComponent]:
        return [
            c for c in r.components
            if c.type in (AIComponentType.MODEL_LLM, AIComponentType.AGENT)
            and not _metadata(c).get("risk_policy")
        ]
    return ComplianceRule(
        id="NIST-AIRLMF-GOV-001",
        title="NIST AI RMF GOVERN 1.1 — Risk policy required for LLM and agent components",
        check=check,
        framework="nist_ai_rmf",
        severity="medium",
        remediation="Define risk_policy metadata referencing the organizational AI risk policy document.",
    )


def rule_nist_map_context_impact() -> ComplianceRule:
    """MAP 1.5 — AI system context and impact must be documented."""
    def check(r: AIBOMResult) -> list[AIComponent]:
        return [
            c for c in r.components
            if c.type.value.startswith("model.")
            and not _metadata(c).get("intended_use")
        ]
    return ComplianceRule(
        id="NIST-AIRLMF-MAP-001",
        title="NIST AI RMF MAP 1.5 — Model intended use must be documented",
        check=check,
        framework="nist_ai_rmf",
        severity="medium",
        remediation="Add intended_use metadata to all model components.",
    )


def rule_nist_measure_eval() -> ComplianceRule:
    """MEASURE 2.5 — AI system performance evaluated against task requirements."""
    def check(r: AIBOMResult) -> list[AIComponent]:
        return [
            c for c in r.components
            if c.type in (AIComponentType.MODEL_LLM, AIComponentType.AGENT)
            and not _metadata(c).get("evaluation_report")
        ]
    return ComplianceRule(
        id="NIST-AIRLMF-MEA-001",
        title="NIST AI RMF MEASURE 2.5 — LLM/agent components require evaluation report",
        check=check,
        framework="nist_ai_rmf",
        severity="medium",
        remediation="Attach evaluation_report (benchmark results, red-team findings) to the component.",
    )


def rule_nist_manage_incident_response() -> ComplianceRule:
    """MANAGE 4.1 — Incident response plans for AI systems."""
    def check(r: AIBOMResult) -> list[AIComponent]:
        return [
            c for c in r.components
            if c.type in (AIComponentType.AGENT, AIComponentType.AGENT_REACT, AIComponentType.AGENT_PLANNER)
            and not _metadata(c).get("incident_response_plan")
        ]
    return ComplianceRule(
        id="NIST-AIRLMF-MAN-001",
        title="NIST AI RMF MANAGE 4.1 — Autonomous agents require incident response plan",
        check=check,
        framework="nist_ai_rmf",
        severity="medium",
        remediation="Define incident_response_plan in component metadata.",
    )


# ── Framework registries ──────────────────────────────────────

def eresus_rules() -> list[ComplianceRule]:
    return [rule_no_shadow_ai(), rule_endpoints_authorized(), rule_no_unpinned_models()]


def eu_ai_act_rules() -> list[ComplianceRule]:
    return [
        rule_euaia_prohibited_ai_practices(),
        rule_euaia_high_risk_documentation(),
        rule_euaia_transparency_obligation(),
        rule_euaia_human_oversight(),
        rule_euaia_data_governance(),
    ]


def owasp_agentic_top10_rules() -> list[ComplianceRule]:
    return [
        rule_owasp_at10_prompt_injection(),
        rule_owasp_at10_tool_misuse(),
        rule_owasp_at10_supply_chain(),
        rule_owasp_at10_data_exfil(),
        rule_owasp_at10_memory_poisoning(),
    ]


def owasp_llm_top10_rules() -> list[ComplianceRule]:
    return [
        rule_owasp_llm_prompt_injection(),
        rule_owasp_llm_sensitive_info(),
        rule_owasp_llm_supply_chain(),
        rule_owasp_llm_data_poisoning(),
        rule_owasp_llm_output_handling(),
        rule_owasp_llm_excessive_agency(),
        rule_owasp_llm_system_prompt_leakage(),
        rule_owasp_llm_vector_weakness(),
        rule_owasp_llm_misinformation(),
        rule_owasp_llm_unbounded_consumption(),
    ]


def nist_ai_rmf_rules() -> list[ComplianceRule]:
    return [
        rule_nist_govern_risk_policy(),
        rule_nist_map_context_impact(),
        rule_nist_measure_eval(),
        rule_nist_manage_incident_response(),
    ]


def all_frameworks() -> list[ComplianceRule]:
    """Return all rules from all frameworks."""
    return (
        eresus_rules()
        + owasp_llm_top10_rules()
        + eu_ai_act_rules()
        + owasp_agentic_top10_rules()
        + nist_ai_rmf_rules()
    )


# Backward-compat alias
def default_rules() -> list[ComplianceRule]:
    return eresus_rules()


def evaluate(
    result: AIBOMResult,
    rules: list[ComplianceRule] | None = None,
    framework: str | None = None,
) -> list[ComplianceResult]:
    """Evaluate AIBOM against compliance rules.

    Args:
        result: The AIBOMResult to check.
        rules: Explicit rule list (overrides framework).
        framework: One of "eresus", "eu_ai_act", "owasp_agentic_top10",
                   "nist_ai_rmf", "all". Default: "eresus".
    """
    if rules is None:
        fw = framework or "eresus"
        rules = {
            "eresus": eresus_rules,
            "owasp_llm": owasp_llm_top10_rules,
            "owasp_llm_top10": owasp_llm_top10_rules,
            "eu_ai_act": eu_ai_act_rules,
            "owasp_agentic_top10": owasp_agentic_top10_rules,
            "nist_ai_rmf": nist_ai_rmf_rules,
            "all": all_frameworks,
        }.get(fw, eresus_rules)()
    return [ComplianceResult(rule=rule, violators=rule.check(result)) for rule in rules]
