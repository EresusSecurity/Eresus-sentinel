"""Risk scoring for AIBOM components."""
from __future__ import annotations

from dataclasses import dataclass

from sentinel.aibom.models import AIBOMResult, AIComponentType

_WEIGHTS = {
    AIComponentType.SHADOW_AI: 9.0,
    AIComponentType.SECRET: 8.0,
    AIComponentType.API_KEY_REF: 4.0,
    AIComponentType.MCP_SERVER: 5.0,
    AIComponentType.MCP_CLIENT: 3.0,
    AIComponentType.AGENT: 4.0,
    AIComponentType.AGENT_REACT: 5.0,
    AIComponentType.AGENT_PLANNER: 5.0,
    AIComponentType.MODEL_LLM: 2.0,
    AIComponentType.DATASET: 1.5,
    AIComponentType.ENDPOINT: 2.0,
    AIComponentType.TOOL: 3.0,
    AIComponentType.SKILL: 3.0,
    AIComponentType.PLUGIN: 2.5,
    AIComponentType.CI_PIPELINE: 2.0,
    AIComponentType.CONTAINER: 2.0,
    AIComponentType.GUARDRAIL: -2.0,  # Presence of guardrails reduces risk.
}


@dataclass
class RiskScore:
    total: float
    per_component: dict[str, float]
    top_contributors: list[tuple[str, float]]


def score(result: AIBOMResult) -> RiskScore:
    per: dict[str, float] = {}
    for c in result.components:
        weight = _WEIGHTS.get(c.type, 1.0)
        if c.risks:
            weight *= 1.5 + 0.5 * len(c.risks)
        per[c.id] = round(weight, 2)
    total = round(sum(per.values()), 2)
    ordered = sorted(per.items(), key=lambda kv: kv[1], reverse=True)[:10]
    return RiskScore(total=total, per_component=per, top_contributors=ordered)
