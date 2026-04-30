"""Cross-reference BOM components to resolve relationships and deduplicate."""
from __future__ import annotations

import logging

from sentinel.aibom.models import AIBOMResult, AIComponent, RelationshipType

logger = logging.getLogger(__name__)


def cross_reference(result: AIBOMResult) -> AIBOMResult:
    """Run cross-reference passes to resolve relationships and dedup components."""
    _resolve_env_vars(result)
    _link_models_to_endpoints(result)
    _link_agents_to_tools(result)
    _deduplicate_components(result)
    return result


def _resolve_env_vars(result: AIBOMResult) -> None:
    env_defs: dict[str, AIComponent] = {}
    env_refs: list[AIComponent] = []

    for comp in result.components:
        env_name = comp.properties.get("env", "")
        if not env_name:
            continue
        if comp.properties.get("has_value"):
            env_defs[env_name] = comp
        elif not comp.properties.get("resolved"):
            env_refs.append(comp)

    for ref in env_refs:
        env_name = ref.properties.get("env", "")
        if env_name in env_defs:
            result.relate(ref, env_defs[env_name], RelationshipType.CONFIGURED_BY)
            ref.properties["resolved"] = True


def _link_models_to_endpoints(result: AIBOMResult) -> None:
    models = [c for c in result.components if "model" in c.type.value.lower()]
    endpoints = [c for c in result.components if c.type.value in ("endpoint", "mcp.server")]

    for model in models:
        for ep in endpoints:
            if model.name.lower() in ep.description.lower():
                result.relate(model, ep, RelationshipType.USES)


def _link_agents_to_tools(result: AIBOMResult) -> None:
    agents = [c for c in result.components if "agent" in c.type.value.lower()]
    tools = [c for c in result.components if c.type.value in ("tool", "mcp.tool")]

    for agent in agents:
        agent_path = agent.path
        for tool in tools:
            if tool.path == agent_path:
                result.relate(agent, tool, RelationshipType.USES)


def _deduplicate_components(result: AIBOMResult) -> None:
    seen: dict[str, AIComponent] = {}
    unique: list[AIComponent] = []
    for comp in result.components:
        key = f"{comp.type.value}:{comp.name}:{comp.path}"
        if key in seen:
            existing = seen[key]
            existing.evidence = list(set(existing.evidence + comp.evidence))
        else:
            seen[key] = comp
            unique.append(comp)
    result.components = unique
