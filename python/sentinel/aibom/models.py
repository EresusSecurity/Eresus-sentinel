"""AIBOM data model."""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

AIBOM_SCHEMA_VERSION = "aibom.result.v1"


class AIComponentType(str, Enum):
    MODEL_LLM = "model.llm"
    MODEL_EMBEDDING = "model.embedding"
    MODEL_IMAGE = "model.image"
    MODEL_AUDIO = "model.audio"
    MODEL_VIDEO = "model.video"
    MODEL_RERANKER = "model.reranker"
    MODEL_VISION = "model.vision"
    MODEL_MULTIMODAL = "model.multimodal"

    AGENT = "agent"
    AGENT_REACT = "agent.react"
    AGENT_PLANNER = "agent.planner"
    AGENT_ROUTER = "agent.router"

    MCP_SERVER = "mcp.server"
    MCP_CLIENT = "mcp.client"
    MCP_TOOL = "mcp.tool"

    VECTOR_STORE = "vector_store"
    DATASET = "dataset"
    EMBEDDING_INDEX = "embedding_index"
    PROMPT_TEMPLATE = "prompt_template"
    GUARDRAIL = "guardrail"
    SKILL = "skill"
    PLUGIN = "plugin"
    TOOL = "tool"
    SECRET = "secret"
    ENDPOINT = "endpoint"
    API_KEY_REF = "api_key_ref"
    CONFIG = "config"
    CONTAINER = "container"
    CI_PIPELINE = "ci_pipeline"
    WORKFLOW = "workflow"
    EVALUATION = "evaluation"
    TELEMETRY = "telemetry"
    CACHE = "cache"
    RAG_RETRIEVER = "rag.retriever"
    SHADOW_AI = "shadow_ai"


class RelationshipType(str, Enum):
    USES = "uses"
    CONTAINS = "contains"
    DEPENDS_ON = "depends_on"
    CALLS = "calls"
    GENERATES = "generates"
    CONSUMES = "consumes"
    AUTHORIZED_BY = "authorized_by"
    TRAINED_ON = "trained_on"
    CONFIGURED_BY = "configured_by"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class AIComponent:
    type: AIComponentType
    name: str
    version: str = ""
    path: str = ""
    description: str = ""
    vendor: str = ""
    license: str = ""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    properties: dict[str, Any] = field(default_factory=dict)
    hashes: dict[str, str] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)
    risks: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "name": self.name,
            "version": self.version,
            "path": self.path,
            "description": self.description,
            "vendor": self.vendor,
            "license": self.license,
            "properties": self.properties,
            "hashes": self.hashes,
            "evidence": self.evidence,
            "risks": self.risks,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AIComponent":
        return cls(
            id=str(data.get("id") or uuid.uuid4()),
            type=AIComponentType(str(data.get("type", AIComponentType.CONFIG.value))),
            name=str(data.get("name", "")),
            version=str(data.get("version", "")),
            path=str(data.get("path", "")),
            description=str(data.get("description", "")),
            vendor=str(data.get("vendor", "")),
            license=str(data.get("license", "")),
            properties=dict(data.get("properties") or {}),
            hashes=dict(data.get("hashes") or {}),
            evidence=list(data.get("evidence") or []),
            risks=list(data.get("risks") or []),
        )


@dataclass
class Relationship:
    source_id: str
    target_id: str
    type: RelationshipType
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "type": self.type.value if hasattr(self.type, "value") else str(self.type),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Relationship":
        return cls(
            source_id=str(data.get("source_id", "")),
            target_id=str(data.get("target_id", "")),
            type=RelationshipType(str(data.get("type", RelationshipType.USES.value))),
            metadata=dict(data.get("metadata") or {}),
        )


@dataclass
class AIBOMResult:
    components: list[AIComponent] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tool: str = "Eresus Sentinel AIBOM"
    version: str = "1.0"

    def add(self, comp: AIComponent) -> None:
        self.components.append(comp)

    def relate(self, src: AIComponent, tgt: AIComponent, t: RelationshipType) -> None:
        self.relationships.append(Relationship(src.id, tgt.id, t))

    def group_by_type(self) -> dict[str, list[AIComponent]]:
        out: dict[str, list[AIComponent]] = {}
        for c in self.components:
            out.setdefault(c.type.value, []).append(c)
        return out

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": AIBOM_SCHEMA_VERSION,
            "bom_format": "Eresus-AIBOM",
            "tool": self.tool,
            "version": self.version,
            "generated_at": self.generated_at,
            "summary": {
                "component_count": len(self.components),
                "relationship_count": len(self.relationships),
                "component_types": {
                    type_name: len(items)
                    for type_name, items in sorted(self.group_by_type().items())
                },
            },
            "metadata": self.metadata,
            "components": [component.as_dict() for component in self.components],
            "relationships": [relationship.as_dict() for relationship in self.relationships],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AIBOMResult":
        return cls(
            components=[
                AIComponent.from_dict(component)
                for component in data.get("components", [])
                if isinstance(component, dict)
            ],
            relationships=[
                Relationship.from_dict(relationship)
                for relationship in data.get("relationships", [])
                if isinstance(relationship, dict)
            ],
            metadata=dict(data.get("metadata") or {}),
            generated_at=str(data.get("generated_at") or datetime.now(timezone.utc).isoformat()),
            tool=str(data.get("tool") or "Eresus Sentinel AIBOM"),
            version=str(data.get("version") or "1.0"),
        )
