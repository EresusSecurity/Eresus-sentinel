"""AI Bill of Materials (AIBOM).

Detects AI-related components (models, agents, MCP servers/clients, vector
stores, datasets, guardrails, secrets, endpoints) across a repository and
emits interoperable reports (CycloneDX 1.6, SPDX 3.0.1, SARIF, HTML,
CSV, JUnit, Markdown).
"""
from __future__ import annotations

from sentinel.aibom.models import (
    AIBOM_SCHEMA_VERSION,
    AIBOMResult,
    AIComponent,
    AIComponentType,
    Relationship,
    RelationshipType,
)
from sentinel.aibom.scan_pipeline import ScanPipeline

__all__ = [
    "AIBOMResult",
    "AIBOM_SCHEMA_VERSION",
    "AIComponent",
    "AIComponentType",
    "Relationship",
    "RelationshipType",
    "ScanPipeline",
]
