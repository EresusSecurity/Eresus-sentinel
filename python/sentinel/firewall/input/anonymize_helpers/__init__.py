"""NER-based anonymization helpers — entity types, engine, replacer, vault."""
from __future__ import annotations

from .entity_types import ENTITY_REGISTRY, FINANCIAL_ENTITIES, PII_ENTITIES, EntityType
from .ner_engine import NEREngine, NERResult, PresidioNEREngine, RegexNEREngine, SpacyNEREngine
from .replacer import EntityReplacer, ReplacementStrategy
from .vault import AnonymizationVault, VaultEntry

__all__ = [
    "EntityType", "ENTITY_REGISTRY", "PII_ENTITIES", "FINANCIAL_ENTITIES",
    "NEREngine", "NERResult", "SpacyNEREngine", "PresidioNEREngine", "RegexNEREngine",
    "EntityReplacer", "ReplacementStrategy",
    "AnonymizationVault", "VaultEntry",
]
