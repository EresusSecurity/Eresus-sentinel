"""NER-based anonymization helpers — entity types, engine, replacer, vault."""
from __future__ import annotations
from .entity_types import EntityType, ENTITY_REGISTRY, PII_ENTITIES, FINANCIAL_ENTITIES
from .ner_engine import NEREngine, NERResult, SpacyNEREngine, PresidioNEREngine, RegexNEREngine
from .replacer import EntityReplacer, ReplacementStrategy
from .vault import AnonymizationVault, VaultEntry

__all__ = [
    "EntityType", "ENTITY_REGISTRY", "PII_ENTITIES", "FINANCIAL_ENTITIES",
    "NEREngine", "NERResult", "SpacyNEREngine", "PresidioNEREngine", "RegexNEREngine",
    "EntityReplacer", "ReplacementStrategy",
    "AnonymizationVault", "VaultEntry",
]
