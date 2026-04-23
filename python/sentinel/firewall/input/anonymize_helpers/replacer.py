"""Entity replacement strategies for anonymization."""
from __future__ import annotations
import hashlib
import random
import string
from enum import Enum
from dataclasses import dataclass
from .entity_types import EntityType
from .ner_engine import NERResult


class ReplacementStrategy(str, Enum):
    MASK = "mask"
    REDACT = "redact"
    HASH = "hash"
    SYNTHETIC = "synthetic"
    PLACEHOLDER = "placeholder"


@dataclass
class ReplacementResult:
    original: str
    replacement: str
    entity_type: EntityType
    start: int
    end: int


class EntityReplacer:
    def __init__(self, strategy: ReplacementStrategy = ReplacementStrategy.PLACEHOLDER, hash_key: str = "sentinel"):
        self.strategy = strategy
        self._hash_key = hash_key
        self._counter: dict[EntityType, int] = {}

    def replace_entities(self, text: str, entities: list[NERResult]) -> tuple[str, list[ReplacementResult]]:
        sorted_entities = sorted(entities, key=lambda e: e.start, reverse=True)
        results: list[ReplacementResult] = []
        modified = text
        for ent in sorted_entities:
            replacement = self._get_replacement(ent)
            modified = modified[:ent.start] + replacement + modified[ent.end:]
            results.append(ReplacementResult(
                original=ent.text, replacement=replacement,
                entity_type=ent.entity_type, start=ent.start, end=ent.end,
            ))
        results.reverse()
        return modified, results

    def _get_replacement(self, entity: NERResult) -> str:
        if self.strategy == ReplacementStrategy.MASK:
            return self._mask(entity)
        elif self.strategy == ReplacementStrategy.REDACT:
            return f"[{entity.entity_type.value}]"
        elif self.strategy == ReplacementStrategy.HASH:
            return self._hash(entity)
        elif self.strategy == ReplacementStrategy.SYNTHETIC:
            return self._synthetic(entity)
        return self._placeholder(entity)

    def _mask(self, entity: NERResult) -> str:
        text = entity.text
        if entity.entity_type == EntityType.EMAIL:
            parts = text.split("@")
            if len(parts) == 2:
                return parts[0][0] + "***@" + parts[1]
        elif entity.entity_type == EntityType.PHONE:
            digits = [c for c in text if c.isdigit()]
            if len(digits) >= 4:
                return "***" + "".join(digits[-4:])
        elif entity.entity_type == EntityType.CREDIT_CARD:
            digits = [c for c in text if c.isdigit()]
            if len(digits) >= 4:
                return "****-****-****-" + "".join(digits[-4:])
        elif entity.entity_type == EntityType.SSN:
            return "***-**-" + text[-4:]
        return "*" * len(text)

    def _hash(self, entity: NERResult) -> str:
        h = hashlib.sha256(f"{self._hash_key}:{entity.text}".encode()).hexdigest()[:12]
        return f"[{entity.entity_type.value}:{h}]"

    def _synthetic(self, entity: NERResult) -> str:
        et = entity.entity_type
        if et == EntityType.PERSON:
            first = random.choice(["Alex", "Jordan", "Taylor", "Morgan", "Casey", "Riley", "Avery", "Quinn"])
            last = random.choice(["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis"])
            return f"{first} {last}"
        elif et == EntityType.EMAIL:
            user = "".join(random.choices(string.ascii_lowercase, k=8))
            return f"{user}@example.com"
        elif et == EntityType.PHONE:
            return f"+1-555-{random.randint(100,999)}-{random.randint(1000,9999)}"
        elif et == EntityType.IP_ADDRESS:
            return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        elif et == EntityType.SSN:
            return f"{random.randint(100,999)}-{random.randint(10,99)}-{random.randint(1000,9999)}"
        elif et == EntityType.CREDIT_CARD:
            return f"4111-1111-1111-{random.randint(1000,9999)}"
        elif et == EntityType.URL:
            return "https://example.com/" + "".join(random.choices(string.ascii_lowercase, k=6))
        return f"[SYNTHETIC_{et.value}]"

    def _placeholder(self, entity: NERResult) -> str:
        count = self._counter.get(entity.entity_type, 0) + 1
        self._counter[entity.entity_type] = count
        return f"<{entity.entity_type.value}_{count}>"
