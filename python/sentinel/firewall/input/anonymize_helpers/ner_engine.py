"""NER engine abstraction — multiple backends for entity recognition."""
from __future__ import annotations

import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass

from .entity_types import EntityType

logger = logging.getLogger(__name__)


@dataclass
class NERResult:
    entity_type: EntityType
    text: str
    start: int
    end: int
    score: float = 1.0
    source: str = "regex"


class NEREngine(ABC):
    @abstractmethod
    def detect(self, text: str, entity_types: set[EntityType] | None = None) -> list[NERResult]:
        ...

    def detect_all(self, text: str) -> list[NERResult]:
        return self.detect(text, None)


class RegexNEREngine(NEREngine):
    PATTERNS: list[tuple[EntityType, re.Pattern]] = [
        (EntityType.EMAIL, re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")),
        (EntityType.PHONE, re.compile(r"(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}")),
        (EntityType.SSN, re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
        (EntityType.CREDIT_CARD, re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b")),
        (EntityType.IBAN, re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b")),
        (EntityType.IP_ADDRESS, re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
        (EntityType.URL, re.compile(r"https?://[^\s<>\"']{5,200}")),
        (EntityType.DATE_OF_BIRTH, re.compile(r"\b(?:0[1-9]|1[0-2])[/-](?:0[1-9]|[12]\d|3[01])[/-](?:19|20)\d{2}\b")),
        (EntityType.AWS_KEY, re.compile(r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}")),
        (EntityType.API_KEY, re.compile(r"(?:sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{36}|glpat-[A-Za-z0-9_-]{20})")),
        (EntityType.PASSWORD, re.compile(r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']?[^\s"\']{6,}["\']?')),
        (EntityType.PASSPORT, re.compile(r"\b[A-Z]{1,2}\d{6,9}\b")),
        (EntityType.CRYPTO_WALLET, re.compile(r"\b(?:0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{39,59})\b")),
        (EntityType.NATIONAL_ID, re.compile(r"\b\d{9,12}\b")),
    ]

    def detect(self, text: str, entity_types: set[EntityType] | None = None) -> list[NERResult]:
        results: list[NERResult] = []
        for etype, pattern in self.PATTERNS:
            if entity_types and etype not in entity_types:
                continue
            for m in pattern.finditer(text):
                results.append(NERResult(
                    entity_type=etype, text=m.group(), start=m.start(), end=m.end(),
                    score=0.9, source="regex",
                ))
        return sorted(results, key=lambda r: r.start)


class SpacyNEREngine(NEREngine):
    def __init__(self, model: str = "en_core_web_sm"):
        self._model_name = model
        self._nlp: object = None
        self._loaded = False

    def _load(self):
        if self._loaded:
            return
        self._loaded = True
        try:
            import spacy
            self._nlp = spacy.load(self._model_name)
        except ImportError:
            logger.warning("spacy not installed, falling back to regex")
        except OSError:
            logger.warning("spacy model %s not found", self._model_name)

    SPACY_MAP = {
        "PERSON": EntityType.PERSON, "ORG": EntityType.ORGANIZATION,
        "GPE": EntityType.LOCATION, "LOC": EntityType.LOCATION,
        "DATE": EntityType.DATE_OF_BIRTH, "FAC": EntityType.ADDRESS,
    }

    def detect(self, text: str, entity_types: set[EntityType] | None = None) -> list[NERResult]:
        self._load()
        if self._nlp is None:
            return RegexNEREngine().detect(text, entity_types)
        doc = self._nlp(text)  # type: ignore[operator]
        results: list[NERResult] = []
        for ent in doc.ents:
            mapped = self.SPACY_MAP.get(ent.label_)
            if mapped is None:
                continue
            if entity_types and mapped not in entity_types:
                continue
            results.append(NERResult(
                entity_type=mapped, text=ent.text, start=ent.start_char, end=ent.end_char,
                score=0.85, source="spacy",
            ))
        regex_results = RegexNEREngine().detect(text, entity_types)
        spacy_spans = {(r.start, r.end) for r in results}
        for rr in regex_results:
            if (rr.start, rr.end) not in spacy_spans:
                results.append(rr)
        return sorted(results, key=lambda r: r.start)


class PresidioNEREngine(NEREngine):
    def __init__(self, language: str = "en"):
        self._language = language
        self._analyzer: object = None
        self._loaded = False

    def _load(self):
        if self._loaded:
            return
        self._loaded = True
        try:
            from presidio_analyzer import AnalyzerEngine
            self._analyzer = AnalyzerEngine()
        except ImportError:
            logger.warning("presidio-analyzer not installed, falling back to regex")

    PRESIDIO_MAP = {
        "PERSON": EntityType.PERSON, "EMAIL_ADDRESS": EntityType.EMAIL,
        "PHONE_NUMBER": EntityType.PHONE, "US_SSN": EntityType.SSN,
        "CREDIT_CARD": EntityType.CREDIT_CARD, "IBAN_CODE": EntityType.IBAN,
        "IP_ADDRESS": EntityType.IP_ADDRESS, "URL": EntityType.URL,
        "DATE_TIME": EntityType.DATE_OF_BIRTH, "LOCATION": EntityType.LOCATION,
        "US_PASSPORT": EntityType.PASSPORT, "US_DRIVER_LICENSE": EntityType.DRIVERS_LICENSE,
        "MEDICAL_LICENSE": EntityType.MEDICAL_RECORD, "CRYPTO": EntityType.CRYPTO_WALLET,
        "NRP": EntityType.NATIONAL_ID, "US_BANK_NUMBER": EntityType.BANK_ACCOUNT,
    }

    def detect(self, text: str, entity_types: set[EntityType] | None = None) -> list[NERResult]:
        self._load()
        if self._analyzer is None:
            return RegexNEREngine().detect(text, entity_types)
        presidio_results = self._analyzer.analyze(text=text, language=self._language)  # type: ignore[union-attr]
        results: list[NERResult] = []
        for pr in presidio_results:
            mapped = self.PRESIDIO_MAP.get(pr.entity_type)
            if mapped is None:
                continue
            if entity_types and mapped not in entity_types:
                continue
            results.append(NERResult(
                entity_type=mapped, text=text[pr.start:pr.end], start=pr.start, end=pr.end,
                score=pr.score, source="presidio",
            ))
        return sorted(results, key=lambda r: r.start)


class CompositeNEREngine(NEREngine):
    """Combines multiple NER engines, deduplicating overlapping spans."""

    def __init__(self, engines: list[NEREngine] | None = None):
        self.engines = engines or [RegexNEREngine()]

    def detect(self, text: str, entity_types: set[EntityType] | None = None) -> list[NERResult]:
        all_results: list[NERResult] = []
        for engine in self.engines:
            all_results.extend(engine.detect(text, entity_types))
        all_results.sort(key=lambda r: (r.start, -r.score))
        deduped: list[NERResult] = []
        last_end = -1
        for r in all_results:
            if r.start >= last_end:
                deduped.append(r)
                last_end = r.end
            elif r.score > 0.95:
                deduped.append(r)
                last_end = max(last_end, r.end)
        return deduped
