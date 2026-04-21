"""PII anonymizer — dual-engine: regex + Presidio NER (optional)."""

from __future__ import annotations

import re
import hashlib
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)




@dataclass
class AnonymizedEntity:
    """A single anonymized entity with its replacement."""
    original: str
    replacement: str
    entity_type: str
    start: int
    end: int
    score: float = 1.0




PII_DETECTORS = {
    "EMAIL": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "PHONE_US": re.compile(r"\b(?:\+1[\s-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b"),
    "PHONE_INTL": re.compile(r"\+\d{1,3}[\s.-]?\d{3,4}[\s.-]?\d{3,4}[\s.-]?\d{3,4}"),
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "CREDIT_CARD": re.compile(
        r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))\s?\d{4}\s?\d{4}\s?\d{4}\b"
    ),
    "IP_ADDRESS": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "DATE_OF_BIRTH": re.compile(
        r"\b(?:0[1-9]|1[0-2])/(?:0[1-9]|[12]\d|3[01])/(?:19|20)\d{2}\b"
    ),
    "US_PASSPORT": re.compile(r"\b[A-Z]\d{8}\b"),
    "IBAN": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?\d{0,16})\b"),
    "AWS_KEY": re.compile(r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}"),
    "NAME_PATTERN": re.compile(
        r"\b(?:Mr|Mrs|Ms|Dr|Prof)\.\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}\b"
    ),
    "CRYPTO_WALLET": re.compile(
        r"\b(?:0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{39,59})\b"
    ),
    "UUID": re.compile(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
    ),
    "US_BANK_NUMBER": re.compile(r"\b\d{8,17}\b"),
}


PRESIDIO_ENTITY_TYPES = [
    "CREDIT_CARD",
    "CRYPTO",
    "EMAIL_ADDRESS",
    "IBAN_CODE",
    "IP_ADDRESS",
    "PERSON",
    "PHONE_NUMBER",
    "US_SSN",
    "US_BANK_NUMBER",
    "LOCATION",
    "DATE_TIME",
    "NRP",
    "MEDICAL_LICENSE",
    "URL",
]




def _get_fake_value(entity_type: str) -> Optional[str]:
    """Generate a realistic fake value for a given entity type."""
    try:
        from faker import Faker
        fake = Faker()
        _FAKER_MAP = {
            "PERSON": fake.name,
            "NAME_PATTERN": fake.name,
            "EMAIL": fake.email,
            "EMAIL_ADDRESS": fake.email,
            "PHONE_US": fake.phone_number,
            "PHONE_INTL": fake.phone_number,
            "PHONE_NUMBER": fake.phone_number,
            "CREDIT_CARD": fake.credit_card_number,
            "SSN": fake.ssn,
            "US_SSN": fake.ssn,
            "IP_ADDRESS": fake.ipv4,
            "DATE_OF_BIRTH": lambda: fake.date_of_birth().strftime("%m/%d/%Y"),
            "DATE_TIME": lambda: fake.date_time().isoformat(),
            "LOCATION": fake.city,
            "IBAN_CODE": fake.iban,
            "IBAN": fake.iban,
            "URL": fake.url,
        }
        generator = _FAKER_MAP.get(entity_type)
        if generator:
            return generator()
    except ImportError:
        pass
    return None




class _PresidioEngine:
    """Optional Presidio NER wrapper. Falls back gracefully when not installed."""

    def __init__(
        self,
        entity_types: list[str] | None = None,
        language: str = "en",
        score_threshold: float = 0.35,
        use_onnx: bool = False,
    ):
        self._entity_types = entity_types or PRESIDIO_ENTITY_TYPES
        self._language = language
        self._score_threshold = score_threshold
        self._use_onnx = use_onnx
        self._analyzer = None
        self._available = False
        self._loaded = False

    @property
    def is_available(self) -> bool:
        if not self._loaded:
            self._try_load()
        return self._available

    def _try_load(self) -> None:
        """Attempt to load Presidio. Safe to call multiple times."""
        if self._loaded:
            return
        self._loaded = True

        try:
            from presidio_analyzer import AnalyzerEngine
            from presidio_analyzer.nlp_engine import NlpEngineProvider

            # spaCy model mapping for multi-language support
            SPACY_MODELS = {
                "en": "en_core_web_sm", "de": "de_core_news_sm",
                "fr": "fr_core_news_sm", "es": "es_core_news_sm",
                "it": "it_core_news_sm", "pt": "pt_core_news_sm",
                "nl": "nl_core_news_sm", "zh": "zh_core_web_sm",
                "ja": "ja_core_news_sm", "ru": "ru_core_news_sm",
                "tr": "xx_ent_wiki_sm", "ar": "xx_ent_wiki_sm",
                "xx": "xx_ent_wiki_sm",
            }
            model_name = SPACY_MODELS.get(self._language, "xx_ent_wiki_sm")

            try:
                import spacy
                if not spacy.util.is_package(model_name):
                    logger.info("Downloading spaCy model: %s", model_name)
                    from spacy.cli import download
                    download(model_name)
            except ImportError:
                logger.warning("spaCy not installed. Presidio NER unavailable.")
                return

            nlp_config = {
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": self._language, "model_name": model_name}],
            }
            nlp_engine = NlpEngineProvider(nlp_configuration=nlp_config).create_engine()

            self._analyzer = AnalyzerEngine(
                nlp_engine=nlp_engine,
                supported_languages=[self._language],
            )
            self._available = True
            logger.info("Presidio NER loaded: lang=%s, model=%s", self._language, model_name)

        except ImportError:
            logger.info(
                "presidio-analyzer not installed. Using regex-only PII detection. "
                "For ML-based NER: pip install presidio-analyzer spacy"
            )
        except Exception as exc:
            logger.warning("Failed to load Presidio engine: %s", exc)

    def analyze(self, text: str) -> list[AnonymizedEntity]:
        """Run Presidio analysis and return detected entities."""
        if not self.is_available or not self._analyzer:
            return []

        try:
            results = self._analyzer.analyze(
                text=text,
                language=self._language,
                entities=self._entity_types,
                score_threshold=self._score_threshold,
            )

            entities = []
            for r in results:
                entities.append(AnonymizedEntity(
                    original=text[r.start:r.end],
                    replacement="",  # Will be filled by caller
                    entity_type=r.entity_type,
                    start=r.start,
                    end=r.end,
                    score=r.score,
                ))
            return entities

        except Exception as exc:
            logger.warning("Presidio analysis error: %s", exc)
            return []




class AnonymizeScanner:
    """Dual-engine PII scanner: Presidio NER + regex, with faker and vault."""

    def __init__(
        self,
        entity_types: list[str] | None = None,
        use_hash: bool = False,
        use_faker: bool = False,
        use_presidio: bool = True,
        language: str = "en",
        score_threshold: float = 0.35,
        preamble: str = "",
        allowed_names: list[str] | None = None,
        hidden_names: list[str] | None = None,
    ):
        """
        Args:
            entity_types: PII entity types to detect. None = all types.
            use_hash: Use SHA-256 hash in placeholders instead of counters.
            use_faker: Replace PII with realistic fake data (requires faker).
            use_presidio: Enable Presidio NER engine (if installed).
            language: Language for NER analysis. Default "en".
            score_threshold: Presidio confidence threshold. Default 0.35.
            preamble: Text to prepend to sanitized output.
            allowed_names: Names to exclude from anonymization.
            hidden_names: Additional names to always detect and anonymize.
        """
        self._entity_types = set(entity_types) if entity_types else set(PII_DETECTORS.keys())
        self._use_hash = use_hash
        self._use_faker = use_faker
        self._preamble = preamble
        self._allowed_names = set(allowed_names) if allowed_names else set()
        self._hidden_names = hidden_names or []
        self._vault: dict[str, AnonymizedEntity] = {}
        self._counters: dict[str, int] = {}

        # Presidio NER engine (optional, graceful fallback)
        self._presidio: Optional[_PresidioEngine] = None
        if use_presidio:
            self._presidio = _PresidioEngine(
                language=language,
                score_threshold=score_threshold,
            )

    @property
    def vault(self) -> dict[str, AnonymizedEntity]:
        """Access the anonymization vault for de-anonymization."""
        return self._vault

    @property
    def has_presidio(self) -> bool:
        """Whether Presidio NER engine is operational."""
        return self._presidio is not None and self._presidio.is_available

    def scan(self, prompt: str) -> tuple[str, bool, float]:
        """Scan prompt for PII, anonymize detected entities.

        Returns:
            Tuple of (sanitized_prompt, is_clean, risk_score).
        """
        if not prompt.strip():
            return prompt, True, -1.0

        all_entities: list[AnonymizedEntity] = []

        # Engine 1: Presidio NER (if available)
        if self._presidio and self._presidio.is_available:
            presidio_entities = self._presidio.analyze(prompt)
            all_entities.extend(presidio_entities)

        # Engine 2: Regex patterns (always available)
        regex_entities = self._detect_regex(prompt)
        all_entities.extend(regex_entities)

        # Engine 3: Hidden names (custom deny-list)
        for name in self._hidden_names:
            for match in re.finditer(re.escape(name), prompt, re.IGNORECASE):
                all_entities.append(AnonymizedEntity(
                    original=match.group(0),
                    replacement="",
                    entity_type="CUSTOM",
                    start=match.start(),
                    end=match.end(),
                ))

        # Filter allowed names
        if self._allowed_names:
            all_entities = [
                e for e in all_entities
                if e.original not in self._allowed_names
            ]

        # Deduplicate overlapping spans (prefer higher score / earlier)
        all_entities = self._resolve_overlaps(all_entities)

        # Assign replacements
        for entity in all_entities:
            entity.replacement = self._get_replacement(
                entity.entity_type, entity.original
            )

        # Apply anonymization (reverse order to preserve indices)
        all_entities.sort(key=lambda e: e.start, reverse=True)
        anonymized = prompt
        for entity in all_entities:
            anonymized = (
                anonymized[:entity.start]
                + entity.replacement
                + anonymized[entity.end:]
            )
            self._vault[entity.replacement] = entity

        has_pii = len(all_entities) > 0
        risk = 0.0
        if has_pii:
            max_score = max(e.score for e in all_entities) if all_entities else 0.0
            risk = min(1.0, max(0.2, max_score))

        result = self._preamble + anonymized if self._preamble else anonymized
        return result, not has_pii, risk

    def _detect_regex(self, text: str) -> list[AnonymizedEntity]:
        """Detect PII using regex patterns."""
        entities = []
        for entity_type, pattern in PII_DETECTORS.items():
            if entity_type not in self._entity_types:
                continue
            for match in pattern.finditer(text):
                entities.append(AnonymizedEntity(
                    original=match.group(0),
                    replacement="",
                    entity_type=entity_type,
                    start=match.start(),
                    end=match.end(),
                ))
        return entities

    @staticmethod
    def _resolve_overlaps(
        entities: list[AnonymizedEntity],
    ) -> list[AnonymizedEntity]:
        """Resolve overlapping entity spans.

        When two entities overlap, keep the one with:
          1. Higher confidence score
          2. Longer span (ties broken by score)
        """
        if not entities:
            return []

        # Sort by start position, then by score descending
        entities.sort(key=lambda e: (e.start, -e.score))

        resolved = []
        last_end = -1

        for entity in entities:
            if entity.start >= last_end:
                resolved.append(entity)
                last_end = entity.end
            else:
                # Overlap — keep higher score
                if resolved and entity.score > resolved[-1].score:
                    resolved[-1] = entity
                    last_end = entity.end

        return resolved

    def _get_replacement(self, entity_type: str, original: str) -> str:
        """Generate a replacement string for an entity."""
        # Faker mode — generate realistic fake data
        if self._use_faker:
            fake_val = _get_fake_value(entity_type)
            if fake_val:
                return fake_val

        # Hash mode — deterministic placeholder
        if self._use_hash:
            h = hashlib.sha256(original.encode()).hexdigest()[:8]
            return f"[REDACTED_{entity_type}_{h}]"

        # Counter mode — sequential placeholder
        count = self._counters.get(entity_type, 0) + 1
        self._counters[entity_type] = count
        return f"[REDACTED_{entity_type}_{count}]"

    def clear_vault(self):
        """Clear the anonymization vault and counters."""
        self._vault.clear()
        self._counters.clear()
