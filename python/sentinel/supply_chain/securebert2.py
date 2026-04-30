"""Offline SecureBERT 2.0 model catalog and evaluation fixtures."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SecureBERTModelSpec:
    task: str
    model_id: str
    model_type: str
    use_cases: tuple[str, ...]
    eval_fixture: str
    aliases: tuple[str, ...] = ()


_CATALOG: tuple[SecureBERTModelSpec, ...] = (
    SecureBERTModelSpec(
        task="masked_language_modeling",
        model_id="cisco-ai/SecureBERT2.0-base",
        model_type="ModernBERT encoder",
        use_cases=(
            "cybersecurity term prediction",
            "threat report encoding",
            "domain adaptation baseline",
        ),
        eval_fixture="mlm",
        aliases=("CiscoAITeam/SecureBERT2.0-base",),
    ),
    SecureBERTModelSpec(
        task="cross_encoder_retrieval",
        model_id="cisco-ai/SecureBERT2.0-cross_encoder",
        model_type="sentence-transformers cross encoder",
        use_cases=(
            "threat-intel pair ranking",
            "semantic search reranking",
            "document relevance scoring",
        ),
        eval_fixture="cross_encoder",
        aliases=("CiscoAITeam/SecureBERT2.0-cross_encoder",),
    ),
    SecureBERTModelSpec(
        task="bi_encoder_retrieval",
        model_id="cisco-ai/SecureBERT2.0-biencoder",
        model_type="sentence-transformers bi-encoder",
        use_cases=(
            "dense cybersecurity retrieval",
            "RAG corpus embedding",
            "nearest-neighbor search",
        ),
        eval_fixture="bi_encoder",
        aliases=("CiscoAITeam/SecureBERT2.0-biencoder",),
    ),
    SecureBERTModelSpec(
        task="named_entity_recognition",
        model_id="cisco-ai/SecureBERT2.0-NER",
        model_type="token classification",
        use_cases=("CVE extraction", "malware/entity tagging", "threat actor and product NER"),
        eval_fixture="ner",
        aliases=("CiscoAITeam/SecureBERT2.0-NER",),
    ),
    SecureBERTModelSpec(
        task="code_vulnerability_detection",
        model_id="cisco-ai/SecureBERT2.0-code-vuln-detection",
        model_type="sequence classification",
        use_cases=(
            "vulnerable code triage",
            "secure code review enrichment",
            "offline vuln benchmark",
        ),
        eval_fixture="code_vulnerability",
        aliases=("CiscoAITeam/SecureBERT2.0-code-vuln-detection",),
    ),
)


_EVAL_FIXTURES: dict[str, tuple[dict[str, str], ...]] = {
    "mlm": (
        {
            "input": "The attacker gained access through a [MASK] vulnerability.",
            "expected_family": "cybersecurity-term",
        },
        {
            "input": "The malware established [MASK] with its command and control server.",
            "expected_family": "threat-intelligence-term",
        },
    ),
    "cross_encoder": (
        {
            "query": "APT credential phishing campaign",
            "positive": "Threat actor used spear phishing to harvest credentials.",
            "negative": "The system generated a monthly billing invoice.",
        },
    ),
    "bi_encoder": (
        {
            "query": "remote code execution in deserialization",
            "positive": "Unsafe object deserialization can lead to arbitrary code execution.",
            "negative": "A stylesheet changed the button color.",
        },
    ),
    "ner": (
        {
            "text": "CVE-2024-3094 affected XZ Utils and enabled supply-chain compromise.",
            "entities": "CVE, PRODUCT, TECHNIQUE",
        },
    ),
    "code_vulnerability": (
        {
            "language": "python",
            "code": "import pickle\npickle.loads(user_input)",
            "label": "vulnerable",
        },
        {
            "language": "javascript",
            "code": "const query = 'SELECT * FROM users WHERE id=' + req.query.id",
            "label": "vulnerable",
        },
    ),
}


def securebert2_catalog() -> tuple[SecureBERTModelSpec, ...]:
    """Return the offline SecureBERT 2.0 Hugging Face model catalog."""
    return _CATALOG


def securebert2_model_ids(*, include_aliases: bool = False) -> tuple[str, ...]:
    ids: list[str] = []
    for spec in _CATALOG:
        ids.append(spec.model_id)
        if include_aliases:
            ids.extend(spec.aliases)
    return tuple(ids)


def get_securebert2_model(task_or_model_id: str) -> SecureBERTModelSpec | None:
    needle = task_or_model_id.strip().lower()
    for spec in _CATALOG:
        candidates = {
            spec.task.lower(),
            spec.model_id.lower(),
            *(alias.lower() for alias in spec.aliases),
        }
        if needle in candidates:
            return spec
    return None


def validate_securebert2_model_id(model_id: str, *, allow_aliases: bool = True) -> bool:
    ids = set(securebert2_model_ids(include_aliases=allow_aliases))
    return model_id in ids


def securebert2_eval_fixtures(
    task: str | None = None,
) -> dict[str, tuple[dict[str, str], ...]] | tuple[dict[str, str], ...]:
    """Return small deterministic SecureBERT 2.0 eval fixtures without loading models."""
    if task is None:
        return dict(_EVAL_FIXTURES)
    spec = get_securebert2_model(task)
    fixture_key = spec.eval_fixture if spec else task
    return _EVAL_FIXTURES.get(fixture_key, ())


__all__ = [
    "SecureBERTModelSpec",
    "securebert2_catalog",
    "securebert2_model_ids",
    "get_securebert2_model",
    "validate_securebert2_model_id",
    "securebert2_eval_fixtures",
]
