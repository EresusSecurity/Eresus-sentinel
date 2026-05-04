"""Reference fingerprint database for model provenance scans."""

from __future__ import annotations

import hmac
import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from .signals import SIGNAL_IDS, ProvenanceSignal, extract_signals, signal_similarity, weighted_score

_DB_HMAC_KEY = b"eresus-sentinel-provenance-seed-v1"


@dataclass(frozen=True)
class ReferenceFingerprint:
    """A comparable reference model fingerprint."""

    model_id: str
    family: str
    publisher: str
    license: str
    parameter_hint: str
    signals: dict[str, ProvenanceSignal]

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_id": self.model_id,
            "family": self.family,
            "publisher": self.publisher,
            "license": self.license,
            "parameter_hint": self.parameter_hint,
            "signals": {key: signal.to_dict() for key, signal in self.signals.items()},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ReferenceFingerprint":
        signals = {
            key: ProvenanceSignal(
                signal_id=value.get("signal_id", key),
                score=float(value.get("score", 0.0)),
                confidence=float(value.get("confidence", 0.0)),
                value=dict(value.get("value", {})),
            )
            for key, value in dict(data.get("signals", {})).items()
        }
        return cls(
            model_id=str(data.get("model_id", "")),
            family=str(data.get("family", "")),
            publisher=str(data.get("publisher", "")),
            license=str(data.get("license", "")),
            parameter_hint=str(data.get("parameter_hint", "")),
            signals=signals,
        )


class FingerprintDatabase:
    """In-memory reference database with optional JSON persistence."""

    def __init__(self, references: list[ReferenceFingerprint] | None = None) -> None:
        self.references = references or _seed_references()

    @classmethod
    def load(cls, path: str | Path | None = None) -> "FingerprintDatabase":
        if path is None:
            return cls()
        db_path = Path(path)
        if not db_path.is_file():
            return cls()
        payload = json.loads(db_path.read_text(encoding="utf-8"))
        references = [ReferenceFingerprint.from_dict(item) for item in payload.get("references", [])]
        return cls(references)

    def to_dict(self) -> dict[str, Any]:
        references = [reference.to_dict() for reference in self.references]
        payload = {
            "schema_version": "provenance.db.v1",
            "manifest": self.manifest_for(references),
            "references": references,
        }
        payload["hmac_sha256"] = self.hmac_for(references)
        return payload

    def manifest_for(self, references: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        """Build a compact integrity manifest for the reference database."""
        body = references if references is not None else [reference.to_dict() for reference in self.references]
        families = sorted({str(reference.get("family", "")) for reference in body if reference.get("family")})
        publishers = sorted({str(reference.get("publisher", "")) for reference in body if reference.get("publisher")})
        return {
            "schema_version": "provenance.db-manifest.v1",
            "reference_count": len(body),
            "signal_ids": list(SIGNAL_IDS),
            "families": families,
            "publishers": publishers,
            "shards": [
                {
                    "id": "seed",
                    "reference_count": len(body),
                    "hmac_sha256": self.hmac_for(body),
                }
            ],
        }

    def write(self, path: str | Path) -> Path:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
        return output

    def hmac_for(self, references: list[dict[str, Any]] | None = None) -> str:
        body = references if references is not None else [reference.to_dict() for reference in self.references]
        encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        return hmac.new(_DB_HMAC_KEY, encoded, sha256).hexdigest()

    def verify_integrity(self, payload: dict[str, Any] | None = None) -> bool:
        if payload is None:
            payload = self.to_dict()
        expected = str(payload.get("hmac_sha256", ""))
        actual = self.hmac_for(list(payload.get("references", [])))
        if not hmac.compare_digest(expected, actual):
            return False
        manifest = payload.get("manifest") if isinstance(payload.get("manifest"), dict) else {}
        shards = manifest.get("shards") if isinstance(manifest.get("shards"), list) else []
        for shard in shards:
            if not isinstance(shard, dict) or shard.get("id") != "seed":
                continue
            shard_hmac = str(shard.get("hmac_sha256", ""))
            if shard_hmac and not hmac.compare_digest(shard_hmac, actual):
                return False
        return True

    def write_shards(self, directory: str | Path, *, shard_size: int = 50) -> dict[str, Any]:
        """Write deterministic JSON shard files and return their manifest."""
        output = Path(directory)
        output.mkdir(parents=True, exist_ok=True)
        references = [reference.to_dict() for reference in self.references]
        shards: list[dict[str, Any]] = []
        shard_size = max(1, shard_size)
        for index in range(0, len(references), shard_size):
            body = references[index:index + shard_size]
            shard_id = f"shard-{index // shard_size:04d}"
            shard_payload = {
                "schema_version": "provenance.db-shard.v1",
                "id": shard_id,
                "references": body,
                "hmac_sha256": self.hmac_for(body),
            }
            path = output / f"{shard_id}.json"
            path.write_text(json.dumps(shard_payload, indent=2, sort_keys=True), encoding="utf-8")
            shards.append(
                {
                    "id": shard_id,
                    "path": path.name,
                    "reference_count": len(body),
                    "hmac_sha256": shard_payload["hmac_sha256"],
                }
            )
        manifest = self.manifest_for(references)
        manifest["shards"] = shards
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
        return manifest

    def match(self, signals: dict[str, ProvenanceSignal], *, top_k: int = 5) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        for reference in self.references:
            similarities = signal_similarity(signals, reference.signals)
            score = weighted_score(similarities)
            matches.append(
                {
                    "model_id": reference.model_id,
                    "family": reference.family,
                    "publisher": reference.publisher,
                    "license": reference.license,
                    "parameter_hint": reference.parameter_hint,
                    "score": round(score, 6),
                    "signals": {key: round(value, 6) for key, value in similarities.items()},
                }
            )
        matches.sort(key=lambda item: item["score"], reverse=True)
        return matches[:top_k]

    def info(self) -> dict[str, Any]:
        families = sorted({reference.family for reference in self.references})
        publishers = sorted({reference.publisher for reference in self.references})
        return {
            "schema_version": "provenance.db-info.v1",
            "reference_count": len(self.references),
            "families": families,
            "publishers": publishers,
            "manifest": self.manifest_for(),
            "hmac_sha256": self.to_dict()["hmac_sha256"],
            "integrity_ok": self.verify_integrity(),
        }


def _seed_references() -> list[ReferenceFingerprint]:
    seeds = [
        ("gpt2", "gpt2", "openai", "mit", "124M", {"model_type": "gpt2", "n_embd": 768, "n_layer": 12, "n_head": 12, "vocab_size": 50257}),
        ("gpt2-medium", "gpt2", "openai", "mit", "355M", {"model_type": "gpt2", "n_embd": 1024, "n_layer": 24, "n_head": 16, "vocab_size": 50257}),
        ("bert-base-uncased", "bert", "google", "apache-2.0", "110M", {"model_type": "bert", "hidden_size": 768, "num_hidden_layers": 12, "num_attention_heads": 12, "vocab_size": 30522}),
        ("bert-large-uncased", "bert", "google", "apache-2.0", "340M", {"model_type": "bert", "hidden_size": 1024, "num_hidden_layers": 24, "num_attention_heads": 16, "vocab_size": 30522}),
        ("roberta-base", "roberta", "meta", "mit", "125M", {"model_type": "roberta", "hidden_size": 768, "num_hidden_layers": 12, "num_attention_heads": 12, "vocab_size": 50265}),
        ("llama-7b", "llama", "meta", "custom", "7B", {"model_type": "llama", "hidden_size": 4096, "num_hidden_layers": 32, "num_attention_heads": 32, "vocab_size": 32000}),
        ("llama-13b", "llama", "meta", "custom", "13B", {"model_type": "llama", "hidden_size": 5120, "num_hidden_layers": 40, "num_attention_heads": 40, "vocab_size": 32000}),
        ("mistral-7b", "mistral", "mistral-ai", "apache-2.0", "7B", {"model_type": "mistral", "hidden_size": 4096, "num_hidden_layers": 32, "num_attention_heads": 32, "vocab_size": 32000}),
        ("gemma-2b", "gemma", "google", "gemma", "2B", {"model_type": "gemma", "hidden_size": 2048, "num_hidden_layers": 18, "num_attention_heads": 8, "vocab_size": 256000}),
        ("gemma-7b", "gemma", "google", "gemma", "7B", {"model_type": "gemma", "hidden_size": 3072, "num_hidden_layers": 28, "num_attention_heads": 16, "vocab_size": 256000}),
    ]
    references: list[ReferenceFingerprint] = []
    for model_id, family, publisher, license_name, parameter_hint, config in seeds:
        signals = _signals_from_seed(config)
        references.append(
            ReferenceFingerprint(
                model_id=model_id,
                family=family,
                publisher=publisher,
                license=license_name,
                parameter_hint=parameter_hint,
                signals=signals,
            )
        )
    return references


def _signals_from_seed(config: dict[str, Any]) -> dict[str, ProvenanceSignal]:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="sentinel-provenance-seed-") as tmp:
        root = Path(tmp)
        (root / "config.json").write_text(json.dumps(config), encoding="utf-8")
        vocab_size = int(config.get("vocab_size", 0) or 0)
        vocab = {f"tok_{index}": index for index in range(min(vocab_size, 2048))}
        tokenizer = {"model": {"type": config.get("model_type", "unknown"), "vocab": vocab}}
        (root / "tokenizer.json").write_text(json.dumps(tokenizer), encoding="utf-8")
        return extract_signals(root)
