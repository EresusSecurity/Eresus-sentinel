"""Deterministic model provenance signal extraction.

The extractor is intentionally metadata-first and streaming-friendly. It does
not deserialize model code or load tensors into memory; it uses config,
tokenizer, file manifests, and safetensors headers as cheap lineage signals.
"""

from __future__ import annotations

import hashlib
import json
import math
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SIGNAL_IDS = ("MFI", "TFV", "VOA", "EAS", "NLF", "LEP", "END", "WVC")


@dataclass(frozen=True)
class ProvenanceSignal:
    """A single comparable provenance signal."""

    signal_id: str
    score: float
    value: dict[str, Any]
    confidence: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "signal_id": self.signal_id,
            "score": round(self.score, 6),
            "confidence": round(self.confidence, 6),
            "value": self.value,
        }


def extract_signals(model_path: str | Path) -> dict[str, ProvenanceSignal]:
    """Extract all eight provenance signals from a local model path."""
    root = Path(model_path)
    files = _model_files(root)
    config = _read_json(_first_existing(root, ("config.json",)))
    tokenizer = _read_json(_first_existing(root, ("tokenizer.json", "tokenizer_config.json")))
    vocab = _read_vocab(root)
    tensor_names = _tensor_names(root)

    return {
        "MFI": _signal_mfi(config, files),
        "TFV": _signal_tfv(tokenizer, config, vocab),
        "VOA": _signal_voa(vocab),
        "EAS": _signal_eas(tensor_names, files),
        "NLF": _signal_nlf(tensor_names),
        "LEP": _signal_lep(files),
        "END": _signal_end(config, tensor_names, files),
        "WVC": _signal_wvc(config, tokenizer, tensor_names, files),
    }


def signal_similarity(left: dict[str, ProvenanceSignal], right: dict[str, ProvenanceSignal]) -> dict[str, float]:
    """Compute per-signal similarity scores between two extracted fingerprints."""
    similarities: dict[str, float] = {}
    for signal_id in SIGNAL_IDS:
        a = left.get(signal_id)
        b = right.get(signal_id)
        if not a or not b:
            similarities[signal_id] = 0.0
            continue
        similarities[signal_id] = _value_similarity(signal_id, a.value, b.value)
    return similarities


def weighted_score(similarities: dict[str, float]) -> float:
    weights = {
        "MFI": 0.22,
        "TFV": 0.15,
        "VOA": 0.14,
        "EAS": 0.12,
        "NLF": 0.10,
        "LEP": 0.10,
        "END": 0.08,
        "WVC": 0.09,
    }
    total = sum(weights.values())
    return sum(similarities.get(signal_id, 0.0) * weight for signal_id, weight in weights.items()) / total


def _model_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    if not root.exists():
        return []
    interesting = {
        ".json", ".safetensors", ".bin", ".pt", ".pth", ".gguf", ".model", ".txt",
        ".vocab", ".merges",
    }
    return sorted(path for path in root.rglob("*") if path.is_file() and path.suffix.lower() in interesting)


def _first_existing(root: Path, names: tuple[str, ...]) -> Path | None:
    if root.is_file():
        return None
    for name in names:
        path = root / name
        if path.is_file():
            return path
    return None


def _read_json(path: Path | None) -> dict[str, Any]:
    if not path:
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}


def _read_vocab(root: Path) -> set[str]:
    vocab: set[str] = set()
    tokenizer = _read_json(_first_existing(root, ("tokenizer.json",)))
    model = tokenizer.get("model") if isinstance(tokenizer.get("model"), dict) else {}
    model_vocab = model.get("vocab") if isinstance(model.get("vocab"), dict) else {}
    vocab.update(str(token) for token in model_vocab.keys())

    vocab_json = _read_json(_first_existing(root, ("vocab.json",)))
    if isinstance(vocab_json, dict):
        vocab.update(str(token) for token in vocab_json.keys())

    vocab_txt = _first_existing(root, ("vocab.txt",))
    if vocab_txt:
        try:
            vocab.update(line.strip() for line in vocab_txt.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip())
        except OSError:
            pass
    return vocab


def _tensor_names(root: Path) -> list[str]:
    names: list[str] = []
    files = [root] if root.is_file() else sorted(root.rglob("*.safetensors")) if root.exists() else []
    for path in files:
        names.extend(_safetensors_header_names(path))
    return sorted(set(names))


def _safetensors_header_names(path: Path) -> list[str]:
    try:
        with open(path, "rb") as handle:
            raw_len = handle.read(8)
            if len(raw_len) != 8:
                return []
            header_len = struct.unpack("<Q", raw_len)[0]
            if header_len > 16 * 1024 * 1024:
                return []
            header = json.loads(handle.read(header_len).decode("utf-8", errors="replace"))
    except Exception:
        return []
    if not isinstance(header, dict):
        return []
    return sorted(key for key, value in header.items() if key != "__metadata__" and isinstance(value, dict))


def _signal_mfi(config: dict[str, Any], files: list[Path]) -> ProvenanceSignal:
    architecture = config.get("model_type") or _first(config.get("architectures")) or "unknown"
    keys = sorted(str(key) for key in config.keys())
    shape = {
        "architecture": str(architecture).lower(),
        "hidden_size": config.get("hidden_size") or config.get("n_embd") or config.get("d_model"),
        "layers": config.get("num_hidden_layers") or config.get("n_layer") or config.get("num_layers"),
        "heads": config.get("num_attention_heads") or config.get("n_head"),
        "vocab_size": config.get("vocab_size"),
        "config_hash": _hash_json({key: config.get(key) for key in keys[:64]}),
        "file_count": len(files),
    }
    confidence = 0.9 if config else 0.25 if files else 0.0
    return ProvenanceSignal("MFI", confidence, shape, confidence)


def _signal_tfv(tokenizer: dict[str, Any], config: dict[str, Any], vocab: set[str]) -> ProvenanceSignal:
    model = tokenizer.get("model") if isinstance(tokenizer.get("model"), dict) else {}
    special = tokenizer.get("added_tokens") if isinstance(tokenizer.get("added_tokens"), list) else []
    value = {
        "tokenizer_model": str(model.get("type") or tokenizer.get("tokenizer_class") or "unknown").lower(),
        "vocab_size": len(vocab) or config.get("vocab_size") or 0,
        "has_normalizer": isinstance(tokenizer.get("normalizer"), dict),
        "has_pre_tokenizer": isinstance(tokenizer.get("pre_tokenizer"), dict),
        "special_token_count": len(special),
        "feature_hash": _hash_json(
            {
                "model": model.get("type"),
                "normalizer": tokenizer.get("normalizer"),
                "pre_tokenizer": tokenizer.get("pre_tokenizer"),
                "post_processor": tokenizer.get("post_processor"),
            }
        ),
    }
    confidence = 0.85 if tokenizer or vocab else 0.2 if config.get("vocab_size") else 0.0
    return ProvenanceSignal("TFV", confidence, value, confidence)


def _signal_voa(vocab: set[str]) -> ProvenanceSignal:
    sample = sorted(vocab)[:2048]
    value = {
        "vocab_size": len(vocab),
        "sample_hash": _hash_json(sample),
        "anchors": sorted(token for token in vocab if token in {"<s>", "</s>", "[CLS]", "[SEP]", "<pad>", "<unk>", "Ġthe", "the"})[:16],
    }
    confidence = 0.9 if vocab else 0.0
    return ProvenanceSignal("VOA", confidence, value, confidence)


def _signal_eas(tensor_names: list[str], files: list[Path]) -> ProvenanceSignal:
    anchors = [name for name in tensor_names if any(part in name.lower() for part in ("embed", "wte", "token"))]
    value = {
        "embedding_tensors": anchors[:64],
        "embedding_count": len(anchors),
        "manifest_hash": _hash_json([path.name for path in files if path.suffix.lower() in {".safetensors", ".bin", ".pt", ".pth"}]),
    }
    confidence = 0.75 if anchors else 0.25 if files else 0.0
    return ProvenanceSignal("EAS", confidence, value, confidence)


def _signal_nlf(tensor_names: list[str]) -> ProvenanceSignal:
    norm_names = [name for name in tensor_names if "norm" in name.lower() or "ln_" in name.lower()]
    value = {
        "norm_count": len(norm_names),
        "norm_hash": _hash_json(norm_names[:256]),
        "first_norms": norm_names[:32],
    }
    confidence = 0.8 if norm_names else 0.0
    return ProvenanceSignal("NLF", confidence, value, confidence)


def _signal_lep(files: list[Path]) -> ProvenanceSignal:
    sizes = [path.stat().st_size for path in files if path.exists()]
    buckets = _histogram(sizes, buckets=8)
    value = {
        "file_count": len(files),
        "total_bytes": sum(sizes),
        "size_histogram": buckets,
        "manifest_hash": _hash_json([(path.name, path.stat().st_size) for path in files if path.exists()][:512]),
    }
    confidence = 0.65 if files else 0.0
    return ProvenanceSignal("LEP", confidence, value, confidence)


def _signal_end(config: dict[str, Any], tensor_names: list[str], files: list[Path]) -> ProvenanceSignal:
    dims = [
        config.get("hidden_size"),
        config.get("intermediate_size"),
        config.get("vocab_size"),
        config.get("num_attention_heads"),
        config.get("num_hidden_layers"),
    ]
    numeric = [int(value) for value in dims if isinstance(value, (int, float))]
    value = {
        "dimension_histogram": _histogram(numeric, buckets=8),
        "tensor_name_count": len(tensor_names),
        "weight_file_count": sum(1 for path in files if path.suffix.lower() in {".safetensors", ".bin", ".pt", ".pth"}),
    }
    confidence = 0.7 if numeric else 0.25 if tensor_names else 0.0
    return ProvenanceSignal("END", confidence, value, confidence)


def _signal_wvc(config: dict[str, Any], tokenizer: dict[str, Any], tensor_names: list[str], files: list[Path]) -> ProvenanceSignal:
    value = {
        "config_hash": _hash_json(config),
        "tokenizer_hash": _hash_json(tokenizer),
        "tensor_hash": _hash_json(tensor_names[:2048]),
        "file_hash": _hash_json([path.name for path in files][:2048]),
    }
    confidence = 0.85 if config or tokenizer or tensor_names else 0.0
    return ProvenanceSignal("WVC", confidence, value, confidence)


def _value_similarity(signal_id: str, left: dict[str, Any], right: dict[str, Any]) -> float:
    if signal_id == "MFI":
        return _average(
            [
                1.0 if left.get("architecture") == right.get("architecture") else 0.0,
                _num_similarity(left.get("hidden_size"), right.get("hidden_size")),
                _num_similarity(left.get("layers"), right.get("layers")),
                _num_similarity(left.get("heads"), right.get("heads")),
                _num_similarity(left.get("vocab_size"), right.get("vocab_size")),
            ]
        )
    if signal_id == "TFV":
        return _average(
            [
                1.0 if left.get("tokenizer_model") == right.get("tokenizer_model") else 0.0,
                _num_similarity(left.get("vocab_size"), right.get("vocab_size")),
                1.0 if left.get("feature_hash") == right.get("feature_hash") else 0.25,
            ]
        )
    if signal_id == "VOA":
        return _average(
            [
                _num_similarity(left.get("vocab_size"), right.get("vocab_size")),
                _jaccard(set(left.get("anchors", [])), set(right.get("anchors", []))),
                1.0 if left.get("sample_hash") == right.get("sample_hash") else 0.0,
            ]
        )
    if signal_id in {"EAS", "NLF"}:
        key = "embedding_tensors" if signal_id == "EAS" else "first_norms"
        return _jaccard(set(left.get(key, [])), set(right.get(key, [])))
    if signal_id in {"LEP", "END"}:
        hist_key = "size_histogram" if signal_id == "LEP" else "dimension_histogram"
        return _cosine(left.get(hist_key, []), right.get(hist_key, []))
    if signal_id == "WVC":
        keys = ("config_hash", "tokenizer_hash", "tensor_hash", "file_hash")
        return sum(1 for key in keys if left.get(key) == right.get(key)) / len(keys)
    return 0.0


def _first(value: Any) -> Any:
    if isinstance(value, list) and value:
        return value[0]
    return value


def _hash_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:32]


def _histogram(values: list[int], *, buckets: int) -> list[float]:
    if not values:
        return [0.0] * buckets
    lo = min(values)
    hi = max(values)
    if lo == hi:
        out = [0.0] * buckets
        out[0] = 1.0
        return out
    out = [0.0] * buckets
    for value in values:
        index = min(buckets - 1, int(((value - lo) / (hi - lo)) * buckets))
        out[index] += 1.0
    total = sum(out) or 1.0
    return [round(item / total, 6) for item in out]


def _num_similarity(left: Any, right: Any) -> float:
    if left in (None, 0, "") or right in (None, 0, ""):
        return 0.0
    try:
        a = float(left)
        b = float(right)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, 1.0 - abs(a - b) / max(abs(a), abs(b), 1.0))


def _jaccard(left: set[Any], right: set[Any]) -> float:
    if not left and not right:
        return 0.0
    return len(left & right) / len(left | right)


def _cosine(left: list[float], right: list[float]) -> float:
    if not left or not right or len(left) != len(right):
        return 0.0
    dot = sum(a * b for a, b in zip(left, right))
    norm_a = math.sqrt(sum(a * a for a in left))
    norm_b = math.sqrt(sum(b * b for b in right))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)


def _average(values: list[float]) -> float:
    clean = [value for value in values if value >= 0.0]
    return sum(clean) / len(clean) if clean else 0.0
