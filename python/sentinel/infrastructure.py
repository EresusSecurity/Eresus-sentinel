"""Infrastructure utilities — rule catalog, cache, HF popular models whitelist."""
from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


# ── Rule Catalog ───────────────────────────────────────────────────

@dataclass(frozen=True)
class RuleCatalogEntry:
    code: str
    name: str
    severity: str
    description: str
    patterns: tuple[str, ...]


RULE_CATALOG: tuple[RuleCatalogEntry, ...] = (
    RuleCatalogEntry("S101", "os module import", "CRITICAL", "OS command execution via os module", (r"import\s+os\b", r"from\s+os\s+import")),
    RuleCatalogEntry("S102", "sys module import", "CRITICAL", "System manipulation via sys module", (r"import\s+sys\b", r"from\s+sys\s+import")),
    RuleCatalogEntry("S103", "subprocess import", "CRITICAL", "Process spawning via subprocess", (r"import\s+subprocess", r"from\s+subprocess\s+import")),
    RuleCatalogEntry("S104", "eval/exec usage", "CRITICAL", "Dynamic code execution", (r"\beval\s*\(", r"\bexec\s*\(")),
    RuleCatalogEntry("S105", "compile usage", "CRITICAL", "Runtime code compilation", (r"\bcompile\s*\(",)),
    RuleCatalogEntry("S106", "pickle loads", "CRITICAL", "Pickle deserialization", (r"pickle\.loads", r"pickle\.load\b")),
    RuleCatalogEntry("S107", "marshal loads", "CRITICAL", "Marshal deserialization", (r"marshal\.loads",)),
    RuleCatalogEntry("S108", "shelve open", "HIGH", "Shelve deserialization", (r"shelve\.open",)),
    RuleCatalogEntry("S109", "__import__", "CRITICAL", "Dynamic import", (r"__import__\s*\(",)),
    RuleCatalogEntry("S110", "ctypes usage", "HIGH", "Native code loading", (r"ctypes\.CDLL", r"ctypes\.cdll")),
    RuleCatalogEntry("S111", "socket usage", "HIGH", "Network communication", (r"socket\.socket", r"socket\.connect")),
    RuleCatalogEntry("S112", "http client", "MEDIUM", "HTTP requests", (r"urllib\.request", r"http\.client", r"requests\.get")),
    RuleCatalogEntry("S113", "webbrowser", "MEDIUM", "Browser invocation", (r"webbrowser\.open",)),
    RuleCatalogEntry("S114", "pty spawn", "CRITICAL", "PTY spawning", (r"pty\.spawn",)),
    RuleCatalogEntry("S115", "code interact", "HIGH", "Interactive console", (r"code\.interact",)),
    RuleCatalogEntry("S116", "shutil rmtree", "HIGH", "Recursive deletion", (r"shutil\.rmtree",)),
    RuleCatalogEntry("S117", "tempfile usage", "LOW", "Temporary file creation", (r"tempfile\.",)),
    RuleCatalogEntry("S118", "base64 decode", "MEDIUM", "Base64 decoding (obfuscation)", (r"base64\.b64decode",)),
    RuleCatalogEntry("S119", "zipfile extract", "MEDIUM", "ZIP extraction (path traversal risk)", (r"zipfile\..*extract",)),
    RuleCatalogEntry("S120", "tarfile extract", "MEDIUM", "TAR extraction (path traversal risk)", (r"tarfile\..*extract",)),
)


def get_rule(code: str) -> RuleCatalogEntry | None:
    for entry in RULE_CATALOG:
        if entry.code == code:
            return entry
    return None


# ── Scan Results Cache ──────────────────────────────────────────────

class ScanResultsCache:
    """File-hash-based scan results cache with TTL."""

    def __init__(self, cache_dir: str | None = None, ttl: int = 3600):
        self._cache_dir = Path(cache_dir) if cache_dir else Path.home() / ".cache" / "sentinel"
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._ttl = ttl

    def _hash_file(self, filepath: str) -> str:
        h = hashlib.blake2b(digest_size=16)
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()

    def get(self, filepath: str) -> list[dict] | None:
        try:
            file_hash = self._hash_file(filepath)
            cache_path = self._cache_dir / f"{file_hash}.json"
            if not cache_path.exists():
                return None
            data = json.loads(cache_path.read_text())
            if time.time() - data.get("timestamp", 0) > self._ttl:
                cache_path.unlink(missing_ok=True)
                return None
            return data.get("findings", [])
        except Exception:
            return None

    def put(self, filepath: str, findings: list[dict]) -> None:
        try:
            file_hash = self._hash_file(filepath)
            cache_path = self._cache_dir / f"{file_hash}.json"
            cache_path.write_text(json.dumps({"timestamp": time.time(), "findings": findings, "file": filepath}))
        except Exception:
            pass

    def invalidate(self, filepath: str) -> None:
        try:
            file_hash = self._hash_file(filepath)
            cache_path = self._cache_dir / f"{file_hash}.json"
            cache_path.unlink(missing_ok=True)
        except Exception:
            pass

    def clear(self) -> int:
        count = 0
        for p in self._cache_dir.glob("*.json"):
            p.unlink()
            count += 1
        return count

    def stats(self) -> dict:
        entries = list(self._cache_dir.glob("*.json"))
        total_size = sum(p.stat().st_size for p in entries)
        return {"entries": len(entries), "size_bytes": total_size, "cache_dir": str(self._cache_dir)}


# ── HuggingFace Popular Models Whitelist ────────────────────────

POPULAR_MODELS: set[str] = {
    "meta-llama/Llama-2-7b-hf", "meta-llama/Llama-2-13b-hf", "meta-llama/Llama-2-70b-hf",
    "meta-llama/Meta-Llama-3-8B", "meta-llama/Meta-Llama-3-70B", "meta-llama/Meta-Llama-3.1-8B-Instruct",
    "google/gemma-2b", "google/gemma-7b", "google/flan-t5-base", "google/flan-t5-large",
    "google/flan-t5-xxl", "google/bert-base-uncased", "google/vit-base-patch16-224",
    "microsoft/phi-2", "microsoft/DialoGPT-medium", "microsoft/deberta-v3-base",
    "mistralai/Mistral-7B-v0.1", "mistralai/Mixtral-8x7B-v0.1", "mistralai/Mistral-7B-Instruct-v0.2",
    "openai/clip-vit-base-patch32", "openai/whisper-base", "openai/whisper-large-v3",
    "facebook/bart-large-cnn", "facebook/opt-1.3b", "facebook/sam-vit-base",
    "stabilityai/stable-diffusion-xl-base-1.0", "stabilityai/stable-diffusion-2-1",
    "sentence-transformers/all-MiniLM-L6-v2", "sentence-transformers/all-mpnet-base-v2",
    "BAAI/bge-base-en-v1.5", "BAAI/bge-large-en-v1.5", "BAAI/bge-m3",
    "deepseek-ai/deepseek-coder-6.7b-base", "deepseek-ai/DeepSeek-V2",
    "Qwen/Qwen-7B", "Qwen/Qwen-14B", "Qwen/Qwen2-7B-Instruct",
    "bigscience/bloom-560m", "bigscience/bloom-7b1", "EleutherAI/gpt-neo-2.7B",
    "EleutherAI/gpt-j-6b", "EleutherAI/pythia-6.9b", "tiiuae/falcon-7b",
    "tiiuae/falcon-40b", "nvidia/Llama-3.1-Nemotron-70B-Instruct-HF",
    "THUDM/chatglm3-6b", "01-ai/Yi-6B", "allenai/OLMo-7B",
    "databricks/dbrx-base", "CompVis/stable-diffusion-v1-4",
    "runwayml/stable-diffusion-v1-5", "lmsys/vicuna-7b-v1.5",
}


def is_popular_model(model_id: str) -> bool:
    return model_id in POPULAR_MODELS
