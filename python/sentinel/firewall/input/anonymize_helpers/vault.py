"""Reversible anonymization vault — stores mappings for de-anonymization."""
from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from .entity_types import EntityType
from .replacer import ReplacementResult

logger = logging.getLogger(__name__)


@dataclass
class VaultEntry:
    original: str
    replacement: str
    entity_type: EntityType
    timestamp: float = field(default_factory=time.time)
    session_id: str = ""
    ttl: int = 3600


class AnonymizationVault:
    """Thread-safe in-memory vault for reversible anonymization with optional disk persistence."""

    def __init__(self, persist_path: str | None = None, encryption_key: str | None = None):
        self._entries: dict[str, VaultEntry] = {}
        self._reverse: dict[str, str] = {}
        self._persist_path = Path(persist_path) if persist_path else None
        self._encryption_key = encryption_key
        if self._persist_path and self._persist_path.exists():
            self._load()

    def store(self, results: list[ReplacementResult], session_id: str = "") -> int:
        stored = 0
        for r in results:
            key = self._make_key(r.replacement)
            if key not in self._entries:
                self._entries[key] = VaultEntry(
                    original=r.original, replacement=r.replacement,
                    entity_type=r.entity_type, session_id=session_id,
                )
                self._reverse[self._make_key(r.original)] = r.replacement
                stored += 1
        if stored and self._persist_path:
            self._save()
        return stored

    def deanonymize(self, text: str) -> str:
        self._expire()
        for key, entry in self._entries.items():
            if entry.replacement in text:
                text = text.replace(entry.replacement, entry.original)
        return text

    def lookup(self, replacement: str) -> VaultEntry | None:
        key = self._make_key(replacement)
        entry = self._entries.get(key)
        if entry and self._is_expired(entry):
            del self._entries[key]
            return None
        return entry

    def lookup_original(self, original: str) -> str | None:
        key = self._make_key(original)
        return self._reverse.get(key)

    def clear_session(self, session_id: str) -> int:
        to_remove = [k for k, v in self._entries.items() if v.session_id == session_id]
        for k in to_remove:
            entry = self._entries.pop(k)
            self._reverse.pop(self._make_key(entry.original), None)
        if to_remove and self._persist_path:
            self._save()
        return len(to_remove)

    def clear_all(self) -> None:
        self._entries.clear()
        self._reverse.clear()
        if self._persist_path and self._persist_path.exists():
            self._persist_path.unlink()

    @property
    def size(self) -> int:
        return len(self._entries)

    def get_stats(self) -> dict:
        self._expire()
        by_type: dict[str, int] = {}
        for entry in self._entries.values():
            by_type[entry.entity_type.value] = by_type.get(entry.entity_type.value, 0) + 1
        return {"total": len(self._entries), "by_type": by_type}

    def _expire(self) -> None:
        time.time()
        expired = [k for k, v in self._entries.items() if self._is_expired(v)]
        for k in expired:
            entry = self._entries.pop(k)
            self._reverse.pop(self._make_key(entry.original), None)

    def _is_expired(self, entry: VaultEntry) -> bool:
        return entry.ttl > 0 and (time.time() - entry.timestamp) > entry.ttl

    def _make_key(self, text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()[:16]

    def _save(self) -> None:
        if not self._persist_path:
            return
        data = []
        for entry in self._entries.values():
            data.append({
                "original": entry.original, "replacement": entry.replacement,
                "entity_type": entry.entity_type.value, "timestamp": entry.timestamp,
                "session_id": entry.session_id, "ttl": entry.ttl,
            })
        payload = json.dumps(data)
        if self._encryption_key:
            payload = self._encrypt(payload)
        self._persist_path.write_text(payload)

    def _load(self) -> None:
        if not self._persist_path or not self._persist_path.exists():
            return
        try:
            payload = self._persist_path.read_text()
            if self._encryption_key:
                payload = self._decrypt(payload)
            data = json.loads(payload)
            for item in data:
                et = EntityType(item["entity_type"])
                entry = VaultEntry(
                    original=item["original"], replacement=item["replacement"],
                    entity_type=et, timestamp=item.get("timestamp", time.time()),
                    session_id=item.get("session_id", ""), ttl=item.get("ttl", 3600),
                )
                if not self._is_expired(entry):
                    key = self._make_key(entry.replacement)
                    self._entries[key] = entry
                    self._reverse[self._make_key(entry.original)] = entry.replacement
        except Exception as e:
            logger.warning("Failed to load vault: %s", e)

    def _encrypt(self, data: str) -> str:
        try:
            import base64

            from cryptography.fernet import Fernet
            key = base64.urlsafe_b64encode(hashlib.sha256(self._encryption_key.encode()).digest())
            return Fernet(key).encrypt(data.encode()).decode()
        except ImportError:
            logger.warning("cryptography not installed, storing vault unencrypted")
            return data

    def _decrypt(self, data: str) -> str:
        try:
            import base64

            from cryptography.fernet import Fernet
            key = base64.urlsafe_b64encode(hashlib.sha256(self._encryption_key.encode()).digest())
            return Fernet(key).decrypt(data.encode()).decode()
        except ImportError:
            return data
