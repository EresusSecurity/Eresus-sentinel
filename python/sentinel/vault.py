"""
Eresus Sentinel — Vault: Secure PII Redaction & Restoration.

When scanners redact sensitive data

(PII, API keys, etc.), the Vault stores the original values securely and
provides deterministic placeholder tokens. After LLM processing, the Vault
can restore the original values — enabling safe LLM interactions without
data loss.

Architecture:
  1. Scanner detects PII → calls vault.redact("John Smith", "PERSON")
  2. Vault stores mapping: "[PERSON_a7f3]" → "John Smith"
  3. Redacted text sent to LLM
  4. LLM response received
  5. vault.restore(response) replaces all placeholders with originals

Security:
  - Values encrypted at rest (Fernet) if encryption key provided
  - Auto-expiry after configurable TTL
  - Thread-safe with RLock
  - No plaintext values in logs
  - Memory-only by default (no disk persistence)

Usage:
    from sentinel.vault import Vault

    vault = Vault()
    redacted = vault.redact("My SSN is 123-45-6789", "SSN")
    # Returns: "[SSN_a7f3]"

    # After LLM processing...
    restored = vault.restore("The SSN [SSN_a7f3] is valid")
    # Returns: "The SSN 123-45-6789 is valid"

    # Bulk redaction
    text, count = vault.redact_all(text, detections)
"""

from __future__ import annotations

import hashlib
import logging
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class VaultEntry:
    """Single stored redaction entry."""
    original: str             # Original sensitive value
    category: str             # PII type: PERSON, EMAIL, SSN, API_KEY, etc.
    placeholder: str          # Replacement token: [PERSON_a7f3]
    created_at: float         # time.monotonic() for TTL
    metadata: dict[str, Any] = field(default_factory=dict)


class Vault:
    """
    Secure in-memory vault for PII redaction and restoration.

    Thread-safe, with optional encryption and auto-expiry.

    Usage:
        vault = Vault(ttl_seconds=3600)  # 1 hour TTL

        # Single redaction
        placeholder = vault.redact("john@example.com", "EMAIL")

        # Bulk redact using detection results
        clean_text, count = vault.redact_all(
            "Contact john@example.com or call 555-0123",
            [
                {"value": "john@example.com", "category": "EMAIL"},
                {"value": "555-0123", "category": "PHONE"},
            ]
        )

        # Restore after LLM processing
        original = vault.restore(llm_response)
    """

    def __init__(
        self,
        ttl_seconds: float = 3600.0,
        encryption_key: bytes | None = None,
        max_entries: int = 10_000,
    ):
        self._lock = threading.RLock()
        self._entries: dict[str, VaultEntry] = {}  # placeholder → entry
        self._reverse: dict[str, str] = {}         # original_hash → placeholder
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._total_redactions = 0
        self._total_restorations = 0

        # Optional encryption
        self._cipher = None
        if encryption_key:
            try:
                from cryptography.fernet import Fernet
                # Validate key format before using
                if len(encryption_key) < 32:
                    logger.warning("Encryption key too short — use Fernet.generate_key() for a secure key")
                self._cipher = Fernet(encryption_key)
            except ImportError:
                logger.warning("cryptography package not installed — vault values stored in plaintext")
            except Exception as e:
                logger.error("Invalid encryption key: %s — vault values stored in plaintext", e)

    def redact(self, value: str, category: str = "PII", **metadata) -> str:
        """
        Store a sensitive value and return a placeholder token.

        Args:
            value: The sensitive value to redact.
            category: PII category (PERSON, EMAIL, SSN, API_KEY, etc.).
            **metadata: Additional metadata to store with the entry.

        Returns:
            Placeholder string like "[EMAIL_a7f3]".
        """
        if not value or not value.strip():
            return value

        value_hash = hashlib.sha256(value.encode("utf-8")).hexdigest()

        with self._lock:
            # Check if already redacted (deduplication)
            if value_hash in self._reverse:
                return self._reverse[value_hash]

            # Evict expired entries if at capacity
            if len(self._entries) >= self._max_entries:
                self._evict_expired()

            # Generate unique placeholder
            token = secrets.token_hex(8)  # 16 hex chars = 2^64 possibilities
            placeholder = f"[{category.upper()}_{token}]"

            # Ensure uniqueness
            while placeholder in self._entries:
                token = secrets.token_hex(8)
                placeholder = f"[{category.upper()}_{token}]"

            # Store (optionally encrypted)
            stored_value = self._encrypt(value) if self._cipher else value

            entry = VaultEntry(
                original=stored_value,
                category=category.upper(),
                placeholder=placeholder,
                created_at=time.monotonic(),
                metadata=metadata,
            )

            self._entries[placeholder] = entry
            self._reverse[value_hash] = placeholder
            self._total_redactions += 1

            logger.debug("Vault: redacted %s value → %s", category, placeholder)
            return placeholder

    def restore(self, text: str) -> str:
        """
        Replace all placeholder tokens in text with original values.

        Args:
            text: Text containing placeholder tokens.

        Returns:
            Text with all placeholders restored to original values.
        """
        if not text:
            return text

        with self._lock:
            result = text
            now = time.monotonic()
            for placeholder, entry in list(self._entries.items()):
                if placeholder in result:
                    # Check TTL on access — skip expired entries
                    if (now - entry.created_at) > self._ttl:
                        logger.debug("Vault: skipping expired entry %s", placeholder)
                        continue
                    original = self._decrypt(entry.original) if self._cipher else entry.original
                    result = result.replace(placeholder, original)
                    self._total_restorations += 1

            return result

    def redact_all(
        self,
        text: str,
        detections: list[dict[str, str]],
    ) -> tuple[str, int]:
        """
        Bulk redact multiple detected values in text.

        Args:
            text: The original text.
            detections: List of dicts with 'value' and 'category' keys.

        Returns:
            Tuple of (redacted_text, number_of_redactions).
        """
        count = 0
        result = text

        # Sort by length (longest first) to avoid partial replacements
        sorted_detections = sorted(detections, key=lambda d: len(d.get("value", "")), reverse=True)

        for detection in sorted_detections:
            value = detection.get("value", "")
            category = detection.get("category", "PII")

            if value and value in result:
                placeholder = self.redact(value, category)
                result = result.replace(value, placeholder)
                count += 1

        return result, count

    def restore_all(self, text: str) -> str:
        """Alias for restore() — restores all placeholders."""
        return self.restore(text)

    def clear(self) -> None:
        """Clear all vault entries."""
        with self._lock:
            self._entries.clear()
            self._reverse.clear()
            logger.info("Vault cleared")

    def size(self) -> int:
        """Number of stored entries."""
        with self._lock:
            return len(self._entries)

    def categories(self) -> dict[str, int]:
        """Count of entries by category."""
        with self._lock:
            counts: dict[str, int] = {}
            for entry in self._entries.values():
                counts[entry.category] = counts.get(entry.category, 0) + 1
            return counts

    def stats(self) -> dict[str, Any]:
        """Return vault statistics."""
        with self._lock:
            return {
                "entries": len(self._entries),
                "categories": self.categories(),
                "total_redactions": self._total_redactions,
                "total_restorations": self._total_restorations,
                "encrypted": self._cipher is not None,
                "ttl_seconds": self._ttl,
                "max_entries": self._max_entries,
            }

    def get_placeholder_pattern(self) -> re.Pattern:
        """Return a regex pattern that matches any vault placeholder."""
        return re.compile(r"\[[A-Z_]+_[0-9a-f]{4}\]")

    def contains_placeholders(self, text: str) -> bool:
        """Check if text contains any vault placeholders."""
        return bool(self.get_placeholder_pattern().search(text))

    # ── Private ───────────────────────────────────────────────────

    def _evict_expired(self) -> None:
        """Remove entries that have exceeded TTL."""
        now = time.monotonic()
        expired = [
            ph for ph, entry in self._entries.items()
            if (now - entry.created_at) > self._ttl
        ]
        for ph in expired:
            # Clean up reverse lookup
            entry = self._entries[ph]
            original = self._decrypt(entry.original) if self._cipher else entry.original
            value_hash = hashlib.sha256(original.encode("utf-8")).hexdigest()
            self._reverse.pop(value_hash, None)
            del self._entries[ph]

        if expired:
            logger.debug("Vault: evicted %d expired entries", len(expired))

    def _encrypt(self, value: str) -> str:
        """Encrypt a value using Fernet."""
        if self._cipher:
            return self._cipher.encrypt(value.encode("utf-8")).decode("utf-8")
        return value

    def _decrypt(self, value: str) -> str:
        """Decrypt a value using Fernet."""
        if self._cipher:
            return self._cipher.decrypt(value.encode("utf-8")).decode("utf-8")
        return value


# ── Module-level singleton ────────────────────────────────────────

_default_vault: Vault | None = None


def get_vault() -> Vault:
    """Get or create the default vault singleton."""
    global _default_vault
    if _default_vault is None:
        _default_vault = Vault()
    return _default_vault


def set_vault(vault: Vault) -> None:
    """Set a custom vault as the default singleton."""
    global _default_vault
    _default_vault = vault
