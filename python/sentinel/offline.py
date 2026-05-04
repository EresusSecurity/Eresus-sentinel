"""Shared offline-mode helpers for optional live integrations."""

from __future__ import annotations

import os

_TRUTHY = {"1", "true", "yes", "on"}


def offline_enabled(explicit: bool | None = None) -> bool:
    """Return true when live network integrations should be skipped."""
    if explicit is not None:
        return bool(explicit)
    for key in ("SENTINEL_OFFLINE", "HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE"):
        if os.environ.get(key, "").strip().lower() in _TRUTHY:
            return True
    return False
