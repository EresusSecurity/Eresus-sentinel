"""Compatibility shim for older benchmark imports."""
from __future__ import annotations

from sentinel.artifact.safetensors_validator import SafetensorsValidator

# Simple alias — not a subclass, so plugin auto-discovery skips it
# (the __module__ check in _plugins.py filters it out).
SafetensorsScanner = SafetensorsValidator

__all__ = ["SafetensorsScanner"]
