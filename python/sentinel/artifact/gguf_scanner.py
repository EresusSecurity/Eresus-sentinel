"""Compatibility shim for older benchmark imports."""
from __future__ import annotations

from sentinel.artifact.gguf_analyzer import GGUFAnalyzer

# Simple alias — not a subclass, so plugin auto-discovery skips it
# (the __module__ check in _plugins.py filters it out).
GGUFScanner = GGUFAnalyzer

__all__ = ["GGUFScanner"]
