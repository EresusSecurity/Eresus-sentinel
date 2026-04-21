"""Backwards-compatibility shim.

The pickle scanner has been refactored into a proper subpackage at
``sentinel.artifact.pickle``.  This module re-exports ``PickleScanner``
so existing imports continue to work.
"""

from .pickle import PickleScanner

__all__ = ["PickleScanner"]
