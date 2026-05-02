"""Pickle deserialization security scanner.

Subpackage layout:
  scanner   — Public API (PickleScanner class)
  analyzer  — Deep opcode-level analysis engine
  raw_scan  — Raw byte fallback when pickletools crashes
  formats   — Format detection (protocol, nested pickle, TAR, YAML)
  findings  — Finding builders for each detection class
"""

from .parity import PickleParityResult, compare_pickle_backends
from .scanner import PickleScanner

__all__ = ["PickleParityResult", "PickleScanner", "compare_pickle_backends"]
