"""Pickle deserialization fuzzer backend.

Structure-aware pickle stream generation, mutation, and adversarial
payload validation for Sentinel's PickleScanner self-test pipeline.

Modules:
  opcodes          — Complete opcode definitions (protocol 0-5)
  pvm              — Pickle Virtual Machine stack simulation
  stdlib_globals   — Module/attribute pairs for GLOBAL emission
  generator        — Structure-aware stream generator
  mutators         — 17 mutation strategies
  payloads         — 56+ adversarial payload templates
  selftest         — Self-test pipeline ("Sentinel Eats Itself")
"""

from __future__ import annotations

from .generator import PickleGenerator
from .mutators import (
    PickleMutator,
    BitflipMutator,
    BoundaryMutator,
    OffByOneMutator,
    StringLenMutator,
    CharacterMutator,
    MemoIndexMutator,
    TypeConfusionMutator,
    OpcodeInsertMutator,
    OpcodeDeleteMutator,
    OpcodeSwapMutator,
    PayloadInjectMutator,
    ProtocolMutator,
    FrameCorruptionMutator,
    HavocMutator,
    GlobalRewriteMutator,
    CrossReferenceMutator,
    DeepNestingMutator,
)
from .payloads import PicklePayloadFactory
from .selftest import PickleSelfTest

__all__ = [
    "PickleGenerator",
    "PickleMutator",
    "BitflipMutator",
    "BoundaryMutator",
    "OffByOneMutator",
    "StringLenMutator",
    "CharacterMutator",
    "MemoIndexMutator",
    "TypeConfusionMutator",
    "OpcodeInsertMutator",
    "OpcodeDeleteMutator",
    "OpcodeSwapMutator",
    "PayloadInjectMutator",
    "ProtocolMutator",
    "FrameCorruptionMutator",
    "HavocMutator",
    "GlobalRewriteMutator",
    "CrossReferenceMutator",
    "DeepNestingMutator",
    "PicklePayloadFactory",
    "PickleSelfTest",
]
