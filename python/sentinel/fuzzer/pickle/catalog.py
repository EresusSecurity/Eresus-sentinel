"""Pickle-fuzzer parity catalog and deterministic smoke contracts."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .generator import PickleGenerator
from .mutators import (
    BitflipMutator,
    BoundaryMutator,
    CharacterMutator,
    CrossReferenceMutator,
    DeepNestingMutator,
    FrameCorruptionMutator,
    GlobalRewriteMutator,
    HavocMutator,
    MemoIndexMutator,
    OffByOneMutator,
    OpcodeDeleteMutator,
    OpcodeInsertMutator,
    OpcodeSwapMutator,
    PayloadInjectMutator,
    ProtocolMutator,
    StringLenMutator,
    TypeConfusionMutator,
)


@dataclass(frozen=True)
class PickleProtocolSpec:
    protocol: int
    has_proto_opcode: bool
    supports_frames: bool
    supports_out_of_band_buffers: bool


@dataclass(frozen=True)
class PickleMutatorSpec:
    name: str
    category: str
    unsafe: bool
    description: str


PROTOCOL_MATRIX: tuple[PickleProtocolSpec, ...] = (
    PickleProtocolSpec(0, False, False, False),
    PickleProtocolSpec(1, False, False, False),
    PickleProtocolSpec(2, True, False, False),
    PickleProtocolSpec(3, True, False, False),
    PickleProtocolSpec(4, True, True, False),
    PickleProtocolSpec(5, True, True, True),
)


MUTATOR_CATALOG: tuple[PickleMutatorSpec, ...] = (
    PickleMutatorSpec("bitflip", "byte-level", False, "Flip random bits in-place."),
    PickleMutatorSpec(
        "boundary",
        "argument",
        False,
        "Replace numeric arguments with boundary values.",
    ),
    PickleMutatorSpec("off_by_one", "argument", False, "Shift integer-like arguments by one."),
    PickleMutatorSpec("string_len", "argument", False, "Corrupt string and bytes length fields."),
    PickleMutatorSpec("character", "byte-level", False, "Replace printable character bytes."),
    PickleMutatorSpec("memo_index", "structure", False, "Mutate memo table indexes."),
    PickleMutatorSpec(
        "type_confusion",
        "structure",
        False,
        "Swap related opcodes to confuse stack types.",
    ),
    PickleMutatorSpec("opcode_insert", "opcode", False, "Insert safe or stack-neutral opcodes."),
    PickleMutatorSpec("opcode_delete", "opcode", False, "Delete opcode bytes."),
    PickleMutatorSpec("opcode_swap", "opcode", False, "Swap adjacent opcode bytes."),
    PickleMutatorSpec(
        "payload_inject",
        "payload",
        True,
        "Inject known adversarial payload fragments.",
    ),
    PickleMutatorSpec("protocol", "header", False, "Mutate protocol headers."),
    PickleMutatorSpec("frame_corruption", "frame", False, "Corrupt protocol 4/5 frame metadata."),
    PickleMutatorSpec("havoc", "byte-level", True, "Apply multiple random destructive mutations."),
    PickleMutatorSpec("global_rewrite", "payload", True, "Rewrite GLOBAL references."),
    PickleMutatorSpec(
        "cross_reference",
        "structure",
        False,
        "Add cross-reference and memo pressure.",
    ),
    PickleMutatorSpec("deep_nesting", "structure", False, "Add nested tuple/list structures."),
)


_MUTATOR_CLASSES = (
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


def protocol_matrix() -> tuple[PickleProtocolSpec, ...]:
    return PROTOCOL_MATRIX


def mutator_catalog() -> tuple[PickleMutatorSpec, ...]:
    return MUTATOR_CATALOG


def instantiate_mutators(seed: int | None = None) -> list[Any]:
    return [mutator_cls(seed=seed) for mutator_cls in _MUTATOR_CLASSES]


def pickle_fuzzer_manifest() -> dict[str, Any]:
    return {
        "protocols": [asdict(protocol) for protocol in PROTOCOL_MATRIX],
        "mutators": [asdict(mutator) for mutator in MUTATOR_CATALOG],
        "safe_mutators": sum(1 for mutator in MUTATOR_CATALOG if not mutator.unsafe),
        "unsafe_mutators": sum(1 for mutator in MUTATOR_CATALOG if mutator.unsafe),
    }


def pickle_fuzzer_smoke(seed: int = 1337) -> dict[str, Any]:
    generated = []
    for spec in PROTOCOL_MATRIX:
        sample = PickleGenerator(protocol=spec.protocol, min_opcodes=3, max_opcodes=8).generate(
            seed=seed + spec.protocol
        )
        generated.append(
            {
                "protocol": spec.protocol,
                "size": len(sample),
                "starts_with_proto": sample.startswith(b"\x80"),
                "stops_with_stop": sample.endswith(b"."),
            }
        )

    base = PickleGenerator(protocol=4, min_opcodes=3, max_opcodes=8).generate(seed=seed)
    mutated = [mutator.mutate(base) for mutator in instantiate_mutators(seed=seed)]
    return {
        "generated": generated,
        "mutator_count": len(mutated),
        "mutated_non_empty": sum(1 for item in mutated if item),
    }


__all__ = [
    "MUTATOR_CATALOG",
    "PROTOCOL_MATRIX",
    "PickleMutatorSpec",
    "PickleProtocolSpec",
    "instantiate_mutators",
    "mutator_catalog",
    "pickle_fuzzer_manifest",
    "pickle_fuzzer_smoke",
    "protocol_matrix",
]
