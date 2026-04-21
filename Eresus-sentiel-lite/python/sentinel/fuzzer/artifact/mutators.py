"""Artifact format mutators."""

from __future__ import annotations

import random
import struct
from typing import Optional

from ..base import Mutator


class ArtifactMutator(Mutator):
    """Meta-mutator for ML artifact files."""

    def __init__(self, seed: Optional[int] = None):
        self._rng = random.Random(seed)
        self._mutators: list[Mutator] = [
            HeaderCorruptMutator(seed=seed),
            MagicByteMutator(seed=seed),
            SizeFieldMutator(seed=seed),
            PolygotMutator(seed=seed),
            NestingBombMutator(seed=seed),
        ]

    @property
    def name(self) -> str:
        return "artifact_meta"

    def mutate(self, data: bytes, max_size: int = 65536) -> bytes:
        result = data
        for _ in range(self._rng.randint(1, 2)):
            m = self._rng.choice(self._mutators)
            result = m.mutate(result, max_size)
        return result


class HeaderCorruptMutator(Mutator):
    """Corrupt file header bytes."""

    def __init__(self, seed: Optional[int] = None):
        self._rng = random.Random(seed)

    @property
    def name(self) -> str:
        return "header_corrupt"

    def mutate(self, data: bytes, max_size: int = 65536) -> bytes:
        if len(data) < 8:
            return data
        ba = bytearray(data)
        for _ in range(self._rng.randint(1, 4)):
            pos = self._rng.randint(0, min(15, len(ba) - 1))
            ba[pos] = self._rng.randint(0, 255)
        return bytes(ba)[:max_size]


class MagicByteMutator(Mutator):
    """Swap magic bytes between different formats."""

    MAGICS = {
        "gguf": b"GGUF",
        "pickle": b"\x80\x05",
        "zip": b"PK\x03\x04",
        "onnx": b"\x08",
        "safetensors": b"\x00\x00\x00\x00",
    }

    def __init__(self, seed: Optional[int] = None):
        self._rng = random.Random(seed)

    @property
    def name(self) -> str:
        return "magic_byte"

    def mutate(self, data: bytes, max_size: int = 65536) -> bytes:
        magic = self._rng.choice(list(self.MAGICS.values()))
        return magic + data[len(magic):]


class SizeFieldMutator(Mutator):
    """Corrupt size/length fields to trigger overflows."""

    def __init__(self, seed: Optional[int] = None):
        self._rng = random.Random(seed)

    @property
    def name(self) -> str:
        return "size_field"

    def mutate(self, data: bytes, max_size: int = 65536) -> bytes:
        if len(data) < 16:
            return data
        ba = bytearray(data)
        # Find potential size fields (4 or 8 byte aligned) and corrupt
        pos = self._rng.choice([4, 8, 12]) if len(ba) >= 16 else 0
        evil_sizes = [
            0, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000, 1, 0xFFFF,
        ]
        val = self._rng.choice(evil_sizes)
        if pos + 4 <= len(ba):
            struct.pack_into("<I", ba, pos, val)
        return bytes(ba)[:max_size]


class PolygotMutator(Mutator):
    """Create polyglot files valid as multiple formats."""

    def __init__(self, seed: Optional[int] = None):
        self._rng = random.Random(seed)

    @property
    def name(self) -> str:
        return "polyglot"

    def mutate(self, data: bytes, max_size: int = 65536) -> bytes:
        # Prepend pickle payload before the original file
        pickle_payload = b"\x80\x05\x95\x00\x00\x00\x00\x00\x00\x00\x00"
        pickle_exec = b"\x8c\x02os\x8c\x06system\x93\x8c\x02id\x85R."
        return (pickle_payload + pickle_exec + data)[:max_size]


class NestingBombMutator(Mutator):
    """Inject deeply nested structures to cause stack overflow."""

    def __init__(self, seed: Optional[int] = None):
        self._rng = random.Random(seed)

    @property
    def name(self) -> str:
        return "nesting_bomb"

    def mutate(self, data: bytes, max_size: int = 65536) -> bytes:
        depth = self._rng.randint(100, 1000)
        # Generate nested JSON header
        nested = "null"
        for _ in range(depth):
            nested = '{"n":' + nested + '}'
        header = nested.encode("utf-8")

        if data[:4] in (b"GGUF", b"PK\x03\x04"):
            return data[:4] + header[:256] + data[260:]
        return header[:max_size]
