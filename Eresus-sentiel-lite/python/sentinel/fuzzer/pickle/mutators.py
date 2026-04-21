"""Mutation strategies for pickle byte streams."""

from __future__ import annotations

import random
import struct
from typing import Optional

from ..base import Mutator
from .opcodes import OPCODE_REGISTRY, SAFE_PUSH_OPCODES, ArgType, opcode_by_byte


class PickleMutator(Mutator):
    """Meta-mutator that applies random mutators from the full registry."""

    def __init__(self, protocol: int = 4, seed: Optional[int] = None):
        self._rng = random.Random(seed)
        self._protocol = protocol
        self._mutators: list[Mutator] = [
            BitflipMutator(seed=seed),
            BoundaryMutator(seed=seed),
            OffByOneMutator(seed=seed),
            StringLenMutator(seed=seed),
            CharacterMutator(seed=seed),
            MemoIndexMutator(seed=seed),
            TypeConfusionMutator(seed=seed),
            OpcodeInsertMutator(protocol=protocol, seed=seed),
            OpcodeDeleteMutator(seed=seed),
            OpcodeSwapMutator(seed=seed),
            PayloadInjectMutator(seed=seed),
            ProtocolMutator(seed=seed),
            FrameCorruptionMutator(seed=seed),
            HavocMutator(seed=seed),
            GlobalRewriteMutator(seed=seed),
            CrossReferenceMutator(seed=seed),
            DeepNestingMutator(seed=seed),
        ]

    @property
    def name(self) -> str:
        return "pickle_meta"

    def mutate(self, data: bytes, max_size: int = 65536) -> bytes:
        """Apply 1-3 random mutators in sequence."""
        result = data
        n = self._rng.randint(1, 3)
        for _ in range(n):
            m = self._rng.choice(self._mutators)
            result = m.mutate(result, max_size)
            if len(result) > max_size:
                result = result[:max_size]
        return result


# ── Structural Mutators ──────────────────────────────────────────────

class BitflipMutator(Mutator):
    """Flip random bits in the byte stream."""

    def __init__(self, seed: Optional[int] = None, rate: float = 0.01):
        self._rng = random.Random(seed)
        self._rate = rate

    @property
    def name(self) -> str:
        return "bitflip"

    def mutate(self, data: bytes, max_size: int = 65536) -> bytes:
        if not data:
            return data
        ba = bytearray(data)
        n_flips = max(1, int(len(ba) * self._rate))
        for _ in range(n_flips):
            pos = self._rng.randint(0, len(ba) - 1)
            bit = 1 << self._rng.randint(0, 7)
            ba[pos] ^= bit
        return bytes(ba)


class OpcodeInsertMutator(Mutator):
    """Insert random opcodes at random positions.

    Can insert both safe (push) and dangerous (GLOBAL+REDUCE)
    opcode sequences to test scanner resilience.
    """

    def __init__(self, protocol: int = 4, seed: Optional[int] = None):
        self._rng = random.Random(seed)
        self._protocol = protocol

    @property
    def name(self) -> str:
        return "opcode_insert"

    def mutate(self, data: bytes, max_size: int = 65536) -> bytes:
        if len(data) < 3 or len(data) >= max_size - 20:
            return data
        ba = bytearray(data)

        n_inserts = self._rng.randint(1, 3)
        for _ in range(n_inserts):
            pos = self._rng.randint(2, len(ba) - 1)

            # Choose insertion type
            choice = self._rng.random()
            if choice < 0.4:
                # Safe push opcodes
                insert_bytes = bytearray([self._rng.choice([
                    0x4E,       # NONE
                    0x88,       # NEWTRUE
                    0x89,       # NEWFALSE
                    0x29,       # EMPTY_TUPLE
                ])])
            elif choice < 0.6:
                # BININT1 with value
                insert_bytes = bytearray([0x4B, self._rng.randint(0, 255)])
            elif choice < 0.75:
                # DUP (0x32) — stack manipulation
                insert_bytes = bytearray([0x32])
            elif choice < 0.85:
                # MARK + POP_MARK (NOP pair)
                insert_bytes = bytearray([0x28, 0x31])
            else:
                # SHORT_BINUNICODE with small string
                s = bytes([self._rng.randint(0x41, 0x5A) for _ in range(3)])
                insert_bytes = bytearray([0x8C, len(s)]) + bytearray(s)

            ba[pos:pos] = insert_bytes
            if len(ba) > max_size:
                break

        return bytes(ba)


class OpcodeDeleteMutator(Mutator):
    """Remove random opcodes from the stream.

    Tries to be opcode-aware — identifies opcode boundaries and
    removes full opcodes rather than just random bytes.
    """

    def __init__(self, seed: Optional[int] = None):
        self._rng = random.Random(seed)

    @property
    def name(self) -> str:
        return "opcode_delete"

    def mutate(self, data: bytes, max_size: int = 65536) -> bytes:
        if len(data) < 5:
            return data
        ba = bytearray(data)

        n_deletes = self._rng.randint(1, min(3, len(ba) // 8))
        for _ in range(n_deletes):
            if len(ba) < 4:
                break
            pos = self._rng.randint(2, len(ba) - 2)
            del ba[pos]

        return bytes(ba)


class OpcodeSwapMutator(Mutator):
    """Swap two adjacent opcodes to create invalid ordering.

    This tests scanner resilience to shuffled opcode sequences
    that break PVM stack invariants.
    """

    def __init__(self, seed: Optional[int] = None):
        self._rng = random.Random(seed)

    @property
    def name(self) -> str:
        return "opcode_swap"

    def mutate(self, data: bytes, max_size: int = 65536) -> bytes:
        if len(data) < 6:
            return data
        ba = bytearray(data)

        n_swaps = self._rng.randint(1, 3)
        for _ in range(n_swaps):
            pos = self._rng.randint(2, len(ba) - 3)
            ba[pos], ba[pos + 1] = ba[pos + 1], ba[pos]

        return bytes(ba)


# ── Boundary Mutators ────────────────────────────────────────────────

class BoundaryMutator(Mutator):
    """Replace numeric arguments with boundary values."""

    BOUNDARIES_U8 = [0, 1, 127, 128, 254, 255]
    BOUNDARIES_U16 = [0, 1, 255, 256, 32767, 32768, 65534, 65535]
    BOUNDARIES_I32 = [0, 1, -1, 127, 128, 255, 256, 32767, -32768, 2147483647, -2147483648]
    BOUNDARIES_U64 = [0, 1, 255, 65535, 2**32 - 1, 2**63 - 1]

    def __init__(self, seed: Optional[int] = None):
        self._rng = random.Random(seed)

    @property
    def name(self) -> str:
        return "boundary"

    def mutate(self, data: bytes, max_size: int = 65536) -> bytes:
        if len(data) < 3:
            return data
        ba = bytearray(data)

        i = 0
        while i < len(ba) - 1:
            op = opcode_by_byte(ba[i])
            if op:
                if op.arg_type == ArgType.UINT1 and i + 1 < len(ba):
                    if self._rng.random() < 0.3:
                        ba[i + 1] = self._rng.choice(self.BOUNDARIES_U8)
                elif op.arg_type == ArgType.UINT2 and i + 2 < len(ba):
                    if self._rng.random() < 0.3:
                        val = self._rng.choice(self.BOUNDARIES_U16)
                        struct.pack_into("<H", ba, i + 1, val)
                elif op.arg_type == ArgType.INT4 and i + 4 < len(ba):
                    if self._rng.random() < 0.3:
                        val = self._rng.choice(self.BOUNDARIES_I32)
                        struct.pack_into("<i", ba, i + 1, val)
                elif op.arg_type == ArgType.UINT8 and i + 8 < len(ba):
                    if self._rng.random() < 0.2:
                        val = self._rng.choice(self.BOUNDARIES_U64)
                        struct.pack_into("<Q", ba, i + 1, val)
                elif op.arg_type == ArgType.FLOAT8 and i + 8 < len(ba):
                    if self._rng.random() < 0.2:
                        special = self._rng.choice([
                            float('inf'), float('-inf'), float('nan'),
                            0.0, -0.0, 1e308, -1e308, 5e-324,
                        ])
                        struct.pack_into(">d", ba, i + 1, special)
            i += 1

        return bytes(ba)


class OffByOneMutator(Mutator):
    """±1 on length and index arguments.

    Targets length-prefixed fields to trigger buffer over/underreads.
    """

    def __init__(self, seed: Optional[int] = None):
        self._rng = random.Random(seed)

    @property
    def name(self) -> str:
        return "offbyone"

    def mutate(self, data: bytes, max_size: int = 65536) -> bytes:
        if len(data) < 3:
            return data
        ba = bytearray(data)

        i = 0
        while i < len(ba) - 1:
            op = opcode_by_byte(ba[i])
            if op:
                if op.arg_type in (ArgType.STRING1, ArgType.BYTES1):
                    if i + 1 < len(ba) and self._rng.random() < 0.3:
                        delta = self._rng.choice([-1, 1])
                        new_val = max(0, min(255, ba[i + 1] + delta))
                        ba[i + 1] = new_val
                elif op.arg_type in (ArgType.STRING4, ArgType.BYTES4):
                    if i + 4 < len(ba) and self._rng.random() < 0.3:
                        old = struct.unpack_from("<I", ba, i + 1)[0]
                        delta = self._rng.choice([-1, 1])
                        new_val = max(0, old + delta)
                        struct.pack_into("<I", ba, i + 1, new_val)
                elif op.arg_type == ArgType.BYTES8:
                    if i + 8 < len(ba) and self._rng.random() < 0.2:
                        old = struct.unpack_from("<Q", ba, i + 1)[0]
                        delta = self._rng.choice([-1, 1])
                        new_val = max(0, old + delta)
                        struct.pack_into("<Q", ba, i + 1, new_val)
            i += 1

        return bytes(ba)


# ── String Mutators ──────────────────────────────────────────────────

class StringLenMutator(Mutator):
    """Corrupt string length headers to trigger buffer overreads."""

    def __init__(self, seed: Optional[int] = None):
        self._rng = random.Random(seed)

    @property
    def name(self) -> str:
        return "stringlen"

    def mutate(self, data: bytes, max_size: int = 65536) -> bytes:
        if len(data) < 3:
            return data
        ba = bytearray(data)

        for i in range(len(ba) - 2):
            if ba[i] in (0x8C, 0x55, 0x43):  # SHORT_BINUNICODE, SHORT_BINSTRING, SHORT_BINBYTES
                if self._rng.random() < 0.4:
                    ba[i + 1] = self._rng.choice([0, 255, ba[i + 1] * 2 % 256])
            elif ba[i] in (0x58, 0x54, 0x42):  # BINUNICODE, BINSTRING, BINBYTES
                if i + 5 <= len(ba) and self._rng.random() < 0.3:
                    corrupt_len = self._rng.choice([0, 0xFFFFFFFF, len(ba) * 10])
                    struct.pack_into("<I", ba, i + 1, corrupt_len & 0xFFFFFFFF)

        return bytes(ba)


class CharacterMutator(Mutator):
    """Replace string characters with special/unicode values.

    Targets pickle text protocol delimiters and encoding boundaries.
    """

    SPECIALS = [
        b"\x00",        # null byte
        b"\xff",        # 0xFF
        b"\n",          # newline (pickle delimiter!)
        b"\r\n",        # CRLF
        b"\\",          # backslash
        b"'",           # single quote (STRING delimiter)
        b'"',           # double quote
        b"\x80",        # protocol marker
        b"\x2e",        # STOP opcode
        b"\x95",        # FRAME opcode
        b"\x28",        # MARK opcode
        b"\x93",        # STACK_GLOBAL opcode
        b"\xc0\x80",    # overlong UTF-8 NUL
        b"\xed\xa0\x80", # UTF-8 surrogate half
    ]

    def __init__(self, seed: Optional[int] = None):
        self._rng = random.Random(seed)

    @property
    def name(self) -> str:
        return "character"

    def mutate(self, data: bytes, max_size: int = 65536) -> bytes:
        if len(data) < 5:
            return data
        ba = bytearray(data)

        n_replacements = self._rng.randint(1, min(5, len(ba) // 10 + 1))
        for _ in range(n_replacements):
            pos = self._rng.randint(2, len(ba) - 2)
            special = self._rng.choice(self.SPECIALS)
            end = min(pos + len(special), len(ba))
            ba[pos:end] = special[:end - pos]

        return bytes(ba)


# ── Semantic Mutators ────────────────────────────────────────────────

class MemoIndexMutator(Mutator):
    """Corrupt memo GET/PUT indices to trigger key errors."""

    def __init__(self, seed: Optional[int] = None):
        self._rng = random.Random(seed)

    @property
    def name(self) -> str:
        return "memoindex"

    def mutate(self, data: bytes, max_size: int = 65536) -> bytes:
        if len(data) < 3:
            return data
        ba = bytearray(data)

        for i in range(len(ba) - 1):
            # BINGET (0x68) or BINPUT (0x71) — 1-byte index
            if ba[i] in (0x68, 0x71) and self._rng.random() < 0.4:
                ba[i + 1] = self._rng.randint(200, 255)

            # LONG_BINGET (0x6A) or LONG_BINPUT (0x72) — 4-byte index
            elif ba[i] in (0x6A, 0x72) and i + 4 < len(ba):
                if self._rng.random() < 0.3:
                    struct.pack_into("<I", ba, i + 1, self._rng.randint(10000, 0xFFFFFF))

        return bytes(ba)


class TypeConfusionMutator(Mutator):
    """Swap opcodes between incompatible types to test type checking."""

    # Swap groups: opcodes within each group are substitutable
    SWAP_GROUPS = [
        [0x4E, 0x88, 0x89],          # NONE ↔ NEWTRUE ↔ NEWFALSE
        [0x4A, 0x4B, 0x4D],          # BININT ↔ BININT1 ↔ BININT2
        [0x55, 0x54],                 # SHORT_BINSTRING ↔ BINSTRING
        [0x8C, 0x58],                 # SHORT_BINUNICODE ↔ BINUNICODE
        [0x43, 0x42],                 # SHORT_BINBYTES ↔ BINBYTES
        [0x29, 0x85, 0x86, 0x87],     # EMPTY_TUPLE ↔ TUPLE1/2/3
        [0x5D, 0x7D],                 # EMPTY_LIST ↔ EMPTY_DICT
        [0x52, 0x81],                 # REDUCE ↔ NEWOBJ
        [0x63, 0x93],                 # GLOBAL ↔ STACK_GLOBAL (dangerous!)
        [0x73, 0x62],                 # SETITEM ↔ BUILD
        [0x61, 0x73],                 # APPEND ↔ SETITEM
        [0x47, 0x46],                 # BINFLOAT ↔ FLOAT
    ]

    def __init__(self, seed: Optional[int] = None):
        self._rng = random.Random(seed)
        self._swap_map: dict[int, list[int]] = {}
        for group in self.SWAP_GROUPS:
            for b in group:
                self._swap_map[b] = [x for x in group if x != b]

    @property
    def name(self) -> str:
        return "typeconfusion"

    def mutate(self, data: bytes, max_size: int = 65536) -> bytes:
        if len(data) < 3:
            return data
        ba = bytearray(data)

        for i in range(1, len(ba) - 1):
            if ba[i] in self._swap_map and self._rng.random() < 0.15:
                ba[i] = self._rng.choice(self._swap_map[ba[i]])

        return bytes(ba)


# ── Adversarial Mutators ─────────────────────────────────────────────

class PayloadInjectMutator(Mutator):
    """Inject known-malicious GLOBAL+REDUCE sequences into the stream.

    This is the adversarial mutator — it transforms a benign pickle
    into a weaponized one by splicing in dangerous import chains.
    """

    # Pre-built malicious sequences (protocol 0 text format for maximum compat)
    INJECTIONS = [
        # os.system("id")
        b"cos\nsystem\n(S'id'\ntR",
        # builtins.eval("1+1")
        b"cbuiltins\neval\n(S'1+1'\ntR",
        # subprocess.check_output(["id"])
        b"csubprocess\ncheck_output\n(](S'id'\natR",
        # __import__("os").system("id")
        b"cbuiltins\n__import__\n(S'os'\ntRp0\ncbuiltins\ngetattr\n(g0\nS'system'\ntR(S'id'\ntR",
        # marshal.loads (code object injection prep)
        b"cmarshal\nloads\n(S'payload'\ntR",
        # copyreg abuse
        b"ccopyreg\nadd_extension\n(S'os'\nS'system'\nI42\ntR",
        # ctypes.CDLL (FFI native code loading)
        b"cctypes\nCDLL\n(S'libc.so.6'\ntR",
        # runpy.run_module (arbitrary module exec)
        b"crunpy\nrun_module\n(S'http.server'\ntR",
        # socket (network access)
        b"csocket\nsocket\n(I2\nI1\ntR",
        # shutil.rmtree (filesystem destruction)
        b"cshutil\nrmtree\n(S'/tmp/target'\ntR",
        # STACK_GLOBAL variant (protocol 4+)
        b"\x8c\x02os\x8c\x06system\x93\x8c\x02id\x85\x52",
        # Double indirection: getattr(builtins, 'eval')
        b"cbuiltins\ngetattr\n(cbuiltins\n__builtins__\nS'eval'\ntR(S'1+1'\ntR",
    ]

    def __init__(self, seed: Optional[int] = None):
        self._rng = random.Random(seed)

    @property
    def name(self) -> str:
        return "payload_inject"

    def mutate(self, data: bytes, max_size: int = 65536) -> bytes:
        if len(data) < 3:
            return data

        injection = self._rng.choice(self.INJECTIONS)

        # Insert before STOP (last byte should be 0x2E)
        if data[-1] == 0x2E:
            return data[:-1] + injection + b"\x30" + b"\x2e"
        else:
            return data + injection

    def inject_specific(self, data: bytes, payload_index: int) -> bytes:
        """Inject a specific payload by index."""
        if payload_index >= len(self.INJECTIONS):
            return data
        injection = self.INJECTIONS[payload_index]
        if data[-1] == 0x2E:
            return data[:-1] + injection + b"\x30" + b"\x2e"
        return data + injection


class GlobalRewriteMutator(Mutator):
    """Rewrite GLOBAL opcodes to point to dangerous modules.

    Scans for existing GLOBAL opcodes (0x63) and replaces their
    module\nname\n arguments with dangerous alternatives.
    """

    DANGEROUS_GLOBALS = [
        b"os\nsystem\n",
        b"os\npopen\n",
        b"subprocess\nPopen\n",
        b"builtins\neval\n",
        b"builtins\nexec\n",
        b"builtins\n__import__\n",
        b"builtins\nopen\n",
        b"pickle\nloads\n",
        b"marshal\nloads\n",
        b"ctypes\nCDLL\n",
        b"shutil\nrmtree\n",
        b"socket\nsocket\n",
        b"runpy\nrun_module\n",
        b"importlib\nimport_module\n",
        b"types\nFunctionType\n",
    ]

    def __init__(self, seed: Optional[int] = None):
        self._rng = random.Random(seed)

    @property
    def name(self) -> str:
        return "global_rewrite"

    def mutate(self, data: bytes, max_size: int = 65536) -> bytes:
        if len(data) < 5:
            return data

        ba = bytearray(data)
        result = bytearray()
        i = 0

        while i < len(ba):
            if ba[i] == 0x63 and self._rng.random() < 0.3:
                result.append(0x63)
                i += 1
                # Skip original module\nname\n
                newline_count = 0
                while i < len(ba) and newline_count < 2:
                    if ba[i] == 0x0A:
                        newline_count += 1
                    i += 1
                # Inject dangerous global
                dangerous = self._rng.choice(self.DANGEROUS_GLOBALS)
                result.extend(dangerous)
            else:
                result.append(ba[i])
                i += 1

        if len(result) > max_size:
            return data
        return bytes(result)


# ── Protocol Mutators ────────────────────────────────────────────────

class ProtocolMutator(Mutator):
    """Corrupt or change the PROTO opcode version.

    Tests scanner handling of protocol mismatches where the declared
    protocol doesn't match the opcodes used.
    """

    def __init__(self, seed: Optional[int] = None):
        self._rng = random.Random(seed)

    @property
    def name(self) -> str:
        return "protocol"

    def mutate(self, data: bytes, max_size: int = 65536) -> bytes:
        if len(data) < 3:
            return data
        ba = bytearray(data)

        # Find PROTO opcode (0x80 at position 0 or 1)
        if ba[0] == 0x80 and len(ba) > 1:
            choice = self._rng.random()
            if choice < 0.3:
                ba[1] = 0  # Downgrade to protocol 0
            elif choice < 0.5:
                ba[1] = 5  # Upgrade to max protocol
            elif choice < 0.7:
                ba[1] = 255  # Invalid protocol number
            else:
                # Remove PROTO entirely
                ba = ba[2:]

        return bytes(ba)


class FrameCorruptionMutator(Mutator):
    """Corrupt FRAME headers to test frame parsing resilience.

    Targets FRAME opcode (0x95) and corrupts the 8-byte frame length
    with boundary values to trigger buffer misreads.
    """

    def __init__(self, seed: Optional[int] = None):
        self._rng = random.Random(seed)

    @property
    def name(self) -> str:
        return "frame_corruption"

    def mutate(self, data: bytes, max_size: int = 65536) -> bytes:
        if len(data) < 10:
            return data
        ba = bytearray(data)

        for i in range(len(ba) - 8):
            if ba[i] == 0x95:  # FRAME opcode
                if self._rng.random() < 0.5:
                    corrupt = self._rng.choice([
                        0,
                        0xFFFFFFFFFFFFFFFF,
                        len(ba) * 2,
                        1,
                        0x7FFFFFFFFFFFFFFF,
                    ])
                    struct.pack_into("<Q", ba, i + 1, corrupt)
                break

        return bytes(ba)


# ── Advanced Mutators ────────────────────────────────────────────────

class HavocMutator(Mutator):
    """Extreme havoc mode — random byte corruption at high rate.

    A 'nuclear option' mutator for maximum chaos. 5-20% of bytes
    are randomly corrupted. Tests scanner crash resilience.
    """

    def __init__(self, seed: Optional[int] = None, rate: float = 0.1):
        self._rng = random.Random(seed)
        self._rate = rate

    @property
    def name(self) -> str:
        return "havoc"

    def mutate(self, data: bytes, max_size: int = 65536) -> bytes:
        if len(data) < 3:
            return data
        ba = bytearray(data)

        n_corruptions = max(1, int(len(ba) * self._rate))
        for _ in range(n_corruptions):
            pos = self._rng.randint(0, len(ba) - 1)
            op = self._rng.random()
            if op < 0.4:
                ba[pos] = self._rng.randint(0, 255)
            elif op < 0.6:
                ba[pos] ^= self._rng.choice([0x80, 0xFF, 0x01, 0x7F])
            elif op < 0.8:
                ba[pos] = 0x00
            else:
                ba[pos] = 0xFF

        return bytes(ba)


class CrossReferenceMutator(Mutator):
    """Insert circular memo references to test reference counting.

    Creates PUT followed by GET of the same index in patterns
    that could cause infinite loop or excessive memory in parsers.
    """

    def __init__(self, seed: Optional[int] = None):
        self._rng = random.Random(seed)

    @property
    def name(self) -> str:
        return "cross_reference"

    def mutate(self, data: bytes, max_size: int = 65536) -> bytes:
        if len(data) < 5 or len(data) >= max_size - 20:
            return data
        ba = bytearray(data)

        # Find a position after PROTO, before STOP
        pos = self._rng.randint(2, max(2, len(ba) - 2))

        # Insert PUT(0) ... GET(0) ... PUT(0) ... GET(0) (circular)
        circular = bytearray()
        slot = self._rng.randint(0, 10)
        for _ in range(self._rng.randint(2, 5)):
            if self._rng.random() < 0.5:
                circular.extend([0x71, slot])   # BINPUT
            else:
                circular.extend([0x68, slot])   # BINGET

        ba[pos:pos] = circular

        if len(ba) > max_size:
            return data
        return bytes(ba)


class DeepNestingMutator(Mutator):
    """Create deeply nested structures to test recursion limits.

    Generates chains of EMPTY_LIST + APPEND or EMPTY_DICT + SETITEM
    to create deep nesting that might hit recursion limits.
    """

    def __init__(self, seed: Optional[int] = None, max_depth: int = 50):
        self._rng = random.Random(seed)
        self._max_depth = max_depth

    @property
    def name(self) -> str:
        return "deep_nesting"

    def mutate(self, data: bytes, max_size: int = 65536) -> bytes:
        if len(data) < 3 or len(data) >= max_size - 200:
            return data

        depth = self._rng.randint(10, self._max_depth)
        nested = bytearray()

        # Stack: innermost → outermost
        for _ in range(depth):
            nested.extend([0x5D])               # EMPTY_LIST
        for _ in range(depth - 1):
            nested.extend([0x61])               # APPEND (inner into outer)

        # Insert before STOP
        ba = bytearray(data)
        if ba[-1] == 0x2E:
            # Pop our entire structure and the original TOS
            ba = ba[:-1] + nested + bytearray([0x30, 0x2E])
        else:
            ba = ba + nested

        if len(ba) > max_size:
            return data
        return bytes(ba)
