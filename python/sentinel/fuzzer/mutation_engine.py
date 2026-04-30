"""Binary mutation engine — comprehensive AFL/LibFuzzer-style mutations for security fuzzing.

Implements all standard AFL mutation stages:
  • Bit-flip (1, 2, 4 bits)
  • Byte-flip
  • Arithmetic add/sub on u8/u16/u32
  • Interesting value substitution (u8/u16/u32)
  • Block duplication / deletion / shuffle
  • Dictionary token insertion
  • Splice (cross-over with another corpus entry)
  • Havoc (random combination of all above)
  • Radamsa-inspired structural mutations
  • Overlong / multi-byte encoding tricks for Unicode parsers
  • Structured text mutations (JSON, pickle opcode injection)

All mutation functions are pure (no side-effects) and accept a seeded
`random.Random` instance for deterministic replay.
"""

from __future__ import annotations

import json
import random
import struct
from dataclasses import dataclass, field
from typing import Callable, Optional

# ---------------------------------------------------------------------------
# Interest tables (AFL standard)
# ---------------------------------------------------------------------------

_MAGIC_U8: list[int] = [0x00, 0x01, 0x02, 0x7E, 0x7F, 0x80, 0x81, 0xFE, 0xFF]

_MAGIC_U16: list[int] = [
    0x0000, 0x0001, 0x0002, 0x007F, 0x0080, 0x00FF,
    0x0100, 0x01FF, 0x7FFE, 0x7FFF, 0x8000, 0x8001,
    0xFFFE, 0xFFFF,
]

_MAGIC_U32: list[int] = [
    0x00000000, 0x00000001, 0x00000002,
    0x0000007F, 0x00000080, 0x000000FF,
    0x00000100, 0x00007FFF, 0x00008000,
    0x000FFFFF, 0x00100000, 0x7FFFFFFE,
    0x7FFFFFFF, 0x80000000, 0x80000001,
    0xFFFFFFFE, 0xFFFFFFFF,
]

_MAGIC_U64: list[int] = [
    0, 1, 0x7FFFFFFFFFFFFFFF, 0x8000000000000000,
    0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF,
]

# Dictionary of common attack strings injected during token-insertion mutations
_DEFAULT_DICTIONARY: list[bytes] = [
    b"__reduce__", b"__class__", b"__import__", b"__builtins__",
    b"os.system", b"subprocess", b"eval(", b"exec(",
    b"GLOBAL", b"STACK_GLOBAL", b"BUILD", b"REDUCE", b"INST",
    b"ignore previous instructions", b"system prompt",
    b"jailbreak", b"DAN mode", b"</s>", b"<|endoftext|>",
    b"\x00" * 8, b"\xff" * 8, b"\x80" * 4,
    b"../../../../etc/passwd", b"/dev/null",
    b"SELECT 1--", b"' OR '1'='1",
]


# ---------------------------------------------------------------------------
# Core bit / byte mutations
# ---------------------------------------------------------------------------

def bit_flip(data: bytes, rng: random.Random, n: int = 1) -> bytes:
    """Flip *n* consecutive bits starting at a random bit position.

    Args:
        data:  Input bytes (unchanged if empty).
        rng:   Seeded RNG for deterministic replay.
        n:     Number of consecutive bits to flip (1, 2, or 4 typical).

    Returns:
        Mutated bytes of the same length.
    """
    if not data:
        return data
    arr = bytearray(data)
    total_bits = len(arr) * 8
    pos = rng.randrange(total_bits)
    for i in range(n):
        bit_pos = pos + i
        if bit_pos < total_bits:
            byte_i = bit_pos // 8
            arr[byte_i] ^= 1 << (bit_pos % 8)
    return bytes(arr)


def byte_flip(data: bytes, rng: random.Random) -> bytes:
    """XOR a random byte with 0xFF."""
    if not data:
        return data
    arr = bytearray(data)
    arr[rng.randrange(len(arr))] ^= 0xFF
    return bytes(arr)


def byte_set(data: bytes, rng: random.Random, value: Optional[int] = None) -> bytes:
    """Set a random byte to *value* (or a random value if None)."""
    if not data:
        return data
    arr = bytearray(data)
    idx = rng.randrange(len(arr))
    arr[idx] = value if value is not None else rng.randint(0, 255)
    return bytes(arr)


# ---------------------------------------------------------------------------
# Arithmetic mutations
# ---------------------------------------------------------------------------

def arith_add(data: bytes, rng: random.Random, max_delta: int = 35) -> bytes:
    """Add a small random integer to a random u8/u16/u32 field (AFL arith stage)."""
    if len(data) < 1:
        return data
    arr = bytearray(data)
    delta = rng.randint(1, max_delta) * rng.choice([-1, 1])
    width = rng.choice([w for w in [1, 2, 4] if w <= len(arr)])
    pos = rng.randrange(len(arr) - width + 1)
    endian = ">" if rng.random() < 0.5 else "<"
    fmt = {1: "B", 2: "H", 4: "I"}[width]
    orig = struct.unpack_from(endian + fmt, arr, pos)[0]
    new_val = (orig + delta) % (256 ** width)
    struct.pack_into(endian + fmt, arr, pos, new_val)
    return bytes(arr)


# ---------------------------------------------------------------------------
# Interesting-value substitution
# ---------------------------------------------------------------------------

def insert_magic(data: bytes, rng: random.Random) -> bytes:
    """Insert a magic boundary-triggering value at a random position."""
    if not data:
        return data
    pos = rng.randrange(len(data))
    kind = rng.choice(["u8", "u16", "u32", "u64"])
    endian = ">" if rng.random() < 0.5 else "<"
    if kind == "u8":
        magic = bytes([rng.choice(_MAGIC_U8)])
    elif kind == "u16":
        magic = struct.pack(endian + "H", rng.choice(_MAGIC_U16))
    elif kind == "u32":
        magic = struct.pack(endian + "I", rng.choice(_MAGIC_U32))
    else:
        val = rng.choice(_MAGIC_U64)
        magic = struct.pack(endian + "Q", val)
    return data[:pos] + magic + data[pos:]


def overwrite_magic(data: bytes, rng: random.Random) -> bytes:
    """Overwrite bytes at a random position with a magic value (no length change)."""
    if len(data) < 4:
        return data
    arr = bytearray(data)
    width = rng.choice([w for w in [1, 2, 4] if w <= len(arr)])
    pos = rng.randrange(len(arr) - width + 1)
    endian = ">" if rng.random() < 0.5 else "<"
    fmt = {1: "B", 2: "H", 4: "I"}[width]
    table = {1: _MAGIC_U8, 2: _MAGIC_U16, 4: _MAGIC_U32}
    struct.pack_into(endian + fmt, arr, pos, rng.choice(table[width]))
    return bytes(arr)


# ---------------------------------------------------------------------------
# Block-level mutations
# ---------------------------------------------------------------------------

def block_delete(data: bytes, rng: random.Random) -> bytes:
    """Delete a random block of bytes (like AFL block deletion stage)."""
    if len(data) < 4:
        return data
    block_len = rng.randint(1, max(1, len(data) // 4))
    start = rng.randrange(len(data) - block_len + 1)
    return data[:start] + data[start + block_len:]


def block_duplicate(data: bytes, rng: random.Random) -> bytes:
    """Duplicate a block and insert it at another random position."""
    if len(data) < 2:
        return data
    block_len = rng.randint(1, max(1, len(data) // 3))
    src = rng.randrange(len(data) - block_len + 1)
    block = data[src:src + block_len]
    dst = rng.randrange(len(data))
    return data[:dst] + block + data[dst:]


def block_shuffle(data: bytes, rng: random.Random, n_blocks: int = 4) -> bytes:
    """Divide data into chunks and shuffle them (mimics Radamsa block swap)."""
    if len(data) < n_blocks * 2:
        return data
    chunk = max(1, len(data) // n_blocks)
    blocks = [data[i * chunk:(i + 1) * chunk] for i in range(n_blocks)]
    remaining = data[n_blocks * chunk:]
    rng.shuffle(blocks)
    return b"".join(blocks) + remaining


def block_repeat(data: bytes, rng: random.Random) -> bytes:
    """Repeat a random chunk 2-8 times (triggers buffer-overflow edge cases)."""
    if len(data) < 2:
        return data
    block_len = rng.randint(1, max(1, len(data) // 4))
    start = rng.randrange(len(data) - block_len + 1)
    chunk = data[start:start + block_len]
    times = rng.randint(2, 8)
    return data[:start] + chunk * times + data[start + block_len:]


# ---------------------------------------------------------------------------
# Dictionary / token mutations
# ---------------------------------------------------------------------------

def dict_insert(
    data: bytes,
    rng: random.Random,
    dictionary: Optional[list[bytes]] = None,
) -> bytes:
    """Insert a dictionary token at a random position."""
    if not data:
        return data
    tokens = dictionary or _DEFAULT_DICTIONARY
    token = rng.choice(tokens)
    pos = rng.randrange(len(data))
    return data[:pos] + token + data[pos:]


def dict_overwrite(
    data: bytes,
    rng: random.Random,
    dictionary: Optional[list[bytes]] = None,
) -> bytes:
    """Overwrite bytes at a random offset with a dictionary token."""
    if not data:
        return data
    tokens = dictionary or _DEFAULT_DICTIONARY
    token = rng.choice(tokens)
    pos = rng.randrange(len(data))
    return data[:pos] + token + data[pos + len(token):]


# ---------------------------------------------------------------------------
# Cross-corpus mutations
# ---------------------------------------------------------------------------

def splice(data_a: bytes, data_b: bytes, rng: random.Random) -> bytes:
    """AFL splice: graft the tail of *data_b* onto a prefix of *data_a*."""
    if not data_a or not data_b:
        return data_a or data_b
    cut_a = rng.randrange(len(data_a))
    cut_b = rng.randrange(len(data_b))
    return data_a[:cut_a] + data_b[cut_b:]


def crossover(data_a: bytes, data_b: bytes, rng: random.Random) -> bytes:
    """Two-point crossover — middle segment of *data_a* replaced by segment from *data_b*."""
    if len(data_a) < 4 or len(data_b) < 2:
        return splice(data_a, data_b, rng)
    lo = rng.randrange(len(data_a))
    hi = rng.randrange(lo, len(data_a))
    cut_b = rng.randrange(max(1, len(data_b)))
    insert_len = hi - lo
    segment = data_b[cut_b:cut_b + insert_len] if insert_len else b""
    return data_a[:lo] + segment + data_a[hi:]


# ---------------------------------------------------------------------------
# Structural / encoding mutations
# ---------------------------------------------------------------------------

def json_mutate(data: bytes, rng: random.Random) -> bytes:
    """If *data* is valid JSON, corrupt a random value; else fall through to byte_flip."""
    try:
        obj = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return byte_flip(data, rng)

    def _corrupt(node: object) -> object:
        if isinstance(node, dict):
            if node:
                k = rng.choice(list(node.keys()))
                node[k] = _corrupt(node[k])
            return node
        elif isinstance(node, list):
            if node:
                i = rng.randrange(len(node))
                node[i] = _corrupt(node[i])
            return node
        elif isinstance(node, str):
            ops = [
                lambda s: s + rng.choice(["'; DROP TABLE--", "<script>alert(1)</script>", "\x00", "{{7*7}}"]),
                lambda s: s[::-1],
                lambda s: s.replace("e", "\u0435"),  # homoglyph
            ]
            return rng.choice(ops)(node)
        elif isinstance(node, (int, float)):
            return rng.choice([0, -1, 2**31 - 1, 2**63 - 1, float("inf"), float("nan"), node * -1])
        elif isinstance(node, bool):
            return not node
        elif node is None:
            return rng.choice(["null_string", 0, False])
        return node

    corrupted = _corrupt(obj)
    try:
        return json.dumps(corrupted, ensure_ascii=False).encode()
    except (TypeError, ValueError):
        return byte_flip(data, rng)


def null_byte_inject(data: bytes, rng: random.Random) -> bytes:
    """Inject null bytes at random positions (triggers C-string truncation bugs)."""
    arr = bytearray(data)
    n_injections = rng.randint(1, max(1, len(data) // 16))
    for _ in range(n_injections):
        pos = rng.randrange(len(arr))
        arr.insert(pos, 0x00)
    return bytes(arr)


def overlong_utf8(data: bytes, rng: random.Random) -> bytes:
    """Replace a random ASCII byte with an overlong UTF-8 encoding of the same codepoint.

    E.g. 0x2F ('/') → 0xC0 0xAF (overlong 2-byte encoding).
    These are rejected by strict decoders but may slip through regex filters.
    """
    if not data:
        return data
    arr = bytearray(data)
    # Find positions of printable ASCII (0x20-0x7E)
    candidates = [i for i, b in enumerate(arr) if 0x20 <= b <= 0x7E]
    if not candidates:
        return data
    pos = rng.choice(candidates)
    cp = arr[pos]
    # 2-byte overlong: force byte into 2-byte sequence C0/C1 + 80-BF
    overlong = bytes([0xC0 | (cp >> 6), 0x80 | (cp & 0x3F)])
    return bytes(arr[:pos]) + overlong + bytes(arr[pos + 1:])


def truncate(data: bytes, rng: random.Random) -> bytes:
    """Truncate to a random prefix (stress-tests partial-read code paths)."""
    if len(data) <= 1:
        return data
    return data[:rng.randint(1, len(data) - 1)]


def prepend_bom(data: bytes) -> bytes:
    """Prepend a UTF-8 BOM — some parsers mishandle it at non-file boundaries."""
    return b"\xef\xbb\xbf" + data


def append_garbage(data: bytes, rng: random.Random, size: int = 16) -> bytes:
    """Append random bytes (stress-tests parsers that read beyond declared length)."""
    garbage = bytes(rng.randint(0, 255) for _ in range(size))
    return data + garbage


# ---------------------------------------------------------------------------
# Havoc — composite random mutation stage
# ---------------------------------------------------------------------------

#: All single-input mutation operators available in havoc
_HAVOC_OPS: list[Callable[[bytes, random.Random], bytes]] = [
    bit_flip,
    byte_flip,
    byte_set,
    arith_add,
    insert_magic,
    overwrite_magic,
    block_delete,
    block_duplicate,
    block_shuffle,
    block_repeat,
    dict_insert,
    dict_overwrite,
    null_byte_inject,
    truncate,
    append_garbage,
]


def havoc(
    data: bytes,
    rng: random.Random,
    rounds: int = 16,
    ops: Optional[list[Callable]] = None,
    min_len: int = 1,
) -> bytes:
    """Apply *rounds* randomly selected single-input mutations (AFL havoc stage).

    Args:
        data:    Input payload.
        rng:     Seeded RNG.
        rounds:  Number of mutations to apply.
        ops:     Override the operator list (defaults to all _HAVOC_OPS).
        min_len: Skip mutations that would reduce size below this threshold.

    Returns:
        Mutated bytes.
    """
    pool = ops if ops is not None else _HAVOC_OPS
    result = data
    for _ in range(rounds):
        op = rng.choice(pool)
        candidate = op(result, rng)
        if len(candidate) >= min_len:
            result = candidate
    return result


# ---------------------------------------------------------------------------
# Mutation statistics tracking
# ---------------------------------------------------------------------------

@dataclass
class MutationStats:
    """Accumulates coverage / effectiveness metrics across a havoc campaign."""
    total_mutations: int = 0
    unique_results: int = 0
    size_reductions: int = 0
    size_expansions: int = 0
    op_counts: dict[str, int] = field(default_factory=dict)

    def record(self, op_name: str, before: bytes, after: bytes) -> None:
        self.total_mutations += 1
        self.op_counts[op_name] = self.op_counts.get(op_name, 0) + 1
        if len(after) < len(before):
            self.size_reductions += 1
        elif len(after) > len(before):
            self.size_expansions += 1

    def summary(self) -> dict:
        return {
            "total_mutations": self.total_mutations,
            "unique_results": self.unique_results,
            "size_reductions": self.size_reductions,
            "size_expansions": self.size_expansions,
            "top_ops": sorted(self.op_counts.items(), key=lambda x: x[1], reverse=True)[:10],
        }


class MutationEngine:
    """Stateful wrapper around the functional mutation primitives.

    Tracks per-run statistics, supports pluggable dictionaries, and provides
    a high-level ``generate(data, n)`` method for generating N mutants.

    Example::

        engine = MutationEngine(seed=42, rounds=20)
        mutants = engine.generate(b"original payload", n=100)
        print(engine.stats.summary())
    """

    def __init__(
        self,
        seed: Optional[int] = None,
        rounds: int = 16,
        dictionary: Optional[list[bytes]] = None,
        ops: Optional[list[Callable]] = None,
    ):
        self._rng = random.Random(seed)
        self._rounds = rounds
        self._dictionary = dictionary or _DEFAULT_DICTIONARY
        self._ops = ops or _HAVOC_OPS
        self.stats = MutationStats()

    def generate(self, data: bytes, n: int = 10) -> list[bytes]:
        """Return *n* distinct mutations of *data*."""
        results: list[bytes] = []
        seen: set[bytes] = {data}
        attempts = 0
        max_attempts = n * 50

        while len(results) < n and attempts < max_attempts:
            attempts += 1
            mutant = havoc(data, self._rng, rounds=self._rounds, ops=self._ops)
            self.stats.record("havoc", data, mutant)
            if mutant not in seen:
                seen.add(mutant)
                results.append(mutant)
                self.stats.unique_results += 1
        return results

    def generate_single(self, data: bytes, op_name: Optional[str] = None) -> bytes:
        """Apply a single named operator or a random one."""
        op_map = {fn.__name__: fn for fn in _HAVOC_OPS}
        if op_name and op_name in op_map:
            fn = op_map[op_name]
        else:
            fn = self._rng.choice(self._ops)
        result = fn(data, self._rng)
        self.stats.record(fn.__name__, data, result)
        return result

    def seed(self, new_seed: int) -> None:
        """Re-seed the RNG for deterministic replay."""
        self._rng = random.Random(new_seed)

