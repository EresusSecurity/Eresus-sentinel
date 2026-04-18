"""Complete pickle opcode definitions for all protocol versions (0-5)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


class ArgType:
    """Argument format types for pickle opcodes."""
    NONE = "none"               # No argument
    UINT1 = "uint1"             # 1-byte unsigned int
    UINT2 = "uint2"             # 2-byte unsigned int (LE)
    INT4 = "int4"               # 4-byte signed int (LE)
    UINT4 = "uint4"             # 4-byte unsigned int (LE)
    UINT8 = "uint8"             # 8-byte unsigned int (LE)
    FLOAT8 = "float8"           # 8-byte IEEE 754 double (BE)
    STRING1 = "string1"         # 1-byte length + data
    STRING4 = "string4"         # 4-byte length + data
    BYTES1 = "bytes1"           # 1-byte length + bytes
    BYTES4 = "bytes4"           # 4-byte length + bytes
    BYTES8 = "bytes8"           # 8-byte length + bytes
    DECIMALNL_SHORT = "decimalnl_short"  # Text integer terminated by \n
    DECIMALNL_LONG = "decimalnl_long"    # Text long terminated by \n
    FLOATNL = "floatnl"         # Text float terminated by \n
    STRINGNL = "stringnl"       # Quoted string terminated by \n
    STRINGNL_PAIR = "stringnl_pair"     # Two strings separated by \n
    UNICODESTRINGNL = "unicodestringnl"  # Unicode string + \n


@dataclass(frozen=True)
class OpcodeInfo:
    """Definition of a single pickle opcode."""
    byte: int
    name: str
    proto_min: int              # First protocol that supports this
    proto_max: int              # Last protocol that supports this (5 = all current)
    arg_type: str               # ArgType constant
    stack_before: int           # Items consumed from stack (0 = none)
    stack_after: int            # Items pushed to stack (0 = none)
    description: str = ""

    @property
    def char(self) -> bytes:
        return bytes([self.byte])

    def available_in(self, protocol: int) -> bool:
        return self.proto_min <= protocol <= self.proto_max


# ── Complete Opcode Registry ─────────────────────────────────────────


OPCODE_REGISTRY: dict[str, OpcodeInfo] = {}


def _r(byte: int, name: str, pmin: int, pmax: int,
       arg: str, sb: int, sa: int, desc: str = "") -> None:
    OPCODE_REGISTRY[name] = OpcodeInfo(byte, name, pmin, pmax, arg, sb, sa, desc)


# ── Protocol 0 (text protocol) ──────────────────────────────────────
_r(0x28, "MARK",             0, 5, ArgType.NONE,        0, 1, "Push mark onto stack")
_r(0x2E, "STOP",             0, 5, ArgType.NONE,        1, 0, "Stop unpickling")
_r(0x30, "POP",              0, 5, ArgType.NONE,        1, 0, "Pop top of stack")
_r(0x31, "POP_MARK",         1, 5, ArgType.NONE,        0, 0, "Pop to mark")
_r(0x32, "DUP",              0, 5, ArgType.NONE,        1, 2, "Duplicate top of stack")
_r(0x46, "FLOAT",            0, 5, ArgType.FLOATNL,     0, 1, "Push float from text")
_r(0x47, "BINFLOAT",         1, 5, ArgType.FLOAT8,      0, 1, "Push 8-byte big-endian float")
_r(0x49, "INT",              0, 5, ArgType.DECIMALNL_SHORT, 0, 1, "Push int from text")
_r(0x4A, "BININT",           1, 5, ArgType.INT4,        0, 1, "Push 4-byte signed int")
_r(0x4B, "BININT1",          1, 5, ArgType.UINT1,       0, 1, "Push 1-byte unsigned int")
_r(0x4C, "LONG",             0, 5, ArgType.DECIMALNL_LONG, 0, 1, "Push long from text")
_r(0x4D, "BININT2",          1, 5, ArgType.UINT2,       0, 1, "Push 2-byte unsigned int")
_r(0x4E, "NONE",             0, 5, ArgType.NONE,        0, 1, "Push None")
_r(0x50, "PERSID",           0, 5, ArgType.STRINGNL,    0, 1, "Push persistent object by text id")
_r(0x51, "BINPERSID",        1, 5, ArgType.NONE,        1, 1, "Push persistent object by stack id")
_r(0x52, "REDUCE",           0, 5, ArgType.NONE,        2, 1, "Call callable with args")
_r(0x53, "STRING",           0, 5, ArgType.STRINGNL,    0, 1, "Push string literal")
_r(0x54, "BINSTRING",        1, 5, ArgType.STRING4,     0, 1, "Push binary string")
_r(0x55, "SHORT_BINSTRING",  1, 5, ArgType.STRING1,     0, 1, "Push short binary string")
_r(0x56, "UNICODE",          0, 5, ArgType.UNICODESTRINGNL, 0, 1, "Push unicode from text")
_r(0x58, "BINUNICODE",       1, 5, ArgType.STRING4,     0, 1, "Push binary unicode")
_r(0x5D, "EMPTY_LIST",       1, 5, ArgType.NONE,        0, 1, "Push empty list")
_r(0x61, "APPEND",           0, 5, ArgType.NONE,        2, 1, "Append to list")
_r(0x62, "BUILD",            0, 5, ArgType.NONE,        2, 1, "Set instance __dict__/state")
_r(0x63, "GLOBAL",           0, 5, ArgType.STRINGNL_PAIR, 0, 1, "Push global: module.name")
_r(0x64, "DICT",             0, 5, ArgType.NONE,        0, 1, "Build dict from mark")
_r(0x65, "APPENDS",          1, 5, ArgType.NONE,        0, 0, "Bulk append from mark to list")
_r(0x67, "GET",              0, 5, ArgType.DECIMALNL_SHORT, 0, 1, "Read memo by text index")
_r(0x68, "BINGET",           1, 5, ArgType.UINT1,       0, 1, "Read memo by 1-byte index")
_r(0x69, "INST",             0, 5, ArgType.STRINGNL_PAIR, 0, 1, "Push instance from mark")
_r(0x6A, "LONG_BINGET",      1, 5, ArgType.UINT4,       0, 1, "Read memo by 4-byte index")
_r(0x6C, "LIST",             0, 5, ArgType.NONE,        0, 1, "Build list from mark")
_r(0x6F, "OBJ",              1, 5, ArgType.NONE,        0, 1, "Build object from mark")
_r(0x70, "PUT",              0, 5, ArgType.DECIMALNL_SHORT, 0, 0, "Store top in memo (text)")
_r(0x71, "BINPUT",           1, 5, ArgType.UINT1,       0, 0, "Store top in memo (1-byte)")
_r(0x72, "LONG_BINPUT",      1, 5, ArgType.UINT4,       0, 0, "Store top in memo (4-byte)")
_r(0x73, "SETITEM",          0, 5, ArgType.NONE,        3, 1, "Set dict[key]=value")
_r(0x74, "TUPLE",            0, 5, ArgType.NONE,        0, 1, "Build tuple from mark")
_r(0x75, "SETITEMS",         1, 5, ArgType.NONE,        0, 0, "Bulk set dict items")
_r(0x7D, "EMPTY_DICT",       1, 5, ArgType.NONE,        0, 1, "Push empty dict")

# ── Protocol 1 additions ────────────────────────────────────────────
_r(0x29, "EMPTY_TUPLE",      1, 5, ArgType.NONE,        0, 1, "Push empty tuple")

# ── Protocol 2 additions ────────────────────────────────────────────
_r(0x80, "PROTO",            2, 5, ArgType.UINT1,       0, 0, "Declare protocol version")
_r(0x81, "NEWOBJ",           2, 5, ArgType.NONE,        2, 1, "Build new object (cls, args)")
_r(0x82, "EXT1",             2, 5, ArgType.UINT1,       0, 1, "Resolve 1-byte ext code")
_r(0x83, "EXT2",             2, 5, ArgType.UINT2,       0, 1, "Resolve 2-byte ext code")
_r(0x84, "EXT4",             2, 5, ArgType.INT4,        0, 1, "Resolve 4-byte ext code")
_r(0x85, "TUPLE1",           2, 5, ArgType.NONE,        1, 1, "Build 1-element tuple")
_r(0x86, "TUPLE2",           2, 5, ArgType.NONE,        2, 1, "Build 2-element tuple")
_r(0x87, "TUPLE3",           2, 5, ArgType.NONE,        3, 1, "Build 3-element tuple")
_r(0x88, "NEWTRUE",          2, 5, ArgType.NONE,        0, 1, "Push True")
_r(0x89, "NEWFALSE",         2, 5, ArgType.NONE,        0, 1, "Push False")
_r(0x8A, "LONG1",            2, 5, ArgType.BYTES1,      0, 1, "Push long (1-byte len)")
_r(0x8B, "LONG4",            2, 5, ArgType.BYTES4,      0, 1, "Push long (4-byte len)")

# ── Protocol 3 additions ────────────────────────────────────────────
_r(0x42, "BINBYTES",         3, 5, ArgType.BYTES4,      0, 1, "Push binary bytes (4-byte len)")
_r(0x43, "SHORT_BINBYTES",   3, 5, ArgType.BYTES1,      0, 1, "Push short binary bytes")

# ── Protocol 4 additions ────────────────────────────────────────────
_r(0x8C, "SHORT_BINUNICODE", 4, 5, ArgType.STRING1,     0, 1, "Push short unicode (1-byte len)")
_r(0x8D, "BINUNICODE8",      4, 5, ArgType.UINT8,       0, 1, "Push unicode (8-byte len)")
_r(0x8E, "BINBYTES8",        4, 5, ArgType.BYTES8,      0, 1, "Push bytes (8-byte len)")
_r(0x8F, "EMPTY_SET",        4, 5, ArgType.NONE,        0, 1, "Push empty set")
_r(0x90, "ADDITEMS",         4, 5, ArgType.NONE,        0, 0, "Bulk add items to set")
_r(0x91, "FROZENSET",        4, 5, ArgType.NONE,        0, 1, "Build frozenset from mark")
_r(0x92, "NEWOBJ_EX",        4, 5, ArgType.NONE,        3, 1, "Build new object (cls, args, kwargs)")
_r(0x93, "STACK_GLOBAL",     4, 5, ArgType.NONE,        2, 1, "Push global from stack strings")
_r(0x94, "MEMOIZE",          4, 5, ArgType.NONE,        0, 0, "Store top in next memo slot")
_r(0x95, "FRAME",            4, 5, ArgType.UINT8,       0, 0, "Frame header with length")

# ── Protocol 5 additions ────────────────────────────────────────────
_r(0x96, "BYTEARRAY8",       5, 5, ArgType.BYTES8,      0, 1, "Push bytearray (8-byte len)")
_r(0x97, "NEXT_BUFFER",      5, 5, ArgType.NONE,        0, 1, "Push next out-of-band buffer")
_r(0x98, "READONLY_BUFFER",  5, 5, ArgType.NONE,        1, 1, "Make buffer read-only")


# ── Lookup helpers ───────────────────────────────────────────────────

def opcodes_for_protocol(protocol: int) -> list[OpcodeInfo]:
    """Return all opcodes available at the given protocol version."""
    return [
        op for op in OPCODE_REGISTRY.values()
        if op.available_in(protocol)
    ]


def opcode_by_byte(byte: int) -> Optional[OpcodeInfo]:
    """Look up an opcode by its byte value."""
    for op in OPCODE_REGISTRY.values():
        if op.byte == byte:
            return op
    return None


def opcode_by_name(name: str) -> Optional[OpcodeInfo]:
    """Look up an opcode by its name."""
    return OPCODE_REGISTRY.get(name)


# ── Opcode groups for generation ─────────────────────────────────────

PUSH_OPCODES = {
    name for name, op in OPCODE_REGISTRY.items()
    if op.stack_after > 0 and op.stack_before == 0
    and name not in ("MARK", "STOP", "FRAME", "PROTO")
}

CONSUME_OPCODES = {
    name for name, op in OPCODE_REGISTRY.items()
    if op.stack_before > 0
}

# Opcodes safe to push unconditionally (no stack prerequisites)
SAFE_PUSH_OPCODES = {
    "NONE", "NEWTRUE", "NEWFALSE", "EMPTY_TUPLE",
    "EMPTY_LIST", "EMPTY_DICT", "EMPTY_SET",
    "BININT1", "BININT2", "BININT",
    "SHORT_BINUNICODE", "BINUNICODE", "SHORT_BINSTRING",
    "BINSTRING", "SHORT_BINBYTES", "BINBYTES",
    "FLOAT", "BINFLOAT", "INT", "LONG", "LONG1", "LONG4",
    "BYTEARRAY8", "BINBYTES8", "BINUNICODE8",
}

# Opcodes that need specific stack conditions (handled by can_emit)
CALLABLE_OPCODES = {
    "GLOBAL", "STACK_GLOBAL", "INST",
}

CONSTRUCTION_OPCODES = {
    "REDUCE", "NEWOBJ", "NEWOBJ_EX", "BUILD", "OBJ",
}

# All dangerous opcodes that scanners should check
DANGEROUS_OPCODES = {
    "GLOBAL", "STACK_GLOBAL", "INST", "OBJ",
    "REDUCE", "NEWOBJ", "NEWOBJ_EX", "BUILD",
    "EXT1", "EXT2", "EXT4",
    "PERSID", "BINPERSID",
}

# Opcodes controlled by the generator's outer loop (not randomly chosen)
EXCLUDE_FROM_RANDOM = {
    "STOP", "PROTO", "FRAME",
}
