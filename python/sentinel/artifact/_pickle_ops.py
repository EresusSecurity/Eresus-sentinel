"""Opcode constants and data classes for pickle analysis."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..finding import Severity

# Opcodes that import modules/globals onto the stack
GLOBAL_OPS = {"GLOBAL", "INST", "STACK_GLOBAL"}

# Opcodes that EXECUTE the callable on top of stack
REDUCE_OPS = {"REDUCE", "BUILD", "NEWOBJ", "NEWOBJ_EX"}

# Opcodes that push string data onto the stack (potential args)
STRING_OPS = {
    "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8",
    "SHORT_BINSTRING", "BINSTRING",
    "SHORT_BINBYTES", "BINBYTES", "BINBYTES8",
    "STRING", "UNICODE",
}

# Opcodes that build tuples (used as REDUCE args)
TUPLE_OPS = {"TUPLE", "TUPLE1", "TUPLE2", "TUPLE3", "EMPTY_TUPLE"}

# EXT opcodes: resolve via copyreg extension registry
EXT_OPS = {"EXT1", "EXT2", "EXT4"}

# Memo read/write opcodes
MEMO_WRITE_OPS = {"BINPUT", "LONG_BINPUT", "PUT", "MEMOIZE"}
MEMO_READ_OPS = {"BINGET", "LONG_BINGET", "GET"}

# Pickle protocol markers
PROTOCOL_MARKERS = {
    b"\x80\x00": 0, b"\x80\x01": 1, b"\x80\x02": 2,
    b"\x80\x03": 3, b"\x80\x04": 4, b"\x80\x05": 5,
}

# Resource limits (from fickling InterpreterLimits)
MAX_OPCODES = 1_000_000
MAX_MEMO_SIZE = 100_000
GET_PUT_RATIO_WARN = 10    # suspicious threshold
GET_PUT_RATIO_CRIT = 50    # critical threshold
DUP_COUNT_THRESHOLD = 100  # stack duplication attack


@dataclass
class DangerousImport:
    """A detected dangerous import in a pickle stream."""
    module: str
    name: str
    opcode: str
    position: int
    severity: Severity = Severity.CRITICAL
    confidence: float = 0.7
    payload_args: list[str] = field(default_factory=list)
    chain_confirmed: bool = False


@dataclass
class PickleAnalysis:
    """Complete analysis result from pickle opcode scanning."""
    dangerous_imports: list[DangerousImport] = field(default_factory=list)
    protocol_version: int = -1
    total_opcodes: int = 0
    has_reduce: bool = False
    has_nested_pickle: bool = False
    has_nested_yaml: bool = False
    has_introspection_chain: bool = False
    has_codetype_construction: bool = False
    has_ext_registry_abuse: bool = False
    has_tar_format: bool = False
    string_payloads: list[str] = field(default_factory=list)
    obfuscation_detected: bool = False
    risk_score: float = 0.0
    copyreg_extensions: dict = field(default_factory=dict)
    byte_scan_fallback: bool = False
    # ── Fickling-inspired structural integrity checks ────────────
    has_duplicate_proto: bool = False       # Multiple PROTO opcodes (tampered)
    has_misplaced_proto: bool = False       # PROTO not at position 0 (tampered)
    has_expansion_attack: bool = False      # High GET/PUT ratio (Billion Laughs)
    get_put_ratio: float = 0.0             # GET/PUT ratio metric
    dup_count: int = 0                     # Stack DUP opcode count
    has_invalid_opcode: bool = False        # Corrupt/evasion indicator
    has_unused_assignments: bool = False    # Variables assigned but never used
    # ── Advanced analysis engines ────────────────────────────────
    has_setstate_gadget: bool = False        # BUILD opcode with dangerous __setstate__
    has_obj_pop_bypass: bool = False         # OBJ+POP invisibility attack
    has_setitem_mutation: bool = False       # REDUCE→SETITEM heap mutation (CVE-2026-24747)
    has_newobj_setitems: bool = False        # NEWOBJ→SETITEMS attribute injection (CVE-2026-24747)
    suspicious_global_mutations: list[DangerousImport] = field(default_factory=list)
    non_standard_imports: list = field(default_factory=list)  # Imports outside stdlib+allowlist
    has_non_standard_import: bool = False
    interpretation_errors: list[str] = field(default_factory=list)
    parse_error: str | None = None
    # Internal structural counters (set by analyzer, used by post-walk passes)
    _get_count: int = 0
    _put_count: int = 0
    _memo_size: int = 0
