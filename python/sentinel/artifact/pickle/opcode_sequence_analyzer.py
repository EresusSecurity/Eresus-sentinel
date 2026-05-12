"""Sliding-window opcode sequence analyzer for pickle streams.

Detects attack patterns that combine multiple individually innocuous opcodes
into dangerous execution chains — invisible to single-opcode blocklist checks.
"""
from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from ...finding import Finding, Severity

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _Pattern:
    name: str
    opcodes: tuple[str, ...]
    severity: Severity
    description: str
    rule_id: str
    cwe_ids: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()


_PATTERNS: list[_Pattern] = [
    # ── Chained calls / gadget chains ─────────────────────────────────────
    # (plain GLOBAL→REDUCE is handled upstream by the blocklist scanner)
    _Pattern(
        name="chained_reduce_global",
        opcodes=("REDUCE", "GLOBAL", "REDUCE"),
        severity=Severity.CRITICAL,
        description=(
            "REDUCE→GLOBAL→REDUCE: chained function calls — "
            "output of one call passed as argument to next"
        ),
        rule_id="PICKLE-SEQ-003",
        cwe_ids=("CWE-502", "CWE-77"),
        tags=("pickle:gadget-chain",),
    ),
    _Pattern(
        name="chained_reduce_stack_global",
        opcodes=("REDUCE", "STACK_GLOBAL", "REDUCE"),
        severity=Severity.CRITICAL,
        description=(
            "REDUCE→STACK_GLOBAL→REDUCE: protocol-4/5 gadget chain"
        ),
        rule_id="PICKLE-SEQ-003",
        cwe_ids=("CWE-502", "CWE-77"),
        tags=("pickle:gadget-chain", "protocol:4+"),
    ),
    # ── Class instantiation attack ────────────────────────────────────────
    _Pattern(
        name="inst_reduce",
        opcodes=("INST", "REDUCE"),
        severity=Severity.HIGH,
        description="INST→REDUCE: class instantiation followed by call",
        rule_id="PICKLE-SEQ-004",
        cwe_ids=("CWE-502",),
        tags=("pickle:rce",),
    ),
    # ── Post-REDUCE mutation (CVE-2026-24747) ─────────────────────────────
    _Pattern(
        name="reduce_setitem",
        opcodes=("REDUCE", "SETITEM"),
        severity=Severity.HIGH,
        description="REDUCE→SETITEM: attribute mutation on REDUCE result",
        rule_id="PICKLE-SEQ-005",
        cwe_ids=("CWE-502",),
        tags=("pickle:mutation",),
    ),
    _Pattern(
        name="global_reduce_setitem",
        opcodes=("GLOBAL", "REDUCE", "SETITEM"),
        severity=Severity.CRITICAL,
        description="GLOBAL→REDUCE→SETITEM: tensor-rebuild + dict mutation",
        rule_id="PICKLE-SEQ-005",
        cwe_ids=("CWE-502",),
        tags=("pickle:mutation",),
    ),
    _Pattern(
        name="stack_global_reduce_setitem",
        opcodes=("STACK_GLOBAL", "REDUCE", "SETITEM"),
        severity=Severity.CRITICAL,
        description=(
            "STACK_GLOBAL→REDUCE→SETITEM: tensor-rebuild + mutation, "
            "protocol-4/5 variant"
        ),
        rule_id="PICKLE-SEQ-005",
        cwe_ids=("CWE-502",),
        tags=("pickle:mutation", "protocol:4+"),
    ),
    _Pattern(
        name="newobj_setitems",
        opcodes=("NEWOBJ", "SETITEMS"),
        severity=Severity.HIGH,
        description="NEWOBJ→SETITEMS: object construction + bulk dict mutation",
        rule_id="PICKLE-SEQ-006",
        cwe_ids=("CWE-502",),
        tags=("pickle:mutation",),
    ),
    # ── String-based code injection ───────────────────────────────────────
    _Pattern(
        name="string_global_reduce",
        opcodes=("STRING", "GLOBAL", "REDUCE"),
        severity=Severity.CRITICAL,
        description=(
            "STRING→GLOBAL→REDUCE: string constant used as argument to "
            "dangerous callable — code injection via string"
        ),
        rule_id="PICKLE-SEQ-007",
        cwe_ids=("CWE-502", "CWE-94"),
        tags=("pickle:code-injection",),
    ),
    # ── DUP-based evasion ─────────────────────────────────────────────────
    _Pattern(
        name="dup_global_reduce",
        opcodes=("DUP", "GLOBAL", "REDUCE"),
        severity=Severity.HIGH,
        description="DUP→GLOBAL→REDUCE: stack duplication to obscure call chain",
        rule_id="PICKLE-SEQ-008",
        cwe_ids=("CWE-502",),
        tags=("pickle:evasion",),
    ),
]

# Normalise pickletools lower-case names → canonical upper-case tokens
_NORM: dict[str, str] = {
    "reduce": "REDUCE",
    "global": "GLOBAL",
    "stack_global": "STACK_GLOBAL",
    "inst": "INST",
    "obj": "OBJ",
    "newobj": "NEWOBJ",
    "newobj_ex": "NEWOBJ",
    "build": "BUILD",
    "setitem": "SETITEM",
    "setitems": "SETITEMS",
    "dup": "DUP",
    "string": "STRING",
    "short_binstring": "STRING",
    "binstring": "STRING",
    "unicode": "UNICODE",
    "binunicode": "UNICODE",
    "binunicode8": "UNICODE",
    "short_binunicode": "UNICODE",
    "tuple": "TUPLE",
    "tuple1": "TUPLE",
    "tuple2": "TUPLE2",
    "tuple3": "TUPLE",
    "empty_tuple": "TUPLE",
    "pop": "POP",
    "mark": "MARK",
    "get": "GET",
    "binget": "GET",
    "long_binget": "GET",
    "put": "PUT",
    "binput": "PUT",
    "long_binput": "PUT",
    "memoize": "PUT",
}


def _norm(op: str) -> str:
    lo = op.lower()
    return _NORM.get(lo, op.upper())


def _is_subsequence(needle: tuple[str, ...], haystack: list[str]) -> bool:
    """Return True if *needle* appears in *haystack* in order (not necessarily consecutive)."""
    it = iter(haystack)
    return all(token in it for token in needle)


@dataclass
class _MatchResult:
    pattern: _Pattern
    window_snapshot: list[str]
    position: int
    stack_snapshot: list[str]


class OpcodeSequenceAnalyzer:
    """Sliding-window pickle opcode sequence analyzer.

    Feed opcodes one at a time via :meth:`feed`; collect :class:`Finding`
    objects via :meth:`findings`.
    """

    def __init__(self, window_size: int = 12) -> None:
        self._window: deque[str] = deque(maxlen=window_size)
        self._stack: list[str] = []
        self._matches: list[_MatchResult] = []
        self._position: int = 0

    # ── public API ────────────────────────────────────────────────────────

    def feed(self, opcode_name: str, arg: Any = None) -> list[_MatchResult]:
        """Process one opcode and return any newly detected patterns."""
        norm = _norm(opcode_name)
        self._window.append(norm)
        self._update_stack(norm, arg)
        self._position += 1

        new: list[_MatchResult] = []
        win = list(self._window)
        for p in _PATTERNS:
            if len(win) >= len(p.opcodes) and _is_subsequence(p.opcodes, win):
                r = _MatchResult(
                    pattern=p,
                    window_snapshot=win.copy(),
                    position=self._position,
                    stack_snapshot=self._stack.copy(),
                )
                new.append(r)
                self._matches.append(r)
        return new

    def findings(self, filepath: str = "") -> list[Finding]:
        """Convert accumulated matches to :class:`Finding` objects."""
        out: list[Finding] = []
        seen: set[str] = set()
        for r in self._matches:
            p = r.pattern
            key = p.rule_id
            if key in seen:
                continue
            seen.add(key)
            evidence = (
                f"sequence={list(r.pattern.opcodes)}, "
                f"position={r.position}, "
                f"window={r.window_snapshot[-len(p.opcodes) - 2:]}"
            )
            out.append(
                Finding.artifact(
                    rule_id=p.rule_id,
                    title=f"Dangerous opcode sequence: {p.name}",
                    description=p.description,
                    severity=p.severity,
                    target=filepath,
                    evidence=evidence,
                    cwe_ids=list(p.cwe_ids),
                    tags=list(p.tags),
                )
            )
        return out

    def reset(self) -> None:
        self._window.clear()
        self._stack.clear()
        self._matches.clear()
        self._position = 0

    # ── stack simulation (best-effort, for evidence enrichment) ───────────

    def _update_stack(self, op: str, arg: Any) -> None:
        try:
            if op == "GLOBAL" and isinstance(arg, tuple) and len(arg) == 2:
                self._stack.append(f"{arg[0]}.{arg[1]}")
            elif op == "GLOBAL" and isinstance(arg, str):
                self._stack.append(arg)
            elif op == "STACK_GLOBAL":
                if len(self._stack) >= 2:
                    name = self._stack.pop()
                    module = self._stack.pop()
                    self._stack.append(f"{module}.{name}")
            elif op == "REDUCE":
                if len(self._stack) >= 2:
                    args = self._stack.pop()
                    func = self._stack.pop()
                    self._stack.append(f"{func}({args})")
                elif len(self._stack) == 1:
                    func = self._stack.pop()
                    self._stack.append(f"{func}(...)")
            elif op in ("STRING", "UNICODE"):
                self._stack.append(repr(arg) if arg is not None else "STRING")
            elif op in ("TUPLE", "TUPLE2"):
                self._stack.append("TUPLE")
            elif op == "NEWOBJ":
                if len(self._stack) >= 2:
                    args = self._stack.pop()
                    cls = self._stack.pop()
                    self._stack.append(f"new:{cls}({args})")
            elif op == "DUP":
                if self._stack:
                    self._stack.append(self._stack[-1])
            elif op == "POP":
                if self._stack:
                    self._stack.pop()
            elif op == "SETITEM":
                # pops value, key; mutates top-of-stack dict
                if len(self._stack) >= 2:
                    self._stack.pop()
                    self._stack.pop()
            elif op == "SETITEMS":
                pass  # complex mark-based op; skip simulation
        except Exception as exc:
            logger.debug("stack simulation error op=%s: %s", op, exc)


# ── Convenience: scan bytes ───────────────────────────────────────────────

def scan_pickle_bytes(
    data: bytes,
    filepath: str = "",
    window_size: int = 12,
) -> list[Finding]:
    """Run the sequence analyzer over a raw pickle byte stream.

    Returns a (possibly empty) list of :class:`Finding` objects.
    Silently ignores malformed streams.
    """
    import io
    import pickletools

    analyzer = OpcodeSequenceAnalyzer(window_size=window_size)
    position = 0
    try:
        for opcode, arg, pos in pickletools.genops(data):
            analyzer.feed(opcode.name, arg)
            position = pos
    except Exception as exc:
        logger.debug("opcode sequence scan stopped at pos=%d: %s", position, exc)
    return analyzer.findings(filepath)
