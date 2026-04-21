"""Raw byte-level fallback scanner when pickletools crashes."""

from __future__ import annotations

import logging

from .._pickle_ops import DangerousImport, PickleAnalysis
from ...finding import Severity

logger = logging.getLogger(__name__)

# Raw opcode bytes
_GLOBAL_BYTE = 0x63       # 'c' GLOBAL
_STACK_GLOBAL_BYTE = 0x93 # STACK_GLOBAL
_REDUCE_BYTE = 0x52       # 'R' REDUCE


def raw_byte_scan(
    data: bytes,
    analysis: PickleAnalysis,
    check_import_fn,
) -> None:
    """Scan raw bytes when pickletools crashes.

    Finds GLOBAL opcodes by byte pattern matching. This is the
    last-resort fallback that still catches most attacks even
    when the pickle stream is deliberately malformed.

    Args:
        data: Raw pickle bytes.
        analysis: PickleAnalysis to populate.
        check_import_fn: Callable(module, name, op, pos, pending, analysis).
    """
    i = 0
    while i < len(data):
        if data[i] == _GLOBAL_BYTE:
            try:
                end = data.index(b"\n", i + 1)
                module = data[i + 1:end].decode("ascii", errors="replace")
                end2 = data.index(b"\n", end + 1)
                name = data[end + 1:end2].decode("ascii", errors="replace")
                if module and name:
                    check_import_fn(
                        module, name, "GLOBAL(raw)", i,
                        analysis.dangerous_imports, analysis,
                    )
                i = end2 + 1
                continue
            except (ValueError, UnicodeDecodeError):
                pass
        elif data[i] == _STACK_GLOBAL_BYTE:
            analysis.dangerous_imports.append(DangerousImport(
                module="<raw_scan>",
                name="<stack_global>",
                opcode="STACK_GLOBAL(raw)",
                position=i,
                severity=Severity.MEDIUM,
                confidence=0.5,
            ))
        i += 1

    has_reduce = _REDUCE_BYTE in data
    if has_reduce:
        analysis.has_reduce = True
        for imp in analysis.dangerous_imports:
            reduce_pos = data.find(bytes([_REDUCE_BYTE]), imp.position)
            if reduce_pos > imp.position:
                imp.chain_confirmed = True
                imp.confidence = 0.9
