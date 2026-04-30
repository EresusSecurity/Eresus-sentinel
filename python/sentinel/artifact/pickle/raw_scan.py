"""Raw byte-level fallback scanner when pickletools crashes."""

from __future__ import annotations

import logging
import re

from ...finding import Severity
from .._pickle_ops import DangerousImport, PickleAnalysis

logger = logging.getLogger(__name__)

# Raw opcode bytes
_GLOBAL_BYTE = 0x63       # 'c' GLOBAL
_INST_BYTE = 0x69         # 'i' INST
_STACK_GLOBAL_BYTE = 0x93 # STACK_GLOBAL
_REDUCE_BYTE = 0x52       # 'R' REDUCE
_NEWOBJ_BYTE = 0x81       # NEWOBJ
_NEWOBJ_EX_BYTE = 0x92    # NEWOBJ_EX
_BUILD_BYTE = 0x62        # 'b' BUILD

_EXEC_OPCODES = {_REDUCE_BYTE, _NEWOBJ_BYTE, _NEWOBJ_EX_BYTE, _BUILD_BYTE}

# Dangerous module.name patterns to catch even when opcodes are mutated.
# These are searched as raw ASCII substrings in the entire byte stream.
_DANGEROUS_PATTERNS: list[tuple[re.Pattern[bytes], str, str]] = [
    (re.compile(rb"os\nsystem"), "os", "system"),
    (re.compile(rb"os\npopen"), "os", "popen"),
    (re.compile(rb"os\nexecve?"), "os", "exec"),
    (re.compile(rb"posix\nsystem"), "posix", "system"),
    (re.compile(rb"subprocess\n(?:Popen|call|check_output|check_call|run)"),
     "subprocess", "Popen"),
    (re.compile(rb"builtins\n(?:eval|exec|__import__|compile|getattr)"),
     "builtins", "eval"),
    (re.compile(rb"nt\nsystem"), "nt", "system"),
    (re.compile(rb"codecs\n(?:encode|decode)"), "codecs", "encode"),
    (re.compile(rb"webbrowser\nopen"), "webbrowser", "open"),
    (re.compile(rb"shutil\n(?:rmtree|move|copy)"), "shutil", "rmtree"),
    (re.compile(rb"__builtin__\n(?:eval|exec|__import__)"),
     "__builtin__", "eval"),
    # Catch introspection chains (e.g. __subclasses__)
    (re.compile(rb"__subclasses__"), "<introspection>", "__subclasses__"),
    (re.compile(rb"__class__.*__bases__"), "<introspection>", "__class__.__bases__"),
    # Newline-agnostic variants — mutator may replace \n with other bytes
    (re.compile(rb"subprocess.{0,3}(?:Popen|call|check_output|check_call|run)"),
     "subprocess", "Popen"),
    (re.compile(rb"(?:os|posix|nt).{0,3}(?:system|popen|execve?)"),
     "os", "system"),
    (re.compile(rb"builtins.{0,3}(?:eval|exec|__import__|compile|getattr)"),
     "builtins", "eval"),
    (re.compile(rb"__builtin__.{0,3}(?:eval|exec|__import__)"),
     "__builtin__", "eval"),
]


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
        if data[i] in (_GLOBAL_BYTE, _INST_BYTE):
            op_label = "GLOBAL(raw)" if data[i] == _GLOBAL_BYTE else "INST(raw)"
            try:
                end = data.index(b"\n", i + 1)
                module = data[i + 1:end].decode("ascii", errors="replace")
                end2 = data.index(b"\n", end + 1)
                name = data[end + 1:end2].decode("ascii", errors="replace")
                if module and name:
                    check_import_fn(
                        module, name, op_label, i,
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

    # Check for execution opcodes (REDUCE, NEWOBJ, NEWOBJ_EX, BUILD)
    has_exec = bool(_EXEC_OPCODES.intersection(data))
    if has_exec:
        analysis.has_reduce = True
        for imp in analysis.dangerous_imports:
            for exec_byte in _EXEC_OPCODES:
                exec_pos = data.find(bytes([exec_byte]), imp.position)
                if exec_pos > imp.position:
                    imp.chain_confirmed = True
                    imp.confidence = 0.9
                    break

    # Dangerous string pattern scan — catches attacks where the opcode byte
    # itself was mutated but the module\nname payload is still intact.
    _dangerous_string_scan(data, analysis, check_import_fn)


def _dangerous_string_scan(
    data: bytes,
    analysis: PickleAnalysis,
    check_import_fn,
) -> None:
    """Scan for dangerous module\\nname byte patterns regardless of opcode integrity.

    When a mutator flips the GLOBAL opcode byte, the module and name strings
    may still be intact in the stream. This function finds them.
    """
    seen: set[tuple[str, str, int]] = set()
    # Collect already-found imports to avoid duplicates
    for imp in analysis.dangerous_imports:
        seen.add((imp.module, imp.name, imp.position))

    for pat, module_label, name_label in _DANGEROUS_PATTERNS:
        for m in pat.finditer(data):
            pos = m.start()
            key = (module_label, name_label, pos)
            if key in seen:
                continue
            seen.add(key)

            # Check if an exec opcode follows this string
            has_exec_after = any(
                data.find(bytes([eb]), pos) > pos for eb in _EXEC_OPCODES
            )
            conf = 0.85 if has_exec_after else 0.6

            analysis.dangerous_imports.append(DangerousImport(
                module=module_label,
                name=name_label,
                opcode="PATTERN(raw)",
                position=pos,
                severity=Severity.HIGH if has_exec_after else Severity.MEDIUM,
                confidence=conf,
                chain_confirmed=has_exec_after,
            ))
            if has_exec_after:
                analysis.has_reduce = True
