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
    (re.compile(rb"(?:os|posix|nt).{0,3}system"), "os", "system"),
    (re.compile(rb"(?:os|posix|nt).{0,3}popen"), "os", "popen"),
    (re.compile(rb"(?:os|posix|nt).{0,3}execve?"), "os", "exec"),
    (re.compile(rb"builtins.{0,3}(?:eval|exec|__import__|compile|getattr)"),
     "builtins", "eval"),
    (re.compile(rb"__builtin__.{0,3}(?:eval|exec|__import__)"),
     "__builtin__", "eval"),

    # Null-byte / character-insertion tolerance patterns.
    # Use re.DOTALL so '.' matches any byte including \n, allowing patterns to
    # span across the module\nname separator when the separator itself is mutated
    # or extra bytes are injected between the module and function name tokens.
    #
    # Short-distance gaps (1-2 extra bytes per token char) keep FP rate low
    # while catching the mutation families seen in fuzz soak analysis.
    (re.compile(rb"(?:os|posix|nt).{0,10}s.{0,2}y.{0,2}s.{0,2}t.{0,2}e.{0,2}m", re.DOTALL),
     "os", "system"),
    (re.compile(rb"(?:os|posix|nt).{0,10}p.{0,2}o.{0,2}p.{0,2}e.{0,2}n", re.DOTALL),
     "os", "popen"),
    (re.compile(rb"s.{0,2}u.{0,2}b.{0,2}p.{0,2}r.{0,2}o.{0,8}(?:Popen|call|check_output|check_call|run)", re.DOTALL),
     "subprocess", "Popen"),
    (re.compile(rb"s.{0,2}u.{0,2}b.{0,2}p.{0,2}r.{0,2}o.{0,8}c.{0,2}a.{0,2}l.{0,2}l", re.DOTALL),
     "subprocess", "call"),
    (re.compile(rb"s.{0,2}u.{0,2}b.{0,2}p.{0,2}r.{0,2}o.{0,8}c.{0,2}h.{0,2}e.{0,2}c.{0,2}k", re.DOTALL),
     "subprocess", "check_output"),
    (re.compile(rb"b.{0,2}u.{0,2}i.{0,4}t.{0,2}i.{0,2}n.{0,2}s.{0,6}(?:eval|exec|__import__|compile|getattr)", re.DOTALL),
     "builtins", "eval"),
    # "bui?tins" with l missing — catches bui"tins, bui\x00tins style mutations.
    # Use a character class that excludes 'l' (the missing letter) so this
    # does NOT match the intact "builtins" string (which is covered above).
    (re.compile(rb"bui[^lL\n]{1,2}tins", re.DOTALL), "builtins", "<mutated_exec>"),
    # Concatenated module+name — mutator sometimes merges them (e.g. "ospopen")
    (re.compile(rb"ospop.{0,2}en", re.DOTALL), "os", "popen"),
    (re.compile(rb"ossyst.{0,2}em", re.DOTALL), "os", "system"),
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
    dangerous_string_scan(data, analysis, check_import_fn)


def dangerous_string_scan(
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

    # ── Context-window proximity scan ────────────────────────────
    # When a module fragment appears in the stream, search the surrounding
    # 64-byte window for known dangerous function names.  This catches
    # cases where the module name is heavily mutated (null bytes, extra
    # chars) but the function name survives intact — or vice versa.
    _proximity_scan(data, analysis)


# Module fragments → dangerous function names that must appear nearby
_PROXIMITY_ANCHORS: list[tuple[bytes, list[bytes], str, str]] = [
    (b"subprocess",
     # Include function names AND their 3-char suffixes to catch mutations
     # where prefix bytes are corrupted (e.g. "ch\x05all" -> match on "all").
     [b"Popen", b"call", b"check_output", b"check_call", b"run",
      b"all",   # tail of "call" / "check_call"
      b"open",  # tail of "Popen"
      b"heck",  # prefix of "check_output"
      ],
     "subprocess", "Popen"),
    (b"subproc",
     [b"Popen", b"call", b"check_output", b"check_call", b"run",
      b"all", b"open", b"heck",
      b"Po",    # uppercase P = Popen hint even when rest is corrupted
      ],
     "subprocess", "Popen"),
    (b"builtins",
     [b"exec", b"eval", b"__import__", b"compile", b"getattr"],
     "builtins", "eval"),
    # Partial fragments — catches "bui\"tins", "bui\x00tins", "buitins", etc.
    (b"builtin",
     [b"exec", b"eval", b"__import__", b"compile", b"getattr"],
     "builtins", "eval"),
    (b"buitin",
     [b"exec", b"eval", b"__import__", b"compile", b"getattr"],
     "builtins", "eval"),
    (b"__builtin__",
     [b"exec", b"eval", b"__import__"],
     "__builtin__", "eval"),
]

_PROXIMITY_WINDOW = 64  # bytes to search after module fragment


def _proximity_scan(data: bytes, analysis: PickleAnalysis) -> None:
    """Look for dangerous function names within 64 bytes of a module fragment.

    Catches mutations where the module token is mangled by null-byte insertion
    or character substitution but the function name token remains readable.
    """
    seen_positions: set[int] = {imp.position for imp in analysis.dangerous_imports}

    for anchor, func_names, module_label, name_label in _PROXIMITY_ANCHORS:
        start = 0
        while True:
            pos = data.find(anchor, start)
            if pos < 0:
                break
            start = pos + 1
            window = data[pos: pos + _PROXIMITY_WINDOW]
            for func in func_names:
                func_pos = window.find(func)
                if func_pos >= 0:
                    abs_pos = pos + func_pos
                    if abs_pos in seen_positions:
                        continue
                    seen_positions.add(abs_pos)
                    has_exec_after = any(
                        data.find(bytes([eb]), abs_pos) > abs_pos
                        for eb in _EXEC_OPCODES
                    )
                    analysis.dangerous_imports.append(DangerousImport(
                        module=module_label,
                        name=name_label,
                        opcode="PROXIMITY(raw)",
                        position=abs_pos,
                        severity=Severity.HIGH if has_exec_after else Severity.MEDIUM,
                        confidence=0.8 if has_exec_after else 0.55,
                        chain_confirmed=has_exec_after,
                    ))
                    if has_exec_after:
                        analysis.has_reduce = True
                    break  # one match per anchor occurrence is enough
