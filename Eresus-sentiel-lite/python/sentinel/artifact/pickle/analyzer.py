"""Deep opcode-level analysis engine for pickle streams."""

from __future__ import annotations

import io
import logging
import pickletools
from typing import Optional

from .._pickle_ops import (
    GLOBAL_OPS, REDUCE_OPS, STRING_OPS, TUPLE_OPS,
    EXT_OPS, MEMO_WRITE_OPS, MEMO_READ_OPS,
    DangerousImport, PickleAnalysis,
    MAX_OPCODES, MAX_MEMO_SIZE,
    GET_PUT_RATIO_WARN, DUP_COUNT_THRESHOLD,
)
from .._pickle_rules import is_dangerous, classify_severity
from ...finding import Severity
from .formats import (
    PROTO_HEADERS, YAML_MARKERS,
    detect_protocol, detect_nested_pickle, detect_tar,
    detect_yaml_markers, parse_global_arg,
)
from .raw_scan import raw_byte_scan

logger = logging.getLogger(__name__)


def deep_analyze(
    data: bytes,
    source: str,
    blocklist: dict[str, list[str]],
    allowlist: dict[str, list[str]],
) -> PickleAnalysis:
    """Full opcode-level analysis with crash-resilient fallback."""
    analysis = PickleAnalysis()

    analysis.protocol_version = detect_protocol(data)
    analysis.has_nested_pickle = detect_nested_pickle(data)
    analysis.has_tar_format = detect_tar(data)
    analysis.has_nested_yaml = detect_yaml_markers(data)

    # ── Multi-pickle stream parsing ──────────────────────────
    stream = io.BytesIO(data)
    all_ops: list[tuple] = []
    _parse_error: str | None = None

    while stream.tell() < len(data):
        try:
            chunk_ops = list(pickletools.genops(stream))
            if not chunk_ops:
                break
            all_ops.extend(chunk_ops)
            if stream.read(1) == b"":
                break
            stream.seek(-1, 1)
        except Exception as e:
            _parse_error = str(e)
            logger.warning(
                "pickletools.genops error on '%s' at offset %d: %s",
                source, stream.tell(), e,
            )
            break

    # Zero ops → fallback to raw byte scan
    if not all_ops:
        if _parse_error:
            logger.warning(
                "pickletools.genops crashed on '%s': %s — using raw byte scan",
                source, _parse_error,
            )
        analysis.byte_scan_fallback = True

        def _check_fn(mod, name, op, pos, pending, anal):
            _check_import(mod, name, op, pos, pending, anal, blocklist, allowlist)

        raw_byte_scan(data, analysis, _check_fn)
        return analysis

    # Partial-pickle recovery
    if _parse_error:
        analysis.byte_scan_fallback = True

    ops = all_ops
    analysis.total_opcodes = len(ops)

    if len(ops) > MAX_OPCODES:
        analysis.has_invalid_opcode = True
        logger.warning(
            "Pickle '%s' has %d opcodes (limit: %d) — possible DoS",
            source, len(ops), MAX_OPCODES,
        )

    # ── Opcode walk ──────────────────────────────────────────
    _walk_opcodes(ops, analysis, source, blocklist, allowlist)

    # ── Post-walk analysis passes ────────────────────────────
    _expansion_attack_analysis(ops, analysis)
    _unused_variable_analysis(ops, analysis)

    if analysis.dangerous_imports:
        max_conf = max(imp.confidence for imp in analysis.dangerous_imports)
        has_confirmed = any(imp.chain_confirmed for imp in analysis.dangerous_imports)
        analysis.risk_score = 1.0 if has_confirmed else max_conf

    return analysis


def _walk_opcodes(
    ops: list[tuple],
    analysis: PickleAnalysis,
    source: str,
    blocklist: dict[str, list[str]],
    allowlist: dict[str, list[str]],
) -> None:
    """Walk the opcode list and populate analysis."""
    last_global: Optional[DangerousImport] = None
    recent_strings: list[str] = []
    pending_globals: list[DangerousImport] = []
    _value_stack: list = []
    _memo: dict[int, object] = {}
    _memo_counter = 0
    _seen_codetype = False
    _seen_functiontype = False
    _seen_introspection = False
    _last_was_obj = False
    _obj_globals: list[DangerousImport] = []
    _last_was_newobj_or_reduce = False

    _proto_count = 0
    _get_count = 0
    _put_count = 0
    _dup_count = 0
    _op_index = 0

    for opcode, arg, pos in ops:
        op_name = opcode.name

        try:
            # ── Structural integrity tracking ────────────────
            if op_name == "PROTO":
                _proto_count += 1
                ver = arg if isinstance(arg, int) else 0
                if _proto_count > 1:
                    analysis.has_duplicate_proto = True
                if ver >= 2 and _op_index > 0:
                    analysis.has_misplaced_proto = True

            if op_name in MEMO_READ_OPS:
                _get_count += 1
            elif op_name in MEMO_WRITE_OPS:
                _put_count += 1

            if op_name == "DUP":
                _dup_count += 1

            _op_index += 1

            # ── String opcodes ───────────────────────────────
            if op_name in STRING_OPS:
                val = arg
                if isinstance(arg, bytes):
                    val = arg.decode("utf-8", errors="replace")
                _value_stack.append(val)
                if isinstance(val, str) and len(val) < 500:
                    recent_strings.append(val)
                    analysis.string_payloads.append(val)
                    if isinstance(arg, bytes) and len(arg) >= 32:
                        for hdr in PROTO_HEADERS:
                            hdr_pos = arg.find(hdr)
                            if hdr_pos >= 0 and hdr_pos + 2 < len(arg):
                                if arg[hdr_pos + 1] <= 5:
                                    analysis.has_nested_pickle = True
                    if isinstance(val, str):
                        for marker in YAML_MARKERS:
                            if marker.decode() in val:
                                analysis.has_nested_yaml = True

            # ── GLOBAL/INST ──────────────────────────────────
            elif op_name in ("GLOBAL", "INST"):
                module, name = parse_global_arg(arg)
                if module and name:
                    _value_stack.clear()
                    if ".__" in name or name.startswith("__"):
                        _seen_introspection = True
                    if name in ("CodeType", "FunctionType"):
                        if name == "CodeType":
                            _seen_codetype = True
                        else:
                            _seen_functiontype = True
                    _check_import(
                        module, name, op_name, pos,
                        pending_globals, analysis,
                        blocklist, allowlist,
                    )
                    if pending_globals and pending_globals[-1].position == pos:
                        last_global = pending_globals[-1]

            # ── STACK_GLOBAL ─────────────────────────────────
            elif op_name == "STACK_GLOBAL":
                raw_name = _value_stack.pop() if _value_stack else ""
                raw_module = _value_stack.pop() if _value_stack else ""
                name = str(raw_name) if not isinstance(raw_name, str) else raw_name
                module = str(raw_module) if not isinstance(raw_module, str) else raw_module
                if module and name:
                    _check_import(
                        module, name, op_name, pos,
                        pending_globals, analysis,
                        blocklist, allowlist,
                    )
                    if pending_globals and pending_globals[-1].position == pos:
                        last_global = pending_globals[-1]

            # ── EXT opcodes ──────────────────────────────────
            elif op_name in EXT_OPS:
                ext_code = arg if isinstance(arg, int) else 0
                if ext_code in analysis.copyreg_extensions:
                    module, name = analysis.copyreg_extensions[ext_code]
                    analysis.has_ext_registry_abuse = True
                    _check_import(
                        module, name, f"EXT({ext_code})", pos,
                        pending_globals, analysis,
                        blocklist, allowlist,
                    )
                    if pending_globals and pending_globals[-1].position == pos:
                        last_global = pending_globals[-1]

            # ── OBJ opcode ───────────────────────────────────
            elif op_name == "OBJ":
                analysis.has_reduce = True
                _last_was_obj = True
                if last_global is not None:
                    last_global.chain_confirmed = True
                    last_global.confidence = 1.0
                    _obj_globals.append(last_global)

            # ── REDUCE/BUILD/NEWOBJ ──────────────────────────
            elif op_name in REDUCE_OPS:
                analysis.has_reduce = True
                if op_name == "BUILD":
                    if _last_was_newobj_or_reduce:
                        analysis.has_setstate_gadget = True
                if op_name in ("REDUCE", "NEWOBJ", "NEWOBJ_EX"):
                    _last_was_newobj_or_reduce = True
                else:
                    _last_was_newobj_or_reduce = False
                if last_global is not None:
                    last_global.chain_confirmed = True
                    last_global.confidence = 1.0
                    last_global.payload_args = list(recent_strings[-5:])

                    if (last_global.module == "copyreg" and
                            last_global.name == "add_extension"):
                        args = recent_strings[-3:]
                        if len(args) >= 3:
                            try:
                                analysis.copyreg_extensions[int(args[2])] = (args[0], args[1])
                            except (ValueError, IndexError):
                                pass

                    for s in recent_strings[-3:]:
                        if isinstance(s, str) and len(s) >= 32:
                            try:
                                raw = s.encode("latin-1")
                                for hdr in PROTO_HEADERS:
                                    hdr_pos = raw.find(hdr)
                                    if (hdr_pos >= 0 and
                                            hdr_pos + 2 < len(raw) and
                                            raw[hdr_pos + 1] <= 5):
                                        analysis.has_nested_pickle = True
                            except (UnicodeEncodeError, UnicodeDecodeError):
                                pass

                    last_global = None
                    recent_strings.clear()

            # ── Memo write ───────────────────────────────────
            elif op_name in MEMO_WRITE_OPS:
                if op_name == "MEMOIZE":
                    val = _value_stack[-1] if _value_stack else None
                    _memo[_memo_counter] = val
                    _memo_counter += 1
                elif isinstance(arg, int):
                    val = _value_stack[-1] if _value_stack else None
                    _memo[arg] = val

            # ── Memo read ────────────────────────────────────
            elif op_name in MEMO_READ_OPS:
                if isinstance(arg, int) and arg in _memo:
                    _value_stack.append(_memo[arg])

            # ── Tuple opcodes ────────────────────────────────
            elif op_name in TUPLE_OPS:
                pass

            # ── Stack management ─────────────────────────────
            elif op_name in ("POP", "POP_MARK", "STOP"):
                if op_name == "POP" and _last_was_obj and _obj_globals:
                    analysis.has_obj_pop_bypass = True
                    for g in _obj_globals:
                        g.confidence = 1.0
                        g.chain_confirmed = True
                    _obj_globals.clear()
                _last_was_obj = False
                if op_name == "STOP":
                    last_global = None

        except (TypeError, KeyError, IndexError, ValueError) as exc:
            logger.warning(
                "Stack manipulation error at pos %d in '%s': %s — treating as evasion",
                pos, source, exc,
            )
            analysis.dangerous_imports.append(DangerousImport(
                module="<evasion>",
                name="<stack_manipulation>",
                opcode=op_name,
                position=pos,
                severity=Severity.HIGH,
                confidence=0.8,
            ))

    if _seen_codetype or _seen_functiontype:
        analysis.has_codetype_construction = True
    if _seen_introspection:
        analysis.has_introspection_chain = True

    # Store structural counters
    analysis.dup_count = _dup_count
    analysis._get_count = _get_count
    analysis._put_count = _put_count
    analysis._memo_size = len(_memo)

    analysis.dangerous_imports = pending_globals + [
        imp for imp in analysis.dangerous_imports if imp not in pending_globals
    ]


def _check_import(
    module: str,
    name: str,
    op_name: str,
    pos: int,
    pending: list[DangerousImport],
    analysis: PickleAnalysis,
    blocklist: dict[str, list[str]],
    allowlist: dict[str, list[str]],
) -> None:
    """Check a single import and append to pending if dangerous."""
    if is_dangerous(module, name, blocklist, allowlist):
        severity = classify_severity(module, name)
        pending.append(DangerousImport(
            module=module,
            name=name,
            opcode=op_name,
            position=pos,
            severity=severity,
            confidence=0.7,
        ))

    if module in ("base64", "codecs", "marshal", "zlib", "gzip"):
        analysis.obfuscation_detected = True

    if module == "types" and name in ("CodeType", "FunctionType"):
        analysis.has_codetype_construction = True
    if module == "marshal" and name == "loads":
        analysis.has_codetype_construction = True


def _expansion_attack_analysis(ops: list[tuple], analysis: PickleAnalysis) -> None:
    """Detect Billion-Laughs-style expansion attacks."""
    _get_count = getattr(analysis, "_get_count", 0)
    _put_count = getattr(analysis, "_put_count", 0)
    _memo_size = getattr(analysis, "_memo_size", 0)

    if _put_count > 0:
        analysis.get_put_ratio = _get_count / _put_count
        if analysis.get_put_ratio >= GET_PUT_RATIO_WARN:
            analysis.has_expansion_attack = True
    elif _get_count > GET_PUT_RATIO_WARN:
        analysis.get_put_ratio = float(_get_count)
        analysis.has_expansion_attack = True

    if analysis.dup_count > DUP_COUNT_THRESHOLD:
        analysis.has_expansion_attack = True

    if _memo_size > MAX_MEMO_SIZE:
        analysis.has_expansion_attack = True


def _unused_variable_analysis(ops: list[tuple], analysis: PickleAnalysis) -> None:
    """Detect side-effect-only operations (unused memo writes after REDUCE)."""
    _memo_referenced = set()
    for opcode, arg, pos in ops:
        if opcode.name in MEMO_READ_OPS and isinstance(arg, int):
            _memo_referenced.add(arg)

    _memo_written_after_reduce = set()
    _last_was_reduce = False
    for opcode, arg, pos in ops:
        if opcode.name in REDUCE_OPS:
            _last_was_reduce = True
        elif opcode.name in MEMO_WRITE_OPS:
            if _last_was_reduce and isinstance(arg, int):
                _memo_written_after_reduce.add(arg)
            _last_was_reduce = False
        else:
            _last_was_reduce = False

    if _memo_written_after_reduce - _memo_referenced:
        analysis.has_unused_assignments = True
