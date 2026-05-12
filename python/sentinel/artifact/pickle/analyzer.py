"""Deep opcode-level analysis engine for pickle streams."""

from __future__ import annotations

import io
import logging
import pickletools
from contextlib import suppress
from difflib import SequenceMatcher

from ...finding import Severity
from .._pickle_ops import (
    DUP_COUNT_THRESHOLD,
    EXT_OPS,
    GET_PUT_RATIO_WARN,
    MAX_MEMO_SIZE,
    MAX_OPCODES,
    MEMO_READ_OPS,
    MEMO_WRITE_OPS,
    REDUCE_OPS,
    STRING_OPS,
    TUPLE_OPS,
    DangerousImport,
    PickleAnalysis,
)
from .._pickle_rules import _check_list, classify_severity, is_dangerous
from .formats import (
    PROTO_HEADERS,
    YAML_MARKERS,
    detect_nested_pickle,
    detect_protocol,
    detect_tar,
    detect_yaml_markers,
    parse_global_arg,
)
from .raw_scan import dangerous_string_scan, raw_byte_scan

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
        analysis.parse_error = _parse_error

        def _check_fn(mod, name, op, pos, pending, anal):
            _check_import(mod, name, op, pos, pending, anal, blocklist, allowlist)

        raw_byte_scan(data, analysis, _check_fn)
        return analysis

    # Partial-pickle recovery
    if _parse_error:
        analysis.byte_scan_fallback = True
        analysis.parse_error = _parse_error

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

    # Even well-formed mutated pickles can smuggle dangerous module/name
    # strings past opcode-level matching. Run the raw string sweep on every
    # stream to catch those near-miss globals without relying on parser
    # failure as a prerequisite.
    def _check_fn(mod, name, op, pos, pending, anal):
        _check_import(mod, name, op, pos, pending, anal, blocklist, allowlist)

    dangerous_string_scan(data, analysis, _check_fn)

    # ── Post-walk analysis passes ────────────────────────────
    _expansion_attack_analysis(ops, analysis)
    _unused_variable_analysis(ops, analysis)

    # ── Sliding-window opcode sequence analysis ───────────────
    from .opcode_sequence_analyzer import OpcodeSequenceAnalyzer
    seq_analyzer = OpcodeSequenceAnalyzer()
    for opcode, arg, _pos in ops:
        seq_analyzer.feed(opcode.name, arg)
    analysis.sequence_findings = seq_analyzer.findings(source)

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
    last_global: DangerousImport | None = None
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
    _last_suspicious_global: DangerousImport | None = None
    _suspicious_globals: list[DangerousImport] = []
    _last_was_newobj = False  # tracks NEWOBJ specifically for SETITEMS pattern

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
                if ver not in range(6):
                    analysis.has_invalid_opcode = True
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
                            if (
                                hdr_pos >= 0
                                and hdr_pos + 2 < len(arg)
                                and arg[hdr_pos + 1] <= 5
                            ):
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
                    suspicious = _suspicious_global_mutation(
                        module, name, op_name, pos, blocklist, allowlist, str(arg)
                    )
                    if suspicious is not None:
                        _suspicious_globals.append(suspicious)
                        _last_suspicious_global = suspicious

            # ── STACK_GLOBAL ─────────────────────────────────
            elif op_name == "STACK_GLOBAL":
                raw_name = _value_stack.pop() if _value_stack else ""
                raw_module = _value_stack.pop() if _value_stack else ""
                name = str(raw_name) if not isinstance(raw_name, str) else raw_name
                module = str(raw_module) if not isinstance(raw_module, str) else raw_module
                # modelscan parity: "unknown" in module/name = critical RCE assumption
                if "unknown" in module.lower() or "unknown" in name.lower():
                    analysis.dangerous_imports.append(
                        DangerousImport(
                            module=module, name=name, opcode=op_name,
                            position=pos, severity=Severity.CRITICAL,
                            confidence=1.0,
                        )
                    )
                    last_global = analysis.dangerous_imports[-1]
                elif module and name:
                    _check_import(
                        module, name, op_name, pos,
                        pending_globals, analysis,
                        blocklist, allowlist,
                    )
                    if pending_globals and pending_globals[-1].position == pos:
                        last_global = pending_globals[-1]
                    suspicious = _suspicious_global_mutation(
                        module, name, op_name, pos, blocklist, allowlist, f"{module}.{name}"
                    )
                    if suspicious is not None:
                        _suspicious_globals.append(suspicious)
                        _last_suspicious_global = suspicious

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
                if _last_suspicious_global is not None:
                    _last_suspicious_global.chain_confirmed = True
                    _last_suspicious_global.confidence = max(
                        _last_suspicious_global.confidence, 0.8
                    )

            # ── REDUCE/BUILD/NEWOBJ ──────────────────────────
            elif op_name in REDUCE_OPS:
                analysis.has_reduce = True
                if op_name == "BUILD" and _last_was_newobj_or_reduce:
                    if last_global is not None or _last_suspicious_global is not None:
                        analysis.has_setstate_gadget = True
                if op_name in ("REDUCE", "NEWOBJ", "NEWOBJ_EX"):
                    _last_was_newobj_or_reduce = True
                    _last_was_newobj = op_name in ("NEWOBJ", "NEWOBJ_EX")
                else:
                    _last_was_newobj_or_reduce = False
                    _last_was_newobj = False
                if last_global is not None:
                    last_global.chain_confirmed = True
                    last_global.confidence = 1.0
                    last_global.payload_args = list(recent_strings[-5:])

                    if (last_global.module == "copyreg" and
                            last_global.name == "add_extension"):
                        args = recent_strings[-3:]
                        if len(args) >= 3:
                            with suppress(ValueError, IndexError):
                                analysis.copyreg_extensions[int(args[2])] = (args[0], args[1])

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
                if _last_suspicious_global is not None:
                    _last_suspicious_global.chain_confirmed = True
                    _last_suspicious_global.confidence = max(
                        _last_suspicious_global.confidence, 0.8
                    )
                    _last_suspicious_global.payload_args.extend(recent_strings[-5:])
                    _last_suspicious_global = None

            # ── SETITEM / SETITEMS (CVE-2026-24747) ──────────
            elif op_name in ("SETITEM", "SETITEMS"):
                if _last_was_newobj_or_reduce and (
                    last_global is not None or _last_suspicious_global is not None
                    or analysis.dangerous_imports
                ):
                    if op_name == "SETITEMS" and _last_was_newobj:
                        analysis.has_newobj_setitems = True
                    else:
                        analysis.has_setitem_mutation = True
                    if last_global is not None:
                        last_global.chain_confirmed = True
                        last_global.confidence = 1.0

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
                    _last_suspicious_global = None

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
    analysis.suspicious_global_mutations = [
        imp for imp in _suspicious_globals if imp.chain_confirmed
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
    dangerous = is_dangerous(module, name, blocklist, allowlist)
    if dangerous:
        severity = classify_severity(module, name)
        pending.append(DangerousImport(
            module=module,
            name=name,
            opcode=op_name,
            position=pos,
            severity=severity,
            confidence=0.7,
        ))

    if dangerous and module in (
        "base64", "codecs", "_codecs", "binascii",
        "marshal", "zlib", "gzip", "bz2", "lzma",
    ):
        analysis.obfuscation_detected = True

    if module == "types" and name in ("CodeType", "FunctionType"):
        analysis.has_codetype_construction = True
    if module == "marshal" and name == "loads":
        analysis.has_codetype_construction = True

    # When a risky module is imported with a name that contains non-identifier
    # bytes (control chars, null bytes, etc.) the name was most likely
    # corrupted by a mutator from a dangerous function like "call" or "Popen".
    # Also covers cases where the module name itself is mutated but still
    # contains the known module token as a substring.
    _RISKY_MODULE_TOKENS = ("subprocess", "builtins", "__builtin__", "os", "posix", "nt")
    _module_norm = "".join(ch for ch in module if ch.isalnum() or ch in "._")
    _is_risky_module = (
        module in _RISKY_MODULE_TOKENS
        or any(tok in _module_norm for tok in _RISKY_MODULE_TOKENS if len(tok) >= 4)
        or any(_close_identifier(module, tok) for tok in _RISKY_MODULE_TOKENS)
    )
    if not dangerous and _is_risky_module and name:
        has_control = any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in name)
        if has_control:
            pending.append(DangerousImport(
                module=module,
                name=name,
                opcode=f"{op_name}(mutated_name)",
                position=pos,
                severity=classify_severity(
                    "subprocess" if "subprocess" in _module_norm else module,
                    "system",
                ),
                confidence=0.6,
            ))


def _suspicious_global_mutation(
    module: str,
    name: str,
    op_name: str,
    pos: int,
    blocklist: dict[str, list[str]],
    allowlist: dict[str, list[str]],
    raw_arg: str = "",
) -> DangerousImport | None:
    """Return a finding candidate for mutated dangerous GLOBAL names."""
    if not module or not name:
        return None
    if is_dangerous(module, name, blocklist, allowlist):
        return None
    if _check_list(module, name, allowlist):
        return None

    candidate = _nearest_dangerous_global(module, name, blocklist, raw_arg)
    if candidate is None:
        return None

    candidate_module, candidate_name = candidate
    severity_name = candidate_name[:-1] if candidate_name.endswith("*") else candidate_name
    return DangerousImport(
        module=module,
        name=name,
        opcode=f"{op_name}(near:{candidate_module}.{candidate_name})",
        position=pos,
        severity=classify_severity(candidate_module, severity_name),
        confidence=0.65,
        payload_args=[f"near_miss={candidate_module}.{candidate_name}"],
    )


def _nearest_dangerous_global(
    module: str,
    name: str,
    blocklist: dict[str, list[str]],
    raw_arg: str = "",
) -> tuple[str, str] | None:
    """Find a dangerous YAML rule that a mutated GLOBAL appears to target."""
    combined = _normalize_identifier(f"{raw_arg} {module} {name}")

    for rule_module, names in blocklist.items():
        if not isinstance(names, list):
            continue
        candidate_module = rule_module[:-2] if rule_module.endswith(".*") else rule_module
        module_close = _close_identifier(module, candidate_module)
        module_norm = _normalize_identifier(module)

        for pattern in names:
            if not isinstance(pattern, str):
                continue
            if pattern == "*":
                if module_close:
                    return candidate_module, pattern
                continue

            candidate_name = pattern[:-1] if pattern.endswith("*") else pattern
            name_close = _close_identifier(name, candidate_name)
            if module_close and name_close:
                return candidate_module, pattern

            candidate_module_norm = _normalize_identifier(candidate_module)
            candidate_name_norm = _normalize_identifier(candidate_name)
            if (
                len(candidate_module_norm) >= 3
                and len(candidate_name_norm) >= 4
                and candidate_module_norm in combined
                and candidate_name_norm in combined
            ):
                return candidate_module, pattern

            # Short module names such as "os" can absorb the dangerous
            # attribute inside the mutated module token itself (e.g.
            # "os\x00popen", "ospopen"). In that case the attribute may
            # disappear from the parsed name field, so allow a tighter
            # prefix+embedded-name recovery path.
            #
            # Guard: skip when the original module contains a '.' separator
            # after the candidate prefix — that means it's a legitimate
            # sub-module path (e.g. "os.path"), not a concatenated mutation.
            if (
                len(candidate_module_norm) <= 3
                and module_norm.startswith(candidate_module_norm)
                and "." not in module[len(candidate_module):]
            ):
                if len(candidate_name_norm) >= 4:
                    # Exact embed (e.g. "ospopen" contains "popen")
                    embedded = module_norm[len(candidate_module_norm):]
                    if candidate_name_norm in embedded or candidate_name_norm in module_norm:
                        return candidate_module, pattern
                    # Near-miss embed: allow 1-char edit distance on the
                    # embedded suffix (e.g. "ospope" → "popen" with 1 missing)
                    if (
                        len(embedded) >= len(candidate_name_norm) - 2
                        and len(embedded) >= 3
                        and _edit_distance_at_most(embedded, candidate_name_norm, 2)
                    ):
                        return candidate_module, pattern

            # Name close + partial module match — catches heavily mutated
            # module strings where the function name survived (near-)intact.
            if (
                name_close
                and len(candidate_module_norm) >= 4
                and len(module_norm) >= 3
                and (
                    _partial_module_match(module_norm, candidate_module_norm)
                    or _fuzzy_module_match(module, candidate_module)
                )
            ):
                return candidate_module, pattern

            # Module close + exact name match — catches cases where module
            # survived intact but name has minor corruption.
            if (
                module_close
                and len(candidate_name_norm) >= 4
                and _close_identifier(name, candidate_name)
            ):
                return candidate_module, pattern

            # Module close + name ends-with candidate — catches cases where
            # garbage bytes were prepended to the function name.
            if (
                module_close
                and len(candidate_name_norm) >= 4
            ):
                name_norm_val = _normalize_identifier(name)
                if (
                    len(name_norm_val) >= len(candidate_name_norm)
                    and name_norm_val.endswith(candidate_name_norm)
                ):
                    return candidate_module, pattern

            # Module close + scrambled name — catches mutations that reorder
            # or insert characters in the function name token while keeping
            # all (or almost all) original characters.  Uses a sorted-char
            # overlap: if ≥80% of candidate chars appear in the name token
            # and the name is at most 2× longer than the candidate, flag it.
            if (
                module_close
                and len(candidate_name_norm) >= 4
            ):
                name_norm_val = _normalize_identifier(name)
                if (
                    2 <= len(name_norm_val) <= len(candidate_name_norm) * 2
                    and _char_overlap_ratio(name_norm_val, candidate_name_norm) >= 0.80
                ):
                    return candidate_module, pattern

    return None


def _partial_module_match(value: str, candidate: str) -> bool:
    """Relaxed prefix match for near-miss mutation detection.

    Guards against FPs by requiring:
    - Both identifiers share a common prefix (min 3 chars).
    - The shorter string is at least 60% the length of the longer one,
      preventing unrelated modules with coincidental prefixes
      (e.g. json≠jsonpickle, pickle≠pickle_compat).
    """
    if not value or not candidate:
        return False
    shorter, longer = min(len(value), len(candidate)), max(len(value), len(candidate))
    if shorter < 3:
        return False
    if shorter < longer * 0.6:
        return False
    prefix_len = max(3, shorter // 2 + 1)
    if len(value) >= prefix_len and len(candidate) >= prefix_len:
        return value[:prefix_len] == candidate[:prefix_len]
    return False


def _fuzzy_module_match(value: str, candidate: str) -> bool:
    """Catch insert-heavy mutations in module names without broad FPs."""
    value_alpha = _alpha_identifier(value)
    candidate_alpha = _alpha_identifier(candidate)
    if len(candidate_alpha) < 5 or len(value_alpha) < 5:
        return False
    if candidate_alpha in value_alpha or value_alpha in candidate_alpha:
        return True
    return SequenceMatcher(None, value_alpha, candidate_alpha).ratio() >= 0.78


def _alpha_identifier(value: str) -> str:
    return "".join(ch.lower() for ch in value if ch.isalpha())


def _normalize_identifier(value: str) -> str:
    return "".join(ch.lower() for ch in value if ch.isalnum() or ch in "._")


def _close_identifier(value: str, candidate: str) -> bool:
    value_norm = _normalize_identifier(value)
    candidate_norm = _normalize_identifier(candidate)
    if not value_norm or not candidate_norm:
        return False
    if value_norm == candidate_norm:
        return True
    if len(candidate_norm) >= 4 and (
        candidate_norm in value_norm
        or (
            len(value_norm) >= 4
            and len(value_norm) >= len(candidate_norm) // 2
            and value_norm in candidate_norm
        )
    ):
        return True
    max_distance = 1 if len(candidate_norm) <= 5 else 2
    if _edit_distance_at_most(value_norm, candidate_norm, max_distance):
        return True
    return len(candidate_norm) <= 4 and _subsequence_shape(value_norm, candidate_norm)


def _subsequence_shape(value: str, candidate: str) -> bool:
    if len(value) < len(candidate) or len(candidate) < 3:
        return False
    if not value.startswith(candidate[:2]) or value[-1] != candidate[-1]:
        return False
    index = 0
    for char in value:
        if index < len(candidate) and char == candidate[index]:
            index += 1
    return index == len(candidate)


def _edit_distance_at_most(left: str, right: str, limit: int) -> bool:
    if abs(len(left) - len(right)) > limit:
        return False
    previous = list(range(len(right) + 1))
    for i, left_char in enumerate(left, 1):
        current = [i]
        row_min = i
        for j, right_char in enumerate(right, 1):
            cost = 0 if left_char == right_char else 1
            current.append(min(
                previous[j] + 1,
                current[j - 1] + 1,
                previous[j - 1] + cost,
            ))
            row_min = min(row_min, current[-1])
        if row_min > limit:
            return False
        previous = current
    return previous[-1] <= limit


def _char_overlap_ratio(value: str, candidate: str) -> float:
    """Fraction of candidate chars that appear in value (multiset overlap)."""
    if not candidate:
        return 0.0
    from collections import Counter
    v_counts = Counter(value)
    c_counts = Counter(candidate)
    overlap = sum(min(v_counts[ch], c_counts[ch]) for ch in c_counts)
    return overlap / len(candidate)


def _expansion_attack_analysis(ops: list[tuple], analysis: PickleAnalysis) -> None:
    """Detect Billion-Laughs-style expansion attacks."""
    _get_count = getattr(analysis, "_get_count", 0)
    _put_count = getattr(analysis, "_put_count", 0)
    _memo_size = getattr(analysis, "_memo_size", 0)

    if _put_count > 0:
        analysis.get_put_ratio = _get_count / _put_count
        # High GET/PUT ratio with few total opcodes is a compact expansion
        # attack (Billion Laughs).  Large pickles with high ratios are
        # normal memoization (e.g. repeated strings/objects in lists).
        if analysis.get_put_ratio >= GET_PUT_RATIO_WARN:
            total_ops = getattr(analysis, "total_opcodes", 0)
            if total_ops < 200 or _memo_size >= 50:
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
    for opcode, arg, _pos in ops:
        if opcode.name in MEMO_READ_OPS and isinstance(arg, int):
            _memo_referenced.add(arg)

    _memo_written_after_reduce = set()
    _last_was_reduce = False
    for opcode, arg, _pos in ops:
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
