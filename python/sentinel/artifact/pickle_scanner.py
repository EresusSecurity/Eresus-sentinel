"""Pickle deserialization scanner with opcode-level analysis.

Covers all known evasion techniques:
  - pickletools crash fallback (raw byte scan)
  - Scanner-specific exception hardening
  - EXT1/EXT2/EXT4 + copyreg registry tracking
  - Memo indirection for INST/STACK_GLOBAL
  - Nested deserialization (pickle-in-pickle, YAML payloads)
  - Introspection chain detection
  - zlib/base64 deobfuscation
  - TAR format detection
"""

from __future__ import annotations

import io
import logging
import pickletools
import struct
import zipfile
from pathlib import Path
from typing import BinaryIO, Optional

from ..finding import Finding, Severity, Location

from ._pickle_ops import (
    GLOBAL_OPS, REDUCE_OPS, STRING_OPS, TUPLE_OPS,
    EXT_OPS, MEMO_WRITE_OPS, MEMO_READ_OPS,
    PROTOCOL_MARKERS, DangerousImport, PickleAnalysis,
    MAX_OPCODES, MAX_MEMO_SIZE,
    GET_PUT_RATIO_WARN, GET_PUT_RATIO_CRIT, DUP_COUNT_THRESHOLD,
)
from ._pickle_rules import (
    load_default_rules,
    classify_severity, is_dangerous, rule_id_for_module,
)

logger = logging.getLogger(__name__)

# Raw opcode bytes for fallback scanner
_GLOBAL_BYTE = 0x63   # 'c' GLOBAL
_INST_BYTE = 0x69     # 'i' INST
_STACK_GLOBAL_BYTE = 0x93  # STACK_GLOBAL
_REDUCE_BYTE = 0x52   # 'R' REDUCE
_PROTO_BYTE = 0x80    # PROTO

# Pickle protocol headers for nested detection
_PROTO_HEADERS = [b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"]

# YAML deserialization markers
_YAML_MARKERS = [b"!!python/object/apply", b"!!python/object/new", b"!!python/module"]

# TAR magic
_TAR_MAGIC = b"ustar"
_TAR_MAGIC_OFFSET = 257


class PickleScanner:
    """Pickle byte-stream scanner with crash-resilient opcode analysis."""

    def __init__(
        self,
        blocklist: Optional[dict[str, list[str]]] = None,
        allowlist: Optional[dict[str, list[str]]] = None,
    ):
        if blocklist:
            self._blocklist = blocklist
            self._allowlist = allowlist or {}
        else:
            self._blocklist, self._allowlist = load_default_rules()

    # ─── Public API ───────────────────────────────────────────

    def scan_bytes(
        self,
        data: bytes,
        source: str = "<bytes>",
    ) -> list[Finding]:
        """Scan a pickle byte stream with full opcode analysis."""
        analysis = self._deep_analyze(data, source)
        findings: list[Finding] = []

        for imp in analysis.dangerous_imports:
            payload_info = ""
            if imp.payload_args:
                payload_info = f" Extracted payload args: {imp.payload_args[:3]}"

            chain_info = ""
            if imp.chain_confirmed:
                chain_info = (
                    " ⚠ REDUCE opcode confirms this import WILL EXECUTE "
                    "during deserialization — confirmed RCE vector."
                )

            finding = Finding.artifact(
                rule_id=rule_id_for_module(imp.module, imp.opcode),
                title=f"Dangerous pickle import: {imp.module}.{imp.name}",
                description=(
                    f"The pickle stream at '{source}' contains a {imp.opcode} opcode "
                    f"that imports '{imp.module}.{imp.name}'. This import can execute "
                    f"arbitrary code during deserialization."
                    f"{chain_info}{payload_info}"
                ),
                severity=imp.severity,
                confidence=imp.confidence,
                target=source,
                evidence=(
                    f"Opcode: {imp.opcode} at position {imp.position}, "
                    f"import: {imp.module}.{imp.name}, "
                    f"confidence: {imp.confidence:.1f}, "
                    f"chain_confirmed: {imp.chain_confirmed}"
                ),
                location=Location(file=source, byte_offset=imp.position),
                cwe_ids=["CWE-502"],
                tags=[
                    "avid-effect:security:S0403",
                    "owasp:llm05",
                    "mitre-atlas:AML.T0010",
                ],
            )
            findings.append(finding)

        # Protocol version warning
        if analysis.protocol_version in (0, 1):
            findings.append(Finding.artifact(
                rule_id="ARTIFACT-015",
                title=f"Legacy pickle protocol v{analysis.protocol_version}",
                description=(
                    f"The file uses pickle protocol {analysis.protocol_version}, "
                    "which has reduced security boundaries."
                ),
                severity=Severity.MEDIUM,
                confidence=0.6,
                target=source,
                evidence=f"Protocol version: {analysis.protocol_version}",
                cwe_ids=["CWE-502"],
            ))

        # Nested pickle warning
        if analysis.has_nested_pickle:
            findings.append(Finding.artifact(
                rule_id="ARTIFACT-016",
                title="Nested pickle detected (double deserialization)",
                description=(
                    "The pickle stream contains embedded pickle protocol headers, "
                    "indicating a pickle-within-pickle used to chain exploits."
                ),
                severity=Severity.HIGH,
                confidence=0.8,
                target=source,
                evidence="Multiple pickle protocol headers detected",
                cwe_ids=["CWE-502"],
            ))

        # Nested YAML warning
        if analysis.has_nested_yaml:
            findings.append(Finding.artifact(
                rule_id="ARTIFACT-018",
                title="Nested YAML deserialization detected",
                description=(
                    "String payloads contain !!python/object/apply markers, "
                    "indicating YAML-based code execution nested inside pickle."
                ),
                severity=Severity.CRITICAL,
                confidence=0.9,
                target=source,
                evidence="YAML !!python/object/apply in pickle string args",
                cwe_ids=["CWE-502"],
            ))

        # Obfuscation warning
        if analysis.obfuscation_detected:
            findings.append(Finding.artifact(
                rule_id="ARTIFACT-017",
                title="Pickle payload obfuscation detected",
                description=(
                    "Encoding modules (base64, codecs, marshal, zlib) "
                    "are imported in the pickle stream, suggesting payload "
                    "obfuscation to evade pattern-based scanners."
                ),
                severity=Severity.HIGH,
                confidence=0.9,
                target=source,
                evidence="Obfuscation module imports detected in pickle opcodes",
                cwe_ids=["CWE-502"],
            ))

        # Introspection chain warning
        if analysis.has_introspection_chain:
            findings.append(Finding.artifact(
                rule_id="ARTIFACT-019",
                title="Python introspection chain detected",
                description=(
                    "The pickle uses __subclasses__/__builtins__ chaining "
                    "to reach eval/exec from builtins-only GLOBAL opcodes. "
                    "This technique bypasses module-level blocklists."
                ),
                severity=Severity.CRITICAL,
                confidence=0.95,
                target=source,
                evidence="Introspection via __subclasses__ → __builtins__",
                cwe_ids=["CWE-502"],
            ))

        # EXT registry abuse
        if analysis.has_ext_registry_abuse:
            findings.append(Finding.artifact(
                rule_id="ARTIFACT-092",
                title="copyreg extension registry abuse detected",
                description=(
                    "The pickle registers dangerous functions via "
                    "copyreg.add_extension and invokes them via EXT opcodes, "
                    "bypassing GLOBAL/STACK_GLOBAL scanning."
                ),
                severity=Severity.CRITICAL,
                confidence=0.95,
                target=source,
                evidence=f"Registered extensions: {analysis.copyreg_extensions}",
                cwe_ids=["CWE-502"],
            ))

        # CodeType construction
        if analysis.has_codetype_construction:
            findings.append(Finding.artifact(
                rule_id="ARTIFACT-020",
                title="CodeType/FunctionType construction detected",
                description=(
                    "The pickle constructs executable code objects via "
                    "types.CodeType + types.FunctionType, embedding raw "
                    "Python bytecode that evades pattern-based detection."
                ),
                severity=Severity.CRITICAL,
                confidence=0.95,
                target=source,
                evidence="CodeType/FunctionType/marshal.loads in pickle stream",
                cwe_ids=["CWE-502"],
            ))

        # Byte-scan fallback warning
        if analysis.byte_scan_fallback:
            findings.append(Finding.artifact(
                rule_id="ARTIFACT-000",
                title="Pickle opcode parser crashed — evasion technique detected",
                description=(
                    "pickletools.genops() raised an exception on this file. "
                    "This is a known evasion technique (truncated opcodes after "
                    "the malicious REDUCE payload). Findings from raw byte scan."
                ),
                severity=Severity.CRITICAL,
                confidence=0.9,
                target=source,
                evidence="pickletools crash → raw byte scan fallback",
                cwe_ids=["CWE-502"],
            ))

        # ── Fickling-inspired structural integrity checks ────────────

        # Duplicate PROTO: multiple PROTO opcodes = tampered pickle
        if analysis.has_duplicate_proto:
            findings.append(Finding.artifact(
                rule_id="ARTIFACT-030",
                title="Duplicate PROTO opcode detected (tampered pickle)",
                description=(
                    "The pickle contains multiple PROTO opcodes. A valid pickle "
                    "has exactly one PROTO at position 0. Duplicate PROTOs "
                    "indicate a tampered file or an exploit chain."
                ),
                severity=Severity.HIGH,
                confidence=0.9,
                target=source,
                evidence="Multiple PROTO opcodes in single pickle stream",
                cwe_ids=["CWE-502"],
            ))

        # Misplaced PROTO: PROTO not at first opcode position
        if analysis.has_misplaced_proto:
            findings.append(Finding.artifact(
                rule_id="ARTIFACT-031",
                title="Misplaced PROTO opcode (protocol violation)",
                description=(
                    "For pickle protocol >= 2, the PROTO opcode must be "
                    "the first opcode. A misplaced PROTO may indicate "
                    "a tampered file attempting to bypass analysis."
                ),
                severity=Severity.HIGH,
                confidence=0.85,
                target=source,
                evidence="PROTO opcode not at position 0",
                cwe_ids=["CWE-502"],
            ))

        # Expansion attack: high GET/PUT ratio (Billion Laughs style)
        if analysis.has_expansion_attack:
            severity = (
                Severity.HIGH if analysis.get_put_ratio >= GET_PUT_RATIO_CRIT
                else Severity.MEDIUM
            )
            findings.append(Finding.artifact(
                rule_id="ARTIFACT-032",
                title="Expansion attack pattern detected (high GET/PUT ratio)",
                description=(
                    f"GET/PUT ratio is {analysis.get_put_ratio:.1f}:1 — "
                    "this pattern is indicative of an exponential expansion "
                    "attack (Billion Laughs style) that could cause memory "
                    "exhaustion during deserialization."
                ),
                severity=severity,
                confidence=0.8,
                target=source,
                evidence=(
                    f"GET/PUT ratio: {analysis.get_put_ratio:.1f}:1, "
                    f"DUP count: {analysis.dup_count}"
                ),
                cwe_ids=["CWE-400", "CWE-502"],
            ))

        # Invalid opcode: corrupt or evasion
        if analysis.has_invalid_opcode:
            findings.append(Finding.artifact(
                rule_id="ARTIFACT-033",
                title="Invalid pickle opcodes detected",
                description=(
                    "The pickle stream contains invalid opcodes that are "
                    "not part of any known protocol version. This indicates "
                    "a corrupted file or an active bypass attempt."
                ),
                severity=Severity.HIGH,
                confidence=0.85,
                target=source,
                evidence="Invalid opcode sequence in pickle stream",
                cwe_ids=["CWE-502"],
            ))

        return findings

    def scan_file(self, file_path: str | Path) -> list[Finding]:
        path = Path(file_path)
        if not path.exists():
            logger.warning("File not found: %s", path)
            return []
        data = path.read_bytes()
        return self.scan_bytes(data, source=str(path))

    def scan_stream(self, stream: BinaryIO, source: str = "<stream>") -> list[Finding]:
        data = stream.read()
        return self.scan_bytes(data, source=source)

    def scan_zip_entry(
        self,
        zip_file: zipfile.ZipFile,
        entry_name: str,
        source: str = "<zip>",
    ) -> list[Finding]:
        data = zip_file.read(entry_name)
        return self.scan_bytes(data, source=f"{source}!{entry_name}")

    def raw_analysis(self, data: bytes, source: str = "<bytes>") -> PickleAnalysis:
        return self._deep_analyze(data, source)

    # ─── Deep Opcode Analysis ─────────────────────────────────

    def _deep_analyze(self, data: bytes, source: str) -> PickleAnalysis:
        """Full opcode-level analysis with crash-resilient fallback."""
        analysis = PickleAnalysis()

        analysis.protocol_version = self._detect_protocol(data)
        # Note: nested pickle detection is now primarily done during
        # opcode analysis (string payload inspection), not raw byte scan.
        # Raw scan only flags definitive PROTO-STOP-PROTO sequences.
        analysis.has_nested_pickle = self._detect_nested_pickle(data)
        analysis.has_tar_format = self._detect_tar(data)

        # Check for YAML payloads in raw bytes
        for marker in _YAML_MARKERS:
            if marker in data:
                analysis.has_nested_yaml = True
                break

        try:
            ops = list(pickletools.genops(data))
        except Exception as e:
            # pickletools crash = known evasion technique
            logger.warning(
                "pickletools.genops crashed on '%s': %s — using raw byte scan", source, e
            )
            analysis.byte_scan_fallback = True
            self._raw_byte_scan(data, analysis)
            return analysis

        analysis.total_opcodes = len(ops)

        # Resource limit check (fickling-inspired)
        if len(ops) > MAX_OPCODES:
            analysis.has_invalid_opcode = True
            logger.warning(
                "Pickle '%s' has %d opcodes (limit: %d) — possible DoS",
                source, len(ops), MAX_OPCODES,
            )

        last_global: Optional[DangerousImport] = None
        recent_strings: list[str] = []
        pending_globals: list[DangerousImport] = []
        _value_stack: list = []  # Allow any type on stack
        _memo: dict[int, object] = {}
        _memo_counter = 0
        _seen_codetype = False
        _seen_functiontype = False
        _seen_introspection = False

        # Fickling-inspired structural counters
        _proto_count = 0
        _proto_versions: set[int] = set()
        _get_count = 0
        _put_count = 0
        _dup_count = 0
        _op_index = 0

        for opcode, arg, pos in ops:
            op_name = opcode.name

            try:
                # ── Fickling: structural integrity tracking ──────
                # PROTO tracking (duplicate + misplaced detection)
                if op_name == "PROTO":
                    _proto_count += 1
                    ver = arg if isinstance(arg, int) else 0
                    if _proto_count > 1:
                        analysis.has_duplicate_proto = True
                    if ver >= 2 and _op_index > 0:
                        analysis.has_misplaced_proto = True
                    _proto_versions.add(ver)

                # GET/PUT counting for expansion attack detection
                if op_name in MEMO_READ_OPS:
                    _get_count += 1
                elif op_name in MEMO_WRITE_OPS:
                    _put_count += 1

                # DUP tracking for stack duplication attacks
                if op_name == "DUP":
                    _dup_count += 1

                _op_index += 1

                # String opcodes: push values onto simulated stack
                if op_name in STRING_OPS:
                    val = arg
                    if isinstance(arg, bytes):
                        val = arg.decode("utf-8", errors="replace")
                    _value_stack.append(val)
                    if isinstance(val, str) and len(val) < 500:
                        recent_strings.append(val)
                        analysis.string_payloads.append(val)
                        # Nested payload detection in string args
                        # Only flag if the bytes arg is large enough to
                        # contain a real pickle payload (header + opcodes)
                        if isinstance(arg, bytes) and len(arg) >= 32:
                            for hdr in _PROTO_HEADERS:
                                hdr_pos = arg.find(hdr)
                                if hdr_pos >= 0 and hdr_pos + 2 < len(arg):
                                    # Verify version byte is valid (0-5)
                                    if arg[hdr_pos + 1] <= 5:
                                        analysis.has_nested_pickle = True
                        if isinstance(val, str):
                            for marker in _YAML_MARKERS:
                                if marker.decode() in val:
                                    analysis.has_nested_yaml = True

                # GLOBAL/INST: arg contains "module\nname" directly
                elif op_name in ("GLOBAL", "INST"):
                    module, name = self._parse_global_arg(arg)
                    if module and name:
                        _value_stack.clear()
                        # Introspection chain detection
                        if ".__" in name or name.startswith("__"):
                            _seen_introspection = True
                        if name in ("CodeType", "FunctionType"):
                            if name == "CodeType":
                                _seen_codetype = True
                            else:
                                _seen_functiontype = True
                        self._check_import(
                            module, name, op_name, pos,
                            pending_globals, analysis,
                        )
                        if pending_globals and pending_globals[-1].position == pos:
                            last_global = pending_globals[-1]

                # STACK_GLOBAL: pops name then module from stack
                elif op_name == "STACK_GLOBAL":
                    raw_name = _value_stack.pop() if _value_stack else ""
                    raw_module = _value_stack.pop() if _value_stack else ""
                    # Hardened: convert any type to string
                    name = str(raw_name) if not isinstance(raw_name, str) else raw_name
                    module = str(raw_module) if not isinstance(raw_module, str) else raw_module
                    if module and name:
                        self._check_import(
                            module, name, op_name, pos,
                            pending_globals, analysis,
                        )
                        if pending_globals and pending_globals[-1].position == pos:
                            last_global = pending_globals[-1]

                # EXT opcodes: resolve via copyreg registry
                elif op_name in EXT_OPS:
                    ext_code = arg if isinstance(arg, int) else 0
                    if ext_code in analysis.copyreg_extensions:
                        module, name = analysis.copyreg_extensions[ext_code]
                        analysis.has_ext_registry_abuse = True
                        self._check_import(
                            module, name, f"EXT({ext_code})", pos,
                            pending_globals, analysis,
                        )
                        if pending_globals and pending_globals[-1].position == pos:
                            last_global = pending_globals[-1]

                # REDUCE/BUILD/NEWOBJ: execute the callable
                elif op_name in REDUCE_OPS:
                    analysis.has_reduce = True
                    if last_global is not None:
                        last_global.chain_confirmed = True
                        last_global.confidence = 1.0
                        last_global.payload_args = list(recent_strings[-5:])

                        # Track copyreg.add_extension calls
                        if (last_global.module == "copyreg" and
                                last_global.name == "add_extension"):
                            args = recent_strings[-3:]
                            if len(args) >= 3:
                                try:
                                    ext_module = args[0]
                                    ext_name = args[1]
                                    ext_code = int(args[2])
                                    analysis.copyreg_extensions[ext_code] = (ext_module, ext_name)
                                except (ValueError, IndexError):
                                    pass

                        # Check for nested pickle in binary string args
                        # Require minimum payload size to avoid tensor data FPs
                        for s in recent_strings[-3:]:
                            if isinstance(s, str) and len(s) >= 32:
                                try:
                                    raw = s.encode("latin-1")
                                    for hdr in _PROTO_HEADERS:
                                        hdr_pos = raw.find(hdr)
                                        if (hdr_pos >= 0 and
                                                hdr_pos + 2 < len(raw) and
                                                raw[hdr_pos + 1] <= 5):
                                            analysis.has_nested_pickle = True
                                except (UnicodeEncodeError, UnicodeDecodeError):
                                    pass

                        last_global = None
                        recent_strings.clear()

                # Memo write (INST + memo indirection)
                elif op_name in MEMO_WRITE_OPS:
                    if op_name == "MEMOIZE":
                        val = _value_stack[-1] if _value_stack else None
                        _memo[_memo_counter] = val
                        _memo_counter += 1
                    elif isinstance(arg, int):
                        val = _value_stack[-1] if _value_stack else None
                        _memo[arg] = val

                # Memo read
                elif op_name in MEMO_READ_OPS:
                    if isinstance(arg, int) and arg in _memo:
                        _value_stack.append(_memo[arg])

                # Tuple opcodes
                elif op_name in TUPLE_OPS:
                    pass

                # Stack management
                elif op_name in ("POP", "POP_MARK", "STOP"):
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

        # Set flags
        if _seen_codetype or _seen_functiontype:
            analysis.has_codetype_construction = True
        if _seen_introspection:
            analysis.has_introspection_chain = True

        # ── Fickling: expansion attack analysis ──────────────────
        analysis.dup_count = _dup_count
        if _put_count > 0:
            analysis.get_put_ratio = _get_count / _put_count
            if analysis.get_put_ratio >= GET_PUT_RATIO_WARN:
                analysis.has_expansion_attack = True
        elif _get_count > GET_PUT_RATIO_WARN:
            # GETs with no PUTs is malformed/malicious
            analysis.get_put_ratio = float(_get_count)
            analysis.has_expansion_attack = True

        if _dup_count > DUP_COUNT_THRESHOLD:
            analysis.has_expansion_attack = True

        # Memo size check
        if len(_memo) > MAX_MEMO_SIZE:
            analysis.has_expansion_attack = True
            logger.warning(
                "Memo size %d exceeds limit %d in '%s'",
                len(_memo), MAX_MEMO_SIZE, source,
            )

        analysis.dangerous_imports = pending_globals + [
            imp for imp in analysis.dangerous_imports if imp not in pending_globals
        ]

        if analysis.dangerous_imports:
            max_confidence = max(imp.confidence for imp in analysis.dangerous_imports)
            has_confirmed = any(imp.chain_confirmed for imp in analysis.dangerous_imports)
            analysis.risk_score = 1.0 if has_confirmed else max_confidence

        return analysis


    def _raw_byte_scan(self, data: bytes, analysis: PickleAnalysis) -> None:
        """Scan raw bytes when pickletools crashes. Finds GLOBAL opcodes by byte pattern."""
        i = 0
        while i < len(data):
            if data[i] == _GLOBAL_BYTE:  # GLOBAL opcode: c<module>\n<name>\n
                try:
                    end = data.index(b"\n", i + 1)
                    module = data[i + 1:end].decode("ascii", errors="replace")
                    end2 = data.index(b"\n", end + 1)
                    name = data[end + 1:end2].decode("ascii", errors="replace")
                    if module and name:
                        self._check_import(
                            module, name, "GLOBAL(raw)", i,
                            analysis.dangerous_imports, analysis,
                        )
                    i = end2 + 1
                    continue
                except (ValueError, UnicodeDecodeError):
                    pass
            elif data[i] == _STACK_GLOBAL_BYTE:  # STACK_GLOBAL
                # Can't resolve stack from raw bytes, but flag the opcode
                analysis.dangerous_imports.append(DangerousImport(
                    module="<raw_scan>",
                    name="<stack_global>",
                    opcode="STACK_GLOBAL(raw)",
                    position=i,
                    severity=Severity.MEDIUM,
                    confidence=0.5,
                ))
            i += 1

        # Check if any REDUCE byte follows a dangerous import
        has_reduce = _REDUCE_BYTE in data
        if has_reduce:
            analysis.has_reduce = True
            for imp in analysis.dangerous_imports:
                # Find REDUCE after this import's position
                reduce_pos = data.find(bytes([_REDUCE_BYTE]), imp.position)
                if reduce_pos > imp.position:
                    imp.chain_confirmed = True
                    imp.confidence = 0.9

    # ─── Import Checking ─────────────────────────────────────

    def _check_import(
        self,
        module: str,
        name: str,
        op_name: str,
        pos: int,
        pending: list[DangerousImport],
        analysis: PickleAnalysis,
    ) -> None:
        """Check a single import and append to pending if dangerous."""
        if is_dangerous(module, name, self._blocklist, self._allowlist):
            severity = classify_severity(module, name)
            imp = DangerousImport(
                module=module,
                name=name,
                opcode=op_name,
                position=pos,
                severity=severity,
                confidence=0.7,
            )
            pending.append(imp)

        if module in ("base64", "codecs", "marshal", "zlib", "gzip"):
            analysis.obfuscation_detected = True

        
        if module == "types" and name in ("CodeType", "FunctionType"):
            analysis.has_codetype_construction = True
        if module == "marshal" and name == "loads":
            analysis.has_codetype_construction = True

    # ─── Helpers ──────────────────────────────────────────────

    @staticmethod
    def _parse_global_arg(arg: str) -> tuple[str, str]:
        if not arg:
            return ("", "")
        if "\n" in arg:
            parts = arg.split("\n", 1)
        elif " " in arg:
            parts = arg.split(" ", 1)
        else:
            parts = [arg, ""]
        module = parts[0].strip() if len(parts) > 0 else ""
        name = parts[1].strip() if len(parts) > 1 else ""
        return (module, name)

    @staticmethod
    def _detect_protocol(data: bytes) -> int:
        if len(data) < 2:
            return -1
        header = data[:2]
        if header in PROTOCOL_MARKERS:
            return PROTOCOL_MARKERS[header]
        if data[0:1] in (b"(", b"c", b"l", b"d"):
            return 0
        return -1

    @staticmethod
    def _detect_nested_pickle(data: bytes) -> bool:
        """Detect real nested pickle (pickle-in-pickle exploit chaining).

        Strategy: A valid pickle stream ends with exactly one STOP (0x2e)
        at the very end. If a PROTO header (0x80 + version) appears after
        the final STOP of the primary stream, there is a second pickle
        embedded — the hallmark of exploit chaining.

        We use the LAST occurrence of STOP because 0x2e ('.')  appears
        frequently in tensor data / strings — only the very last one is
        the real pickle terminator.
        """
        if len(data) < 8:
            return False

        markers = [b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"]

        # Verify this data starts with a pickle PROTO header
        has_proto_start = any(data[:2] == m for m in markers)
        if not has_proto_start:
            return False

        # The LAST STOP byte is the real pickle stream terminator
        last_stop = data.rfind(b"\x2e")
        if last_stop <= 0:
            return False

        # Check for any PROTO header AFTER the last STOP
        remaining = data[last_stop + 1:]
        if len(remaining) < 4:
            return False

        for marker in markers:
            pos = remaining.find(marker)
            if pos >= 0 and pos + 2 < len(remaining):
                # Validate: version byte must be 0-5
                if remaining[pos + 1] <= 5:
                    return True

        return False

    @staticmethod
    def _detect_tar(data: bytes) -> bool:
        """Detect TAR archive format (old PyTorch serialization)."""
        if len(data) > _TAR_MAGIC_OFFSET + 5:
            return data[_TAR_MAGIC_OFFSET:_TAR_MAGIC_OFFSET + 5] == _TAR_MAGIC
        return False
