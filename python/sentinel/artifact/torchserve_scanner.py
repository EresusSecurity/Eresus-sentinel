"""TorchServe .mar, Torch7 .t7/.th/.net, ExecuTorch .pte, TensorRT .engine scanners.

Each scanner performs static analysis only — no model loading or code execution.
"""
from __future__ import annotations

import io
import json
import logging
import re
import struct
import zipfile
from pathlib import Path

from ..finding import Finding, Severity

logger = logging.getLogger(__name__)

_PICKLE_PROTOS = (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05")
_DANGEROUS_STRINGS = (
    b"__import__", b"os.system", b"os.popen", b"subprocess",
    b"eval(", b"exec(", b"/bin/sh", b"/bin/bash", b"cmd.exe",
    b"socket.connect", b"urllib.request", b"http.client",
)
_PRINTABLE_RE = re.compile(rb"[ -~]{6,512}")


def _extract_strings(data: bytes) -> list[str]:
    return [m.group().decode("latin-1", errors="replace") for m in _PRINTABLE_RE.finditer(data)]


# ─── TorchServe ─────────────────────────────────────────────────────────────

class TorchServeScanner:
    """Scan TorchServe .mar archives for handler and dependency risks."""

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        if not path.exists() or path.suffix.lower() != ".mar":
            return findings
        if not zipfile.is_zipfile(str(path)):
            findings.append(Finding.artifact(
                rule_id="MAR-001", title="Invalid MAR archive",
                description="File has .mar extension but is not a valid ZIP.",
                severity=Severity.HIGH, target=filepath,
            ))
            return findings
        try:
            with zipfile.ZipFile(str(path), "r") as zf:
                for info in zf.infolist():
                    name = info.filename
                    if ".." in name or name.startswith("/") or name.startswith("\\"):
                        findings.append(Finding.artifact(
                            rule_id="MAR-002", title="Path traversal in MAR",
                            description=f"Archive member '{name}' attempts path traversal.",
                            severity=Severity.CRITICAL, target=filepath,
                            evidence=name, cwe_ids=["CWE-22"],
                        ))
                if "MAR-INF/MANIFEST.json" in zf.namelist():
                    try:
                        manifest = json.loads(zf.read("MAR-INF/MANIFEST.json"))
                        handler = manifest.get("model", {}).get("handler", "")
                        dangerous = ["eval", "exec", "system", "subprocess", "__import__", "compile"]
                        if handler and any(d in handler for d in dangerous):
                            findings.append(Finding.artifact(
                                rule_id="MAR-003",
                                title=f"Suspicious handler reference: {handler}",
                                description="MAR manifest handler references a dangerous built-in.",
                                severity=Severity.CRITICAL, target=filepath, evidence=handler,
                            ))
                    except (json.JSONDecodeError, KeyError):
                        findings.append(Finding.artifact(
                            rule_id="MAR-004", title="Invalid MAR manifest",
                            description="Cannot parse MAR-INF/MANIFEST.json.",
                            severity=Severity.MEDIUM, target=filepath,
                        ))
                for name in zf.namelist():
                    if name.endswith((".py", ".sh", ".bash")):
                        data = zf.read(name)[:20_000]
                        for pat in _DANGEROUS_STRINGS:
                            if pat in data:
                                findings.append(Finding.artifact(
                                    rule_id="MAR-008",
                                    title=f"Dangerous code in MAR handler: {name}",
                                    description=f"Pattern '{pat.decode(errors='replace')}' in handler script.",
                                    severity=Severity.CRITICAL, target=filepath,
                                    evidence=f"{name}: {pat.decode(errors='replace')}",
                                    cwe_ids=["CWE-94"],
                                ))
                                break
                    if name.endswith((".pkl", ".pickle", ".pt", ".pth", ".bin")):
                        data = zf.read(name)[:10_000]
                        if any(data[i:i+2] == p[:2] for p in _PICKLE_PROTOS for i in range(min(512, len(data)))):
                            findings.append(Finding.artifact(
                                rule_id="MAR-005",
                                title=f"Pickle payload in MAR member: {name}",
                                description="Pickle data inside TorchServe archive — RCE risk on load.",
                                severity=Severity.HIGH, target=filepath,
                                evidence=name, cwe_ids=["CWE-502"],
                            ))
                    if name == "requirements.txt":
                        reqs = zf.read(name).decode(errors="replace")
                        bad_flags = ["--index-url", "--extra-index-url", "git+", "http://", "--find-links"]
                        if any(f in reqs for f in bad_flags):
                            findings.append(Finding.artifact(
                                rule_id="MAR-006",
                                title="Suspicious requirements.txt in MAR",
                                description="requirements.txt pulls packages from non-PyPI sources.",
                                severity=Severity.HIGH, target=filepath, evidence=reqs[:300],
                            ))
        except zipfile.BadZipFile:
            findings.append(Finding.artifact(
                rule_id="MAR-007", title="Corrupted MAR archive",
                description="zipfile.BadZipFile — archive is corrupted or truncated.",
                severity=Severity.HIGH, target=filepath,
            ))
        return findings


# ─── Torch7 ─────────────────────────────────────────────────────────────────

_T7_SAFE_MODULES = frozenset({
    "torch", "nn", "nngraph", "image", "paths", "math",
    "string", "table", "cunn", "cutorch", "optim",
})

_LUA_EXEC_RE = re.compile(
    r"(?i)\b(?:os\.execute|io\.popen|loadstring|dofile|loadfile|setfenv|getfenv)\s*\(",
)
_LUA_NET_RE = re.compile(
    r"(?i)\b(?:https?://|ftp://|socket\.|luasocket|curl|wget"
    r"|powershell(?:\.exe)?|cmd(?:\.exe)?\s+/c|/bin/sh|/bin/bash|netcat|nc\s)",
)
_LUA_DYNLOAD_RE = re.compile(r"(?i)\b(?:package\.loadlib|ffi\.load|loadlib)\b")
_LUA_REQUIRE_RE = re.compile(r"""(?i)\brequire\s*(?:\(\s*)?['"]([^'"]+)['"]""")

_T7_SIGNATURES = (b"T7\x00\x00", b"torch", b"nn.", b"tensor")


def _is_torch7(data: bytes) -> bool:
    lowered = data[:4096].lower()
    return data[:4].startswith(b"T7\x00\x00") or (
        (b"torch" in lowered or b"luat" in lowered)
        and (b"nn." in lowered or b"tensor" in lowered or b"thnn" in lowered)
    )


class Torch7Scanner:
    """Static scanner for legacy Torch7 .t7/.th/.net model files.

    Torch7 uses Lua serialization — embedded Lua code can call os.execute,
    io.popen, loadstring, or dynamically load native libraries.
    """

    _SUPPORTED = frozenset({".t7", ".th", ".net"})
    _MAX_BYTES = 12 * 1024 * 1024

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        if not path.exists() or path.suffix.lower() not in self._SUPPORTED:
            return findings

        try:
            data = path.read_bytes()[:self._MAX_BYTES]
        except OSError as exc:
            logger.debug("Torch7 scanner: cannot read %s: %s", filepath, exc)
            return findings

        if not _is_torch7(data):
            return findings

        strings = _extract_strings(data)
        seen: set[str] = set()

        for s in strings:
            m = _LUA_EXEC_RE.search(s)
            if m:
                func = m.group()
                if func not in seen:
                    seen.add(func)
                    findings.append(Finding.artifact(
                        rule_id="T7-001",
                        title=f"Lua code execution in Torch7: {func}",
                        description=(
                            f"Torch7 file contains '{func}' — Lua can execute arbitrary "
                            "OS commands when the model is loaded."
                        ),
                        severity=Severity.CRITICAL, target=filepath,
                        evidence=s[:200], cwe_ids=["CWE-94", "CWE-78"],
                    ))

            m2 = _LUA_NET_RE.search(s)
            if m2:
                pat = m2.group()
                if pat not in seen:
                    seen.add(pat)
                    findings.append(Finding.artifact(
                        rule_id="T7-003",
                        title=f"Network/shell pattern in Torch7: {pat[:40]}",
                        description="Network or shell command string embedded in Torch7 file.",
                        severity=Severity.HIGH, target=filepath,
                        evidence=s[:200], cwe_ids=["CWE-918"],
                    ))

            m3 = _LUA_DYNLOAD_RE.search(s)
            if m3:
                func = m3.group()
                if func not in seen:
                    seen.add(func)
                    findings.append(Finding.artifact(
                        rule_id="T7-004",
                        title=f"Dynamic library load in Torch7: {func}",
                        description=f"'{func}' loads native shared libraries from Lua.",
                        severity=Severity.HIGH, target=filepath,
                        evidence=s[:200], cwe_ids=["CWE-426"],
                    ))

            for m4 in _LUA_REQUIRE_RE.finditer(s):
                mod = m4.group(1)
                if mod not in _T7_SAFE_MODULES and mod not in seen:
                    seen.add(mod)
                    findings.append(Finding.artifact(
                        rule_id="T7-002",
                        title=f"Non-standard Lua require: {mod}",
                        description=f"Torch7 loads non-standard module '{mod}' via require().",
                        severity=Severity.MEDIUM, target=filepath,
                        evidence=s[:200],
                    ))

        return findings


# ─── ExecuTorch ──────────────────────────────────────────────────────────────

_EXECUTORCH_FLATBUF_MAGIC = b"ET_F"
_EXECUTORCH_ZIP_MAGIC = b"PK\x03\x04"

_ET_SUSPICIOUS = (
    b"__import__", b"os.system", b"subprocess", b"eval(", b"exec(",
    b"/bin/sh", b"/bin/bash", b"socket.connect", b"urllib",
)

_ET_CUSTOM_OPS = (b"custom_op", b"aten::_custom", b"external_call", b"dlopen", b"LoadLibrary")


class ExecuTorchScanner:
    """Static scanner for ExecuTorch / PyTorch Mobile model files (.ptl, .pte).

    Handles both FlatBuffer binary format and ZIP-wrapped archives.
    ZIP members with embedded pickle are passed through suspicious-string detection.
    """

    _SUPPORTED = frozenset({".pte", ".ptl"})

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        if not path.exists() or path.suffix.lower() not in self._SUPPORTED:
            return findings

        try:
            data = path.read_bytes()
        except OSError as exc:
            logger.debug("ExecuTorch scanner: cannot read %s: %s", filepath, exc)
            return findings

        if len(data) < 8:
            findings.append(Finding.artifact(
                rule_id="EXECUTORCH-001",
                title="ExecuTorch file too small",
                description="File is smaller than the minimum FlatBuffer header (8 bytes).",
                severity=Severity.MEDIUM, target=filepath,
            ))
            return findings

        if data[:4] == _EXECUTORCH_ZIP_MAGIC:
            findings.extend(self._scan_zip(filepath, data))
        else:
            findings.extend(self._scan_flatbuf(filepath, data))

        return findings

    def _scan_flatbuf(self, filepath: str, data: bytes) -> list[Finding]:
        findings: list[Finding] = []
        strings = _extract_strings(data)
        seen: set[bytes] = set()
        for s in strings:
            sb = s.encode("latin-1")
            for pat in _ET_SUSPICIOUS:
                if pat in sb and pat not in seen:
                    seen.add(pat)
                    findings.append(Finding.artifact(
                        rule_id="EXECUTORCH-002",
                        title=f"Dangerous string in ExecuTorch: {pat.decode(errors='replace')}",
                        description="Suspicious pattern in ExecuTorch FlatBuffer binary.",
                        severity=Severity.HIGH, target=filepath,
                        evidence=s[:200], cwe_ids=["CWE-94"],
                    ))
            for op in _ET_CUSTOM_OPS:
                if op in sb and op not in seen:
                    seen.add(op)
                    findings.append(Finding.artifact(
                        rule_id="EXECUTORCH-003",
                        title=f"Custom/external op in ExecuTorch: {op.decode(errors='replace')}",
                        description="Custom operators can execute arbitrary native code.",
                        severity=Severity.MEDIUM, target=filepath,
                        evidence=s[:200],
                    ))
        return findings

    def _scan_zip(self, filepath: str, data: bytes) -> list[Finding]:
        findings: list[Finding] = []
        try:
            with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
                for info in zf.infolist():
                    name = info.filename
                    if ".." in name or name.startswith("/"):
                        findings.append(Finding.artifact(
                            rule_id="EXECUTORCH-004",
                            title=f"Path traversal in ExecuTorch ZIP: {name}",
                            description="Archive member uses path traversal.",
                            severity=Severity.CRITICAL, target=filepath,
                            evidence=name, cwe_ids=["CWE-22"],
                        ))
                    member = zf.read(name)[:8_000]
                    if any(member.startswith(p) for p in _PICKLE_PROTOS):
                        findings.append(Finding.artifact(
                            rule_id="EXECUTORCH-005",
                            title=f"Pickle payload in ExecuTorch ZIP member: {name}",
                            description="Embedded pickle stream — RCE risk on deserialization.",
                            severity=Severity.HIGH, target=filepath,
                            evidence=name, cwe_ids=["CWE-502"],
                        ))
                    for pat in _ET_SUSPICIOUS:
                        if pat in member:
                            findings.append(Finding.artifact(
                                rule_id="EXECUTORCH-002",
                                title=f"Dangerous string in ExecuTorch ZIP member: {name}",
                                description=f"Pattern '{pat.decode(errors='replace')}' in {name}.",
                                severity=Severity.HIGH, target=filepath,
                                evidence=name, cwe_ids=["CWE-94"],
                            ))
                            break
        except zipfile.BadZipFile:
            findings.append(Finding.artifact(
                rule_id="EXECUTORCH-006",
                title="Corrupted ExecuTorch ZIP",
                description="File appears to be a ZIP but could not be parsed.",
                severity=Severity.MEDIUM, target=filepath,
            ))
        return findings


# ─── TensorRT ────────────────────────────────────────────────────────────────

_PE_SIGNATURE = b"PE\x00\x00"
_PE_POINTER_OFFSET = 0x3C
_PE_MIN_HEADER_OFFSET = 0x40
_PE_MAX_HEADER_OFFSET = 0x400
_MZ_SIGNATURE = b"MZ"
_ELF_SIGNATURE = b"\x7fELF"
_ELF_EXECUTABLE_TYPES = frozenset({2, 3})
_ELF_SUPPORTED_MACHINES = frozenset({
    0x03, 0x28, 0x3E, 0xB7, 0xF3,
    62, 183, 243, 40, 3,
})

_TRT_SUSPICIOUS_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("code_execution",       re.compile(r"(?i)\b(?:eval|exec|compile|__import__|system|popen|subprocess)\s*\(")),
    ("shell_command",        re.compile(r"(?i)\b(?:/bin/sh|/bin/bash|cmd\.exe|powershell|bash\s+-c|sh\s+-c)\b")),
    ("network_activity",     re.compile(r"(?i)\b(?:socket\.connect|urllib|requests\.get|http\.client|download|wget|curl)\b")),
    ("dynamic_library_load", re.compile(r"(?i)\b(?:dlopen|LoadLibraryA?W?|GetProcAddress|ctypes\.cdll)\b")),
    ("data_exfiltration",    re.compile(r"(?i)\b(?:base64\.b64encode|zlib\.compress|pickle\.dumps|marshal\.dumps)\b")),
    ("hardcoded_url",        re.compile(r"https?://[^\s\"'<>]{12,}")),
    ("crypto_miner",         re.compile(r"(?i)\b(?:stratum\+tcp|mining\.pool|xmrig|monero|cryptonight)\b")),
)

_TRT_PLUGIN_PATTERNS = (b"IPluginV2", b"IPluginCreator", b"getPluginName", b"nvinfer1::")


def _find_embedded_pe(data: bytes) -> int | None:
    start = 0
    while True:
        mz = data.find(_MZ_SIGNATURE, start)
        if mz == -1:
            return None
        pe_ptr_off = mz + _PE_POINTER_OFFSET
        if pe_ptr_off + 4 <= len(data):
            pe_offset = struct.unpack_from("<I", data, pe_ptr_off)[0]
            pe_sig_off = mz + pe_offset
            if (
                _PE_MIN_HEADER_OFFSET <= pe_offset <= _PE_MAX_HEADER_OFFSET
                and pe_sig_off + 4 <= len(data)
                and data[pe_sig_off: pe_sig_off + 4] == _PE_SIGNATURE
            ):
                return mz
        start = mz + 1


def _find_embedded_elf(data: bytes) -> int | None:
    start = 0
    while True:
        elf = data.find(_ELF_SIGNATURE, start)
        if elf == -1:
            return None
        if elf + 24 <= len(data):
            elf_class   = data[elf + 4]
            byte_order  = data[elf + 5]
            elf_version = data[elf + 6]
            if elf_class in {1, 2} and byte_order in {1, 2} and elf_version == 1:
                endian = "little" if byte_order == 1 else "big"
                obj_type = int.from_bytes(data[elf + 16: elf + 18], endian)
                machine  = int.from_bytes(data[elf + 18: elf + 20], endian)
                obj_ver  = int.from_bytes(data[elf + 20: elf + 24], endian)
                if obj_type in _ELF_EXECUTABLE_TYPES and machine in _ELF_SUPPORTED_MACHINES and obj_ver == 1:
                    return elf
        start = elf + 1


class TensorRTScanner:
    """Static scanner for NVIDIA TensorRT engine files (.engine, .plan, .trt).

    Extracts printable strings from the binary blob and applies pattern rules.
    Also searches for embedded PE (Windows) and ELF (Linux) executables
    using validated header structures.
    """

    _SUPPORTED = frozenset({".engine", ".plan", ".trt"})
    _MAX_BYTES = 64 * 1024 * 1024

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        if not path.exists() or path.suffix.lower() not in self._SUPPORTED:
            return findings

        try:
            data = path.read_bytes()[:self._MAX_BYTES]
        except OSError as exc:
            logger.debug("TensorRT scanner: cannot read %s: %s", filepath, exc)
            return findings

        strings = _extract_strings(data)
        matched_patterns: set[str] = set()

        for s in strings:
            for name, regex in _TRT_SUSPICIOUS_PATTERNS:
                if name in matched_patterns:
                    continue
                if regex.search(s):
                    matched_patterns.add(name)
                    findings.append(Finding.artifact(
                        rule_id="TRT-001",
                        title=f"Suspicious pattern in TensorRT engine: {name}",
                        description=(
                            f"Pattern category '{name}' found in serialized TensorRT engine — "
                            "may indicate malicious code or data exfiltration."
                        ),
                        severity=Severity.CRITICAL, target=filepath,
                        evidence=s[:200], cwe_ids=["CWE-506"],
                    ))

        for ref in _TRT_PLUGIN_PATTERNS:
            if ref in data:
                findings.append(Finding.artifact(
                    rule_id="TRT-002",
                    title=f"TensorRT plugin ABI reference: {ref.decode(errors='replace')}",
                    description=(
                        "TensorRT plugins load system shared libraries and can execute "
                        "arbitrary native code. Verify plugin provenance."
                    ),
                    severity=Severity.MEDIUM, target=filepath,
                    evidence=ref.decode(errors="replace"),
                ))
                break

        pe_off = _find_embedded_pe(data)
        if pe_off is not None:
            findings.append(Finding.artifact(
                rule_id="TRT-003",
                title="Embedded Windows PE/DLL header in TensorRT engine",
                description=f"Valid PE header found at offset 0x{pe_off:x} — potential executable dropper.",
                severity=Severity.CRITICAL, target=filepath,
                cwe_ids=["CWE-506"],
            ))

        elf_off = _find_embedded_elf(data)
        if elf_off is not None:
            findings.append(Finding.artifact(
                rule_id="TRT-004",
                title="Embedded Linux ELF executable in TensorRT engine",
                description=f"Valid ELF header found at offset 0x{elf_off:x} — potential executable dropper.",
                severity=Severity.CRITICAL, target=filepath,
                cwe_ids=["CWE-506"],
            ))

        return findings
