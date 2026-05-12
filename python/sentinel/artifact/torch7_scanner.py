"""Scanner for legacy Torch7 serialized model artifacts (.t7 / .th / .net).

Torch7 is a Lua-based deep learning framework (precursor to PyTorch).
Models serialized by ``torch.save()`` in Lua can contain embedded Lua code
that executes on load via ``os.execute``, ``io.popen``, ``loadstring``, or
dynamic ``require`` / ``ffi.load`` calls.  These artifacts are still
distributed on HuggingFace and model zoos as legacy weights.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from ..finding import Finding, Severity

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────
MAX_SCAN_BYTES = 12 * 1024 * 1024
SIGNATURE_READ_BYTES = 4096
MIN_TORCH7_SIZE = 8

_PRINTABLE_RE = re.compile(rb"[\t\n\r -~]{6,512}")

_EXEC_PRIMITIVE_RE = re.compile(
    r"(?i)\b(?:os\.execute|io\.popen|loadstring|dofile|loadfile|setfenv|getfenv)\s*\("
)

_NETWORK_SHELL_RE = re.compile(
    r"(?i)\b("
    r"https?://|ftp://|socket\.|luasocket|curl|wget|"
    r"powershell(?:\.exe)?|cmd(?:\.exe)?\s+/c|"
    r"/bin/sh|/bin/bash|bash\s+-c|sh\s+-c|netcat|nc\s+"
    r")"
)

_DYNAMIC_LOAD_RE = re.compile(r"(?i)\b(?:package\.loadlib|ffi\.load|loadlib)\b")

_SAFE_REQUIRE: frozenset[str] = frozenset({
    "torch", "nn", "nngraph", "image", "paths", "math",
    "string", "table", "cunn", "cutorch", "optim",
})

_WINDOWS_LOL_RE = re.compile(
    r"(?i)\b(?:certutil|bitsadmin|mshta|wscript|cscript|"
    r"msiexec|wmic|rundll32|regsvr32|"
    r"invoke-expression|invoke-webrequest|start-process|new-object\s+webclient)\b"
)


# ── Signature detection ────────────────────────────────────────────────────

def _is_torch7(prefix: bytes) -> bool:
    """Return True if prefix looks like a Torch7 serialization header."""
    if prefix.startswith(b"T7\x00\x00"):
        return True
    lowered = prefix.lower()
    has_torch = b"torch" in lowered or b"luat" in lowered
    has_struct = b"nn." in lowered or b"tensor" in lowered or b"thnn" in lowered
    return has_torch and has_struct


def _extract_strings(payload: bytes, max_strings: int = 5000) -> list[str]:
    results: list[str] = []
    for m in _PRINTABLE_RE.finditer(payload):
        try:
            results.append(m.group().decode("utf-8", errors="replace"))
        except Exception:
            continue
        if len(results) >= max_strings:
            break
    return results


def _snippet(text: str, max_chars: int = 180) -> str:
    return text if len(text) <= max_chars else text[: max_chars - 3] + "..."


# ── Scanner ────────────────────────────────────────────────────────────────

class Torch7Scanner:
    """Scan Torch7 `.t7` / `.th` / `.net` model files for Lua execution
    primitives, dynamic loading, and network/shell indicators."""

    EXTENSIONS = frozenset({".t7", ".th", ".net"})

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)

        if not path.exists() or not path.is_file():
            return findings
        if path.suffix.lower() not in self.EXTENSIONS:
            return findings
        if path.stat().st_size < MIN_TORCH7_SIZE:
            return findings

        try:
            raw = path.read_bytes()
        except OSError as exc:
            logger.warning("Torch7Scanner: cannot read %s: %s", filepath, exc)
            return findings

        if not _is_torch7(raw[:SIGNATURE_READ_BYTES]):
            return findings

        truncated = len(raw) > MAX_SCAN_BYTES
        payload = raw[:MAX_SCAN_BYTES]

        strings = _extract_strings(payload)

        self._check_exec_primitives(filepath, strings, findings)
        self._check_dynamic_loads(filepath, strings, findings)
        self._check_network_shell(filepath, strings, findings)
        self._check_windows_lolbins(filepath, strings, findings)

        if truncated:
            findings.append(Finding.artifact(
                rule_id="TORCH7-TRUNC",
                title="Torch7 scan truncated (large file)",
                description=f"File exceeds {MAX_SCAN_BYTES // (1024*1024)} MB scan budget; "
                            "remaining bytes not analyzed.",
                severity=Severity.LOW,
                target=filepath,
                evidence=f"file_size={path.stat().st_size}",
            ))

        return findings

    def _check_exec_primitives(
        self, fp: str, strings: list[str], findings: list[Finding]
    ) -> None:
        critical: list[str] = []
        warning: list[str] = []

        for i, text in enumerate(strings):
            if not _EXEC_PRIMITIVE_RE.search(text):
                continue
            window = " ".join(strings[max(0, i - 1): i + 2])
            if _NETWORK_SHELL_RE.search(window):
                critical.append(_snippet(text))
            else:
                warning.append(_snippet(text))

        if critical:
            findings.append(Finding.artifact(
                rule_id="TORCH7-EXEC-001",
                title="Lua execution primitive with network/shell context",
                description=(
                    "Torch7 file contains os.execute/io.popen/loadstring calls "
                    "co-located with network or shell strings — strong RCE signal."
                ),
                severity=Severity.CRITICAL,
                target=fp,
                evidence="; ".join(critical[:5]),
                cwe_ids=["CWE-94", "CWE-78"],
                tags=["owasp:llm05", "mitre-atlas:AML.T0010"],
            ))
        elif warning:
            findings.append(Finding.artifact(
                rule_id="TORCH7-EXEC-002",
                title="Lua execution primitive detected",
                description=(
                    "Torch7 file contains os.execute/io.popen/loadstring/dofile calls "
                    "without corroborating network context — possible payload staging."
                ),
                severity=Severity.HIGH,
                target=fp,
                evidence="; ".join(warning[:5]),
                cwe_ids=["CWE-94"],
                tags=["owasp:llm05"],
            ))

    def _check_dynamic_loads(
        self, fp: str, strings: list[str], findings: list[Finding]
    ) -> None:
        hits: list[str] = []
        for text in strings:
            load_hit = bool(_DYNAMIC_LOAD_RE.search(text))
            suspicious_requires = [
                m
                for m in re.findall(r"require\s*[\(\s]['\"]([^'\"]+)['\"]", text, re.I)
                if m.lower() not in _SAFE_REQUIRE and not m.lower().startswith("torch.")
            ]
            if load_hit or suspicious_requires:
                hits.append(_snippet(text))

        if hits:
            findings.append(Finding.artifact(
                rule_id="TORCH7-LOAD-001",
                title="Dynamic Lua module loading in Torch7 file",
                description=(
                    "package.loadlib / ffi.load or suspicious require() calls outside "
                    "known safe Torch/nn modules detected in serialized text regions."
                ),
                severity=Severity.HIGH,
                target=fp,
                evidence="; ".join(hits[:5]),
                cwe_ids=["CWE-829"],
                tags=["owasp:llm05"],
            ))

    def _check_network_shell(
        self, fp: str, strings: list[str], findings: list[Finding]
    ) -> None:
        hits = [_snippet(t) for t in strings if _NETWORK_SHELL_RE.search(t)]
        if hits:
            findings.append(Finding.artifact(
                rule_id="TORCH7-NET-001",
                title="Network or shell strings in Torch7 serialized text",
                description=(
                    "URLs, socket references, or shell command indicators found in "
                    "Torch7 model text regions — may indicate C2 beaconing or data exfil."
                ),
                severity=Severity.MEDIUM,
                target=fp,
                evidence="; ".join(hits[:8]),
                cwe_ids=["CWE-200"],
                tags=["owasp:llm05"],
            ))

    def _check_windows_lolbins(
        self, fp: str, strings: list[str], findings: list[Finding]
    ) -> None:
        hits = [_snippet(t) for t in strings if _WINDOWS_LOL_RE.search(t)]
        if hits:
            findings.append(Finding.artifact(
                rule_id="TORCH7-LOL-001",
                title="Windows LOLBin references in Torch7 file",
                description=(
                    "References to certutil, bitsadmin, rundll32, mshta or other "
                    "Windows LOLBins detected in Torch7 model text regions."
                ),
                severity=Severity.HIGH,
                target=fp,
                evidence="; ".join(hits[:5]),
                cwe_ids=["CWE-78"],
                tags=["owasp:llm05", "mitre-atlas:AML.T0010"],
            ))
