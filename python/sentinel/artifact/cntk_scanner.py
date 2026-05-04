"""Microsoft CNTK model format scanner (.dnn, .cmf).

Detection rules are loaded from rules/cntk_rules.yaml at import time.
Covers:
  - Legacy v1 (UTF-16LE BCN/BVersion) and CNTKv2 (protobuf) variant detection
  - Structural integrity minimum-byte check per variant
  - Printable-string extraction (ASCII + UTF-16LE) with bounded budgets
  - External native-library load reference detection (same-string AND split-signal)
  - Two-tier load context: strong (explicit) vs weak (module/library/ctypes)
  - Command + network/eval execution correlation
  - Obfuscated Base64 payload detection (decode OR exec OR command context)
  - Direct eval/exec/import detection
  - Native code execution via ctypes/cffi
  - Persistence mechanism detection (schtasks, registry, cron)
  - HTTP fetch call detection
  - Advanced obfuscation (PowerShell -EncodedCommand, hex shellcode)
  - Crypto-miner indicator detection
  - Multi-signal correlation escalation
"""
from __future__ import annotations

import re
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any

from sentinel.finding import Finding, Severity

logger = logging.getLogger(__name__)

_MAX_SIGNATURE_BYTES = 4096
_MAX_SCAN_BYTES = 10 * 1024 * 1024
_MAX_EXTRACTED_STRINGS = 2000
_MAX_EVIDENCE_PER_CATEGORY = 5

_CNTK_LEGACY_MAGIC = b"B\x00C\x00N\x00\x00\x00"
_CNTK_LEGACY_VERSION_MARKER = b"B\x00V\x00e\x00r\x00s\x00i\x00o\x00n\x00\x00\x00"
_CNTK_V2_REQUIRED_MARKERS = (b"\x0a\x07version", b"\x0a\x03uid")
_CNTK_V2_STRUCTURE_MARKERS = (b"CompositeFunction", b"primitive_functions", b"PrimitiveFunction")

_LEGACY_V1_MIN_BYTES = 32
_CNTK_V2_MIN_BYTES = 24

_ASCII_STRING_RE = re.compile(rb"[ -~]{6,512}")
_UTF16LE_STRING_RE = re.compile(rb"(?:[\x20-\x7e]\x00){6,256}")

DISCOVERY_ASSUMPTIONS = [
    "Legacy CNTK models begin with UTF-16LE BCN marker and contain a BVersion section marker.",
    "CNTKv2 protobuf artifacts expose key markers for version/uid plus graph structure fields.",
    "Split-signal detection correlates load_context and library_path across separate extracted strings.",
    "Rules loaded from rules/cntk_rules.yaml v2.0; no hardcoded patterns in scanner code.",
]


def _compile_patterns(patterns: list[str], label: str = "") -> list[re.Pattern[str]]:
    compiled = []
    for pat in patterns:
        try:
            compiled.append(re.compile(pat, re.IGNORECASE))
        except re.error as exc:
            logger.warning("cntk_rules: bad pattern %r in %s: %s", pat, label, exc)
    return compiled


@lru_cache(maxsize=1)
def _compiled_rules() -> dict[str, Any]:
    from sentinel.rules import load_cntk_rules
    rules = load_cntk_rules()

    ext_rules = rules.get("external_load_rules", [])
    safe_keys = frozenset(k.lower() for k in rules.get("safe_metadata_keys", []))

    strong_load_ctx: list[str] = []
    weak_load_ctx: list[str] = []
    lib_path: list[str] = []
    url: list[str] = []
    for r in ext_rules:
        strong_load_ctx.extend(r.get("load_context_patterns", []))
        weak_load_ctx.extend(r.get("weak_load_context_patterns", []))
        lib_path.extend(r.get("library_path_patterns", []))
        url.extend(r.get("url_patterns", []))

    out: dict[str, Any] = {
        "safe_keys": safe_keys,
        "strong_load_context": _compile_patterns(strong_load_ctx, "external_load_rules.load_context"),
        "weak_load_context": _compile_patterns(weak_load_ctx, "external_load_rules.weak_load_context"),
        "lib_path": _compile_patterns(lib_path, "external_load_rules.library_path"),
        "url": _compile_patterns(url, "external_load_rules.url"),
        "command": _compile_patterns(
            sum((r.get("patterns", []) for r in rules.get("command_rules", [])), []),
            "command_rules",
        ),
        "network": _compile_patterns(
            sum(
                (r.get("network_patterns", []) for r in rules.get("command_rules", []) if "network_patterns" in r),
                [],
            ),
            "command_rules.network",
        ),
        "eval": _compile_patterns(
            sum((r.get("patterns", []) for r in rules.get("eval_rules", [])), []),
            "eval_rules",
        ),
        "base64": re.compile(r"\b[A-Za-z0-9+/]{80,}={0,2}\b"),
        "decode_ctx": _compile_patterns(
            sum((r.get("decode_context_patterns", []) for r in rules.get("obfuscation_rules", [])), []),
            "obfuscation_rules.decode",
        ),
        "exec_ctx": _compile_patterns(
            sum((r.get("exec_context_patterns", []) for r in rules.get("obfuscation_rules", [])), []),
            "obfuscation_rules.exec",
        ),
        "native_exec": _compile_patterns(
            sum((r.get("patterns", []) for r in rules.get("native_exec_rules", [])), []),
            "native_exec_rules",
        ),
        "persistence": _compile_patterns(
            sum((r.get("patterns", []) for r in rules.get("persistence_rules", [])), []),
            "persistence_rules",
        ),
        "http_fetch": _compile_patterns(
            sum((r.get("patterns", []) for r in rules.get("http_fetch_rules", [])), []),
            "http_fetch_rules",
        ),
        "obf_advanced": _compile_patterns(
            sum((r.get("patterns", []) for r in rules.get("obfuscation_advanced_rules", [])), []),
            "obfuscation_advanced_rules",
        ),
        "crypto_miner": _compile_patterns(
            sum((r.get("patterns", []) for r in rules.get("crypto_miner_rules", [])), []),
            "crypto_miner_rules",
        ),
        "min_signal_for_correlation": (
            rules.get("correlation_rules", [{}])[0].get("min_signal_categories", 2)
        ),
    }
    return out


def _read_prefix(path: Path, limit: int = _MAX_SIGNATURE_BYTES) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(limit)
    except OSError:
        return b""


def _read_bounded(path: Path, limit: int) -> tuple[bytes, bool]:
    try:
        with open(path, "rb") as fh:
            data = fh.read(limit + 1)
        return data[:limit], len(data) > limit
    except OSError:
        return b"", False


def _detect_variant(prefix: bytes, ext: str) -> tuple[str, str]:
    if ext not in {".dnn", ".cmf"}:
        return "not_cntk", "extension_not_cntk"
    if prefix.startswith(_CNTK_LEGACY_MAGIC):
        if _CNTK_LEGACY_VERSION_MARKER in prefix:
            return "legacy_v1", "bcn_bversion_markers_found"
        return "unsupported", "legacy_magic_without_bversion"
    has_core = all(m in prefix for m in _CNTK_V2_REQUIRED_MARKERS)
    if has_core:
        if any(m in prefix for m in _CNTK_V2_STRUCTURE_MARKERS):
            return "cntk_v2", "protobuf_core_and_structure_markers"
        return "unsupported", "protobuf_core_without_structure"
    return "not_cntk", "no_cntk_markers"


def _extract_strings(data: bytes) -> list[str]:
    candidates: list[str] = []
    seen: set[str] = set()
    for m in _ASCII_STRING_RE.finditer(data):
        text = m.group(0).decode("utf-8", "ignore").strip()
        if text and text not in seen:
            seen.add(text)
            candidates.append(text)
            if len(candidates) >= _MAX_EXTRACTED_STRINGS:
                return candidates
    for m in _UTF16LE_STRING_RE.finditer(data):
        text = m.group(0)[::2].decode("ascii", "ignore").strip()
        if text and text not in seen:
            seen.add(text)
            candidates.append(text)
            if len(candidates) >= _MAX_EXTRACTED_STRINGS:
                break
    return candidates


def _snippet(text: str, max_len: int = 180) -> str:
    normalized = re.sub(r"\s+", " ", text).strip()
    return normalized if len(normalized) <= max_len else normalized[: max_len - 3] + "..."


def _is_safe_metadata(text: str, safe_keys: frozenset[str]) -> bool:
    lowered = text.lower().strip()
    if lowered in safe_keys:
        return True
    return bool(re.fullmatch(r"(?:parameter|placeholder|times|plus|compositefunction)\d+", lowered))


def _collect_split_load_references(
    strings: list[str],
    safe_keys: frozenset[str],
    r: dict[str, Any],
) -> list[str]:
    """Cross-string split-signal: strong load context in string A, lib path in string B."""
    load_ctx_examples: list[str] = []
    lib_ref_examples: list[str] = []

    for text in strings:
        if _is_safe_metadata(text, safe_keys):
            continue
        has_strong = any(p.search(text) for p in r["strong_load_context"])
        has_lib = any(p.search(text) for p in r["lib_path"])
        if has_strong and not has_lib and len(load_ctx_examples) < _MAX_EVIDENCE_PER_CATEGORY:
            load_ctx_examples.append(_snippet(text))
        if has_lib and not has_strong and len(lib_ref_examples) < _MAX_EVIDENCE_PER_CATEGORY:
            lib_ref_examples.append(_snippet(text))

    if not load_ctx_examples or not lib_ref_examples:
        return []

    evidence: list[str] = []
    for ctx, lib in zip(load_ctx_examples, lib_ref_examples):
        evidence.append(f"context={ctx}; library_reference={lib}")
        if len(evidence) >= _MAX_EVIDENCE_PER_CATEGORY:
            break
    return evidence


class CNTKScanner:
    """Scanner for Microsoft Cognitive Toolkit (CNTK) model files (.dnn, .cmf).

    Detection rules are loaded from rules/cntk_rules.yaml v2.0. Performs:
      - Format variant detection (legacy v1 / CNTKv2 protobuf)
      - Structural integrity minimum-byte guard per variant
      - Bounded printable-string extraction (ASCII + UTF-16LE)
      - External native library load — same-string AND cross-string split-signal
      - Two-tier load context (strong explicit vs weak module/library/ctypes)
      - Command + network/eval execution correlation
      - Obfuscated Base64 payload (decode OR exec OR command context)
      - Direct eval/exec/__import__ detection
      - Native code execution via ctypes/cffi
      - Persistence mechanisms (schtasks, registry, cron)
      - HTTP fetch call detection
      - Advanced obfuscation (PS -EncodedCommand, hex shellcode)
      - Crypto-miner indicators
      - Multi-signal correlation escalation when ≥2 categories fire
    """

    EXTENSIONS = frozenset({".cntk", ".dnn", ".cmf"})

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        if not path.exists() or path.suffix.lower() not in self.EXTENSIONS:
            return findings

        prefix = _read_prefix(path)
        ext = path.suffix.lower()
        variant, variant_reason = _detect_variant(prefix, ext)

        if variant == "not_cntk":
            return findings

        if variant == "unsupported":
            findings.append(Finding.artifact(
                rule_id="CNTK-000",
                title="Unsupported CNTK variant",
                description=(
                    f"File has CNTK-like markers but variant cannot be confirmed "
                    f"({variant_reason}). Scan aborted to avoid false positives."
                ),
                severity=Severity.LOW,
                target=filepath,
                evidence=variant_reason,
            ))
            return findings

        data, truncated = _read_bounded(path, _MAX_SCAN_BYTES)
        if not data:
            findings.append(Finding.artifact(
                rule_id="CNTK-000",
                title="Cannot read CNTK file",
                description="File is unreadable or empty.",
                severity=Severity.LOW,
                target=filepath,
            ))
            return findings

        min_bytes = _LEGACY_V1_MIN_BYTES if variant == "legacy_v1" else _CNTK_V2_MIN_BYTES
        if len(data) < min_bytes:
            findings.append(Finding.artifact(
                rule_id="CNTK-STRUCT",
                title="CNTK file appears truncated or structurally incomplete",
                description=(
                    f"CNTK {variant} file is only {len(data)} bytes "
                    f"(minimum expected: {min_bytes}). File may be corrupted."
                ),
                severity=Severity.LOW,
                target=filepath,
                evidence=f"variant={variant}, bytes={len(data)}, min={min_bytes}",
            ))
            return findings

        if truncated:
            findings.append(Finding.artifact(
                rule_id="CNTK-TRUNC",
                title="CNTK scan truncated — bounded read limit reached",
                description=(
                    f"File exceeds the {_MAX_SCAN_BYTES // (1024 * 1024)} MB scan budget. "
                    "Strings beyond this offset were not inspected."
                ),
                severity=Severity.LOW,
                target=filepath,
                evidence=f"max_scan_bytes={_MAX_SCAN_BYTES}",
            ))

        strings = _extract_strings(data)
        r = _compiled_rules()
        safe_keys: frozenset[str] = r["safe_keys"]

        evidence: dict[str, list[str]] = {
            "external_load": [],
            "command_network": [],
            "obfuscated_payload": [],
            "eval_exec": [],
            "native_exec": [],
            "persistence": [],
            "http_fetch": [],
            "obf_advanced": [],
            "crypto_miner": [],
        }

        for text in strings:
            if _is_safe_metadata(text, safe_keys):
                continue
            self._check_external_load(text, evidence, r)
            self._check_command_network(text, evidence, r)
            self._check_obfuscated_payload(text, evidence, r)
            self._check_eval_exec(text, evidence, r)
            self._check_native_exec(text, evidence, r)
            self._check_persistence(text, evidence, r)
            self._check_http_fetch(text, evidence, r)
            self._check_obf_advanced(text, evidence, r)
            self._check_crypto_miner(text, evidence, r)

        if not evidence["external_load"]:
            split_evidence = _collect_split_load_references(strings, safe_keys, r)
            evidence["external_load"].extend(split_evidence)

        findings.extend(self._emit_findings(evidence, filepath, variant))
        return findings

    def _check_external_load(
        self, text: str, evidence: dict[str, list[str]], r: dict[str, Any]
    ) -> None:
        if len(evidence["external_load"]) >= _MAX_EVIDENCE_PER_CATEGORY:
            return
        has_strong = any(p.search(text) for p in r["strong_load_context"])
        has_weak = any(p.search(text) for p in r["weak_load_context"])
        has_lib = any(p.search(text) for p in r["lib_path"])
        has_url = any(p.search(text) for p in r["url"])
        if (has_strong or has_weak) and has_lib:
            evidence["external_load"].append(_snippet(text))
            return
        if has_url and (has_strong or has_weak):
            evidence["external_load"].append(_snippet(text))

    def _check_command_network(
        self, text: str, evidence: dict[str, list[str]], r: dict[str, Any]
    ) -> None:
        if len(evidence["command_network"]) >= _MAX_EVIDENCE_PER_CATEGORY:
            return
        if not any(p.search(text) for p in r["command"]):
            return
        has_net = any(p.search(text) for p in r["network"])
        has_ip = bool(re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))
        has_eval = any(p.search(text) for p in r["eval"])
        if has_net or has_ip or has_eval:
            evidence["command_network"].append(_snippet(text))

    def _check_obfuscated_payload(
        self, text: str, evidence: dict[str, list[str]], r: dict[str, Any]
    ) -> None:
        if len(evidence["obfuscated_payload"]) >= _MAX_EVIDENCE_PER_CATEGORY:
            return
        if not r["base64"].search(text):
            return
        has_decode = any(p.search(text) for p in r["decode_ctx"])
        has_exec = any(p.search(text) for p in r["exec_ctx"])
        has_cmd = any(p.search(text) for p in r["command"])
        if has_decode or has_exec or has_cmd:
            evidence["obfuscated_payload"].append(_snippet(text))

    def _check_eval_exec(
        self, text: str, evidence: dict[str, list[str]], r: dict[str, Any]
    ) -> None:
        if len(evidence["eval_exec"]) >= _MAX_EVIDENCE_PER_CATEGORY:
            return
        if any(p.search(text) for p in r["eval"]):
            evidence["eval_exec"].append(_snippet(text))

    def _check_native_exec(
        self, text: str, evidence: dict[str, list[str]], r: dict[str, Any]
    ) -> None:
        if len(evidence["native_exec"]) >= _MAX_EVIDENCE_PER_CATEGORY:
            return
        if any(p.search(text) for p in r["native_exec"]):
            evidence["native_exec"].append(_snippet(text))

    def _check_persistence(
        self, text: str, evidence: dict[str, list[str]], r: dict[str, Any]
    ) -> None:
        if len(evidence["persistence"]) >= _MAX_EVIDENCE_PER_CATEGORY:
            return
        if any(p.search(text) for p in r["persistence"]):
            evidence["persistence"].append(_snippet(text))

    def _check_http_fetch(
        self, text: str, evidence: dict[str, list[str]], r: dict[str, Any]
    ) -> None:
        if len(evidence["http_fetch"]) >= _MAX_EVIDENCE_PER_CATEGORY:
            return
        if any(p.search(text) for p in r["http_fetch"]):
            evidence["http_fetch"].append(_snippet(text))

    def _check_obf_advanced(
        self, text: str, evidence: dict[str, list[str]], r: dict[str, Any]
    ) -> None:
        if len(evidence["obf_advanced"]) >= _MAX_EVIDENCE_PER_CATEGORY:
            return
        if any(p.search(text) for p in r["obf_advanced"]):
            evidence["obf_advanced"].append(_snippet(text))

    def _check_crypto_miner(
        self, text: str, evidence: dict[str, list[str]], r: dict[str, Any]
    ) -> None:
        if len(evidence["crypto_miner"]) >= _MAX_EVIDENCE_PER_CATEGORY:
            return
        if any(p.search(text) for p in r["crypto_miner"]):
            evidence["crypto_miner"].append(_snippet(text))

    def _emit_findings(
        self,
        evidence: dict[str, list[str]],
        filepath: str,
        variant: str,
    ) -> list[Finding]:
        findings: list[Finding] = []

        category_meta: dict[str, tuple[str, str, Severity, list[str]]] = {
            "external_load": (
                "CNTK-EXT-001",
                "External native library / URL load reference in CNTK model",
                Severity.CRITICAL,
                ["CWE-114", "CWE-506"],
            ),
            "command_network": (
                "CNTK-CMD-002",
                "Command + network/eval execution correlation in CNTK model",
                Severity.CRITICAL,
                ["CWE-78", "CWE-200"],
            ),
            "obfuscated_payload": (
                "CNTK-OBF-001",
                "Base64-encoded payload with decode/exec/command context in CNTK model",
                Severity.CRITICAL,
                ["CWE-506", "CWE-94"],
            ),
            "eval_exec": (
                "CNTK-EVAL-001",
                "Direct eval/exec/__import__ call in CNTK model metadata",
                Severity.CRITICAL,
                ["CWE-94"],
            ),
            "native_exec": (
                "CNTK-NATIVE-001",
                "Native code execution via ctypes/cffi in CNTK model",
                Severity.CRITICAL,
                ["CWE-114", "CWE-94"],
            ),
            "persistence": (
                "CNTK-PERSIST-001",
                "Persistence mechanism string in CNTK model metadata",
                Severity.CRITICAL,
                ["CWE-912", "CWE-78"],
            ),
            "http_fetch": (
                "CNTK-FETCH-001",
                "HTTP fetch call in CNTK model metadata",
                Severity.HIGH,
                ["CWE-494", "CWE-829"],
            ),
            "obf_advanced": (
                "CNTK-OBF-002",
                "Advanced obfuscation (PowerShell encoded command / hex shellcode) in CNTK model",
                Severity.CRITICAL,
                ["CWE-506", "CWE-94"],
            ),
            "crypto_miner": (
                "CNTK-MINER-001",
                "Crypto-miner indicator in CNTK model metadata",
                Severity.HIGH,
                ["CWE-506"],
            ),
        }

        signal_count = sum(1 for v in evidence.values() if v)

        for category, snippets in evidence.items():
            if not snippets:
                continue
            rule_id, title, severity, cwe_ids = category_meta[category]
            findings.append(Finding.artifact(
                rule_id=rule_id,
                title=title,
                description=(
                    f"CNTK variant: {variant}. "
                    f"Suspicious signal category: {category.replace('_', ' ')}. "
                    f"Evidence: {snippets[0]}"
                ),
                severity=severity,
                target=filepath,
                evidence="; ".join(snippets[:3]),
                cwe_ids=cwe_ids,
            ))

        r = _compiled_rules()
        if signal_count >= r.get("min_signal_for_correlation", 2):
            active = sorted(k for k, v in evidence.items() if v)
            findings.append(Finding.artifact(
                rule_id="CNTK-MULTI-001",
                title="Multiple independent suspicious signals in CNTK model",
                description=(
                    f"CNTK variant {variant} contains {signal_count} independent "
                    f"suspicious signal categories: {', '.join(active)}. "
                    "Multiple independent signals strongly indicate a backdoored model."
                ),
                severity=Severity.CRITICAL,
                target=filepath,
                evidence=f"categories={active}",
                cwe_ids=["CWE-506", "CWE-94", "CWE-78"],
            ))

        return findings
