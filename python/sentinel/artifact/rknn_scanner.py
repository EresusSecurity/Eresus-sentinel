"""Rockchip RKNN model format scanner (.rknn).

Detection rules are loaded from rules/rknn_rules.yaml at import time.
Covers:
  - RKNN magic header validation (first 4 bytes == b"RKNN")
  - Structural magic count anomaly detection (>2 standalone RKNN headers)
  - Bounded printable-string extraction
  - Absolute path / path-traversal / URL reference detection
  - Command execution indicator detection
  - Command + network execution correlation (CRITICAL)
  - Public IP address extraction and correlation
  - Obfuscated Base64 payload detection (triple-signal)
"""
from __future__ import annotations

import ipaddress
import re
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from sentinel.finding import Finding, Severity

logger = logging.getLogger(__name__)

_RULES_PATH = Path(__file__).parent.parent.parent.parent / "rules" / "rknn_rules.yaml"

_RKNN_MAGIC = b"RKNN"
_MIN_SIZE = 16
_MAX_SIGNATURE_BYTES = 64
_MAX_PRINTABLE_RUN = 512
_MIN_PRINTABLE_RUN = 6
_PRINTABLE_RE = re.compile(rb"[ -~]{6,512}")


@lru_cache(maxsize=1)
def _load_rules() -> dict[str, Any]:
    try:
        with open(_RULES_PATH, "r") as fh:
            return yaml.safe_load(fh) or {}
    except Exception as exc:
        logger.warning("rknn_rules.yaml not loaded: %s", exc)
        return {}


def _compile(patterns: list[str]) -> list[re.Pattern[str]]:
    out = []
    for p in patterns:
        try:
            out.append(re.compile(p, re.IGNORECASE))
        except re.error as e:
            logger.debug("rknn_rules: bad pattern %r: %s", p, e)
    return out


@lru_cache(maxsize=1)
def _compiled_rules() -> dict[str, Any]:
    rules = _load_rules()
    limits = rules.get("limits", {})
    path_r = rules.get("path_rules", [])
    cmd_r = rules.get("command_rules", [])
    obf_r = rules.get("obfuscation_rules", [])

    safe_keys = frozenset(k.lower() for k in rules.get("safe_metadata_keys", []))

    trav_pats = [r.get("traversal_pattern") for r in path_r if r.get("traversal_pattern")]
    url_pats = [r.get("url_pattern") for r in path_r if r.get("url_pattern")]
    real_fs_prefixes = list(rules.get("path_rules", [{}])[0].get("real_fs_prefixes", []))
    win_drive_pat = rules.get("path_rules", [{}])[0].get("windows_drive_pattern", r"^[a-zA-Z]:[\\\/]")
    min_tilde_len = int(rules.get("path_rules", [{}])[0].get("min_length_for_tilde", 8))

    cmd_pats = sum((r.get("patterns", []) for r in cmd_r if "network_patterns" not in r), [])
    net_pats = sum((r.get("network_patterns", []) for r in cmd_r if "network_patterns" in r), [])

    b64_min = next((r.get("base64_min_length", 96) for r in obf_r), 96)
    decode_pats = sum((r.get("decode_patterns", []) for r in obf_r), [])
    exec_pats = sum((r.get("exec_patterns", []) for r in obf_r), [])

    return {
        "max_scan_bytes": int(limits.get("max_scan_bytes", 12 * 1024 * 1024)),
        "max_strings": int(limits.get("max_extracted_strings", 4000)),
        "max_evidence": int(limits.get("max_evidence_per_category", 10)),
        "safe_keys": safe_keys,
        "traversal": _compile(trav_pats),
        "url": _compile(url_pats),
        "real_fs_prefixes": real_fs_prefixes,
        "win_drive": re.compile(win_drive_pat, re.IGNORECASE),
        "min_tilde_len": min_tilde_len,
        "command": _compile(cmd_pats),
        "network": _compile(net_pats),
        "ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b"),
        "b64": re.compile(rf"\b[A-Za-z0-9+/]{{{b64_min},}}={{0,2}}\b"),
        "decode_ctx": _compile(decode_pats),
        "exec_ctx": _compile(exec_pats),
        "max_struct_magic": int(rules.get("magic", {}).get("structural_magic_max", {}).get("max_count", 2)),
    }


def _count_struct_magic(payload: bytes) -> int:
    alnum_under = frozenset(
        b"_"
        + bytes(range(ord("A"), ord("Z") + 1))
        + bytes(range(ord("a"), ord("z") + 1))
        + bytes(range(ord("0"), ord("9") + 1))
    )
    count = 0
    idx = 0
    while True:
        pos = payload.find(_RKNN_MAGIC, idx)
        if pos == -1:
            break
        before_ok = pos == 0 or payload[pos - 1] not in alnum_under
        after_pos = pos + 4
        after_ok = after_pos >= len(payload) or payload[after_pos] not in alnum_under
        if before_ok and after_ok:
            count += 1
        idx = pos + 4
    return count


def _extract_strings(payload: bytes, max_strings: int) -> list[str]:
    results: list[str] = []
    seen: set[str] = set()
    for m in _PRINTABLE_RE.finditer(payload):
        text = m.group(0).decode("ascii", "ignore").strip()
        if text and text not in seen:
            seen.add(text)
            results.append(text)
            if len(results) >= max_strings:
                break
    return results


def _is_public_ip(candidate: str) -> bool:
    candidate = candidate.split(":")[0]
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast)


def _is_safe_string(text: str, safe_keys: frozenset[str]) -> bool:
    if "=" not in text:
        return False
    key = text.split("=", 1)[0].strip().lower()
    return key in safe_keys


def _snippet(text: str, max_chars: int = 180) -> str:
    normalized = re.sub(r"\s+", " ", text).strip()
    return normalized if len(normalized) <= max_chars else normalized[: max_chars - 3] + "..."


class RKNNScanner:
    """Scanner for Rockchip Neural Network (.rknn) model files.

    Detection rules are loaded from rules/rknn_rules.yaml. Performs:
      - RKNN magic header validation
      - Structural integrity check (anomalous standalone RKNN marker count)
      - Bounded printable-string extraction
      - Absolute path / path-traversal / URL reference detection
      - Command execution indicator detection
      - Command + network / public IP correlation (CRITICAL)
      - Obfuscated Base64 payload detection (triple-signal: b64 + decode + exec)
    """

    EXTENSIONS = frozenset({".rknn"})

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        if not path.exists() or path.suffix.lower() not in self.EXTENSIONS:
            return findings

        try:
            file_size = path.stat().st_size
        except OSError:
            return findings

        if file_size < _MIN_SIZE:
            findings.append(Finding.artifact(
                rule_id="RKNN-STRUCT-001",
                title="RKNN file too small — structurally incomplete",
                description=f"File is only {file_size} bytes; minimum valid RKNN size is {_MIN_SIZE} bytes.",
                severity=Severity.MEDIUM,
                target=filepath,
            ))
            return findings

        r = _compiled_rules()
        max_scan = r["max_scan_bytes"]

        try:
            with open(path, "rb") as fh:
                raw = fh.read(max_scan + 1)
        except OSError:
            return findings

        truncated = len(raw) > max_scan
        payload = raw[:max_scan]

        if truncated:
            findings.append(Finding.artifact(
                rule_id="RKNN-TRUNC",
                title="RKNN scan truncated — bounded read limit reached",
                description=(
                    f"File exceeds the {max_scan // (1024 * 1024)} MB scan budget. "
                    "Strings beyond this offset were not inspected."
                ),
                severity=Severity.LOW,
                target=filepath,
                evidence=f"max_scan_bytes={max_scan}",
            ))

        findings.extend(self._check_header(payload, filepath))
        if any(f.rule_id == "RKNN-HDR-001" for f in findings):
            return findings

        findings.extend(self._check_structural_integrity(payload, filepath, r))

        strings = _extract_strings(payload, r["max_strings"])
        safe_keys: frozenset[str] = r["safe_keys"]

        path_hits: list[str] = []
        cmd_hits: list[str] = []
        cmd_net_hits: list[str] = []
        obf_hits: list[str] = []

        for text in strings:
            if _is_safe_string(text, safe_keys):
                continue
            self._collect_path_hits(text, r, path_hits)
            self._collect_command_hits(text, r, cmd_hits, cmd_net_hits)
            self._collect_obfuscation_hits(text, r, obf_hits)

        findings.extend(self._emit_path_findings(path_hits, filepath, r))
        findings.extend(self._emit_command_findings(cmd_hits, cmd_net_hits, filepath, r))
        findings.extend(self._emit_obfuscation_findings(obf_hits, filepath))
        return findings

    def _check_header(self, payload: bytes, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        if not payload[:4] == _RKNN_MAGIC:
            findings.append(Finding.artifact(
                rule_id="RKNN-HDR-001",
                title="Invalid RKNN magic bytes",
                description=(
                    f"Expected magic bytes 0x524B4E4E (RKNN), "
                    f"got 0x{payload[:4].hex().upper()}. "
                    "File is either corrupted, misidentified, or maliciously crafted."
                ),
                severity=Severity.HIGH,
                target=filepath,
                evidence=f"actual_magic=0x{payload[:4].hex()}",
            ))
        return findings

    def _check_structural_integrity(
        self, payload: bytes, filepath: str, r: dict[str, Any]
    ) -> list[Finding]:
        findings: list[Finding] = []
        count = _count_struct_magic(payload)
        max_allowed = r["max_struct_magic"]
        if count > max_allowed:
            findings.append(Finding.artifact(
                rule_id="RKNN-STRUCT-002",
                title="Anomalous structural RKNN magic count — possible tampering",
                description=(
                    f"Found {count} standalone RKNN structural markers; "
                    f"legitimate files have at most {max_allowed}. "
                    "Extra markers may indicate a tampered or composite payload."
                ),
                severity=Severity.HIGH,
                target=filepath,
                evidence=f"structural_magic_count={count}",
            ))
        return findings

    def _collect_path_hits(
        self, text: str, r: dict[str, Any], hits: list[str]
    ) -> None:
        max_ev = r["max_evidence"]
        if len(hits) >= max_ev:
            return
        for pat in r["traversal"]:
            if pat.search(text):
                hits.append(_snippet(text))
                return
        if text.startswith("~/") and len(text) < r["min_tilde_len"]:
            return
        for prefix in r["real_fs_prefixes"]:
            if text.startswith(prefix):
                hits.append(_snippet(text))
                return
        if r["win_drive"].search(text):
            hits.append(_snippet(text))
            return
        for pat in r["url"]:
            if pat.search(text):
                hits.append(_snippet(text))
                return

    def _collect_command_hits(
        self, text: str, r: dict[str, Any], cmd_hits: list[str], cmd_net_hits: list[str]
    ) -> None:
        max_ev = r["max_evidence"]
        if not any(p.search(text) for p in r["command"]):
            return
        snippet = _snippet(text)
        has_net = any(p.search(text) for p in r["network"])
        has_url = any(p.search(text) for p in r["url"])
        ip_candidates = r["ip"].findall(text)
        has_public_ip = any(_is_public_ip(ip) for ip in ip_candidates)
        if (has_net or has_url or has_public_ip) and len(cmd_net_hits) < max_ev:
            cmd_net_hits.append(snippet)
        elif len(cmd_hits) < max_ev:
            cmd_hits.append(snippet)

    def _collect_obfuscation_hits(
        self, text: str, r: dict[str, Any], hits: list[str]
    ) -> None:
        if len(hits) >= r["max_evidence"]:
            return
        if not r["b64"].search(text):
            return
        if not any(p.search(text) for p in r["decode_ctx"]):
            return
        if not any(p.search(text) for p in r["exec_ctx"]):
            return
        hits.append(_snippet(text))

    def _emit_path_findings(
        self, hits: list[str], filepath: str, r: dict[str, Any]
    ) -> list[Finding]:
        if not hits:
            return []
        return [Finding.artifact(
            rule_id="RKNN-PATH-001",
            title="Suspicious file/URL references in RKNN model metadata",
            description=(
                "Absolute filesystem paths, traversal sequences, or URLs were found "
                "in extracted RKNN string metadata. These may indicate training-environment "
                "leakage, path traversal precursors, or remote resource fetching at inference."
            ),
            severity=Severity.HIGH,
            target=filepath,
            evidence="; ".join(hits[:5]),
            cwe_ids=["CWE-200", "CWE-22", "CWE-494"],
        )]

    def _emit_command_findings(
        self, cmd_hits: list[str], cmd_net_hits: list[str], filepath: str, r: dict[str, Any]
    ) -> list[Finding]:
        findings: list[Finding] = []
        if cmd_net_hits:
            findings.append(Finding.artifact(
                rule_id="RKNN-CMD-002",
                title="Command + network execution correlation in RKNN model",
                description=(
                    "A command-execution keyword was found alongside a network indicator "
                    "or public IP address in the same extracted RKNN string. This high-confidence "
                    "combination strongly suggests a C2 callback or exfiltration mechanism."
                ),
                severity=Severity.CRITICAL,
                target=filepath,
                evidence="; ".join(cmd_net_hits[:5]),
                cwe_ids=["CWE-78", "CWE-200"],
            ))
        elif cmd_hits:
            findings.append(Finding.artifact(
                rule_id="RKNN-CMD-001",
                title="Command execution indicator in RKNN model metadata",
                description=(
                    "A shell command execution keyword was found in extracted RKNN string data. "
                    "RKNN custom operators can invoke host-side code at inference time."
                ),
                severity=Severity.HIGH,
                target=filepath,
                evidence="; ".join(cmd_hits[:5]),
                cwe_ids=["CWE-78"],
            ))
        return findings

    def _emit_obfuscation_findings(
        self, hits: list[str], filepath: str
    ) -> list[Finding]:
        if not hits:
            return []
        return [Finding.artifact(
            rule_id="RKNN-OBF-001",
            title="Encoded payload with decode+exec context in RKNN model",
            description=(
                "A long Base64-like blob was found alongside both a decode keyword and an "
                "exec/import keyword. This triple-signal is characteristic of stage-2 payload "
                "delivery embedded in model weights."
            ),
            severity=Severity.CRITICAL,
            target=filepath,
            evidence="; ".join(hits[:5]),
            cwe_ids=["CWE-506", "CWE-94"],
        )]
