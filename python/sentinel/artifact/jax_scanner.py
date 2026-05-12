"""JAX / Orbax checkpoint scanner (.jax, .checkpoint, .orbax-checkpoint).

Detection rules are loaded from rules/jax_rules.yaml at import time.
Covers:
  - JAX indicator-based file routing (jax/flax/haiku/orbax/jaxlib keywords)
  - Directory-based Orbax checkpoint detection
  - Orbax metadata JSON analysis (restore_fn, pattern scanning)
  - Pickle-format detection in JAX context (anomalous serialization)
  - Pickle GLOBAL/INST opcode enumeration against a dangerous-globals list
    (loaded from YAML — 80+ dangerous module.function pairs)
  - JAX-specific suspicious pattern matching (host_callback, io_callback,
    debug.callback, lax.cond+exec, jit+subprocess, pmap+os.system)
  - Anomalous .pkl files inside Orbax checkpoint directories
  - Bounded string extraction and metadata traversal depth cap
"""
from __future__ import annotations

import json
import logging
import pickletools
import re
from collections import OrderedDict
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from sentinel.finding import Finding, Severity

logger = logging.getLogger(__name__)

_RULES_PATH = Path(__file__).parent.parent.parent.parent / "rules" / "jax_rules.yaml"

_PICKLE_PROTO_MAGIC = frozenset({b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"})
_PICKLE_TEXT_OPCODES = frozenset(b"(cdgINRSUV")
_UTF8_BOM = b"\xef\xbb\xbf"

_MAX_METADATA_DEPTH = 64
_MAX_PATTERN_FINDINGS = 256
_MAX_PICKLE_SCAN_BYTES = 16 * 1024 * 1024
_MAX_PICKLE_OPCODE_FINDINGS = 256
_STACK_LIMIT = 4096
_MEMO_LIMIT = 4096
_CHUNK_BYTES = 8192


@lru_cache(maxsize=1)
def _load_rules() -> dict[str, Any]:
    try:
        with open(_RULES_PATH, "r") as fh:
            return yaml.safe_load(fh) or {}
    except Exception as exc:
        logger.warning("jax_rules.yaml not loaded: %s", exc)
        return {}


@lru_cache(maxsize=1)
def _dangerous_globals() -> frozenset[tuple[str, str]]:
    rules = _load_rules()
    pairs = rules.get("dangerous_pickle_globals", [])
    result: set[tuple[str, str]] = set()
    for pair in pairs:
        if isinstance(pair, list) and len(pair) == 2:
            result.add((str(pair[0]).lower(), str(pair[1]).lower()))
    return frozenset(result)


@lru_cache(maxsize=1)
def _jax_indicators() -> tuple[list[str], frozenset[str]]:
    rules = _load_rules()
    inds = rules.get("jax_indicators", {})
    positives: list[str] = inds.get("positive", [
        "jax", "flax", "haiku", "orbax", "arrayimpl", "jaxlib", "device_array",
    ])
    non_match: frozenset[str] = frozenset(inds.get("non_match_prefixes", ["a"]))
    return positives, non_match


@lru_cache(maxsize=1)
def _doc_context_keys() -> frozenset[str]:
    rules = _load_rules()
    return frozenset(rules.get("documentation_context_keys", [
        "description", "doc", "docs", "documentation",
        "comment", "comments", "note", "notes",
        "help", "readme", "example", "examples",
    ]))


@lru_cache(maxsize=1)
def _suspicious_patterns() -> list[tuple[str, re.Pattern[str], str, str, list[str]]]:
    """Return list of (rule_id, compiled_pattern, title, description, cwe_ids)."""
    rules = _load_rules()
    out = []
    for entry in rules.get("jax_suspicious_patterns", []):
        raw = entry.get("pattern") or entry.get("restore_fn_pattern")
        if not raw:
            continue
        try:
            out.append((
                entry.get("rule_id", "JAX-PAT"),
                re.compile(raw, re.IGNORECASE),
                entry.get("title", "Suspicious JAX pattern"),
                entry.get("description", ""),
                entry.get("cwe_ids", []),
            ))
        except re.error as exc:
            logger.debug("jax_rules: bad pattern %r: %s", raw, exc)
    return out


@lru_cache(maxsize=1)
def _orbax_metadata_files() -> list[str]:
    rules = _load_rules()
    return rules.get("orbax_checkpoint_files", [
        "checkpoint", "checkpoint_0", "metadata.json",
        "_CHECKPOINT", "orbax_checkpoint_metadata.json",
    ])


@lru_cache(maxsize=1)
def _orbax_glob_patterns() -> list[str]:
    rules = _load_rules()
    return rules.get("orbax_checkpoint_patterns", [
        "step_*", "params_*", "state_*", "model_*",
    ])


def _contains_jax_indicator(text: str) -> bool:
    indicators, non_match = _jax_indicators()
    lowered = text.lower()
    for indicator in indicators:
        start = 0
        while (idx := lowered.find(indicator, start)) != -1:
            prefix = lowered[idx - 1] if idx > 0 else ""
            if prefix not in non_match:
                return True
            start = idx + 1
    return False


def _file_has_jax_indicator(path: Path) -> bool:
    tail = ""
    _, non_match = _jax_indicators()
    indicators, _ = _jax_indicators()
    tail_len = max((len(i) for i in indicators), default=1) - 1
    try:
        with open(path, "rb") as fh:
            while chunk := fh.read(_CHUNK_BYTES):
                decoded = chunk.decode("utf-8", "ignore").lower()
                search = tail + decoded
                if _contains_jax_indicator(search):
                    return True
                tail = search[-tail_len:]
    except OSError:
        return False
    return False


def _header_is_json(header: bytes) -> bool:
    norm = header.lstrip()
    if norm.startswith(_UTF8_BOM):
        norm = norm[len(_UTF8_BOM):].lstrip()
    return norm.startswith((b"{", b"["))


def _is_likely_jax_file(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            header = fh.read(512)
        if header[:1] == b"\x80" or header[:1] in _PICKLE_TEXT_OPCODES:
            with open(path, "rb") as fh:
                data = fh.read(8192)
            return _contains_jax_indicator(data.decode("utf-8", "ignore").lower())
        if _header_is_json(header):
            return _contains_jax_indicator(header.decode("utf-8", "ignore").lower()) or _file_has_jax_indicator(path)
        if header.startswith(b"\x93NUMPY") and _contains_jax_indicator(str(path).lower()):
            return True
    except OSError:
        return False
    return False


def _is_orbax_dir(path: Path) -> bool:
    for fname in _orbax_metadata_files():
        if (path / fname).exists():
            return True
    return any(list(path.glob(pat)) for pat in _orbax_glob_patterns())


def _is_doc_context(context: str) -> bool:
    parts = [p for p in re.split(r"[.\[\]_\-]+", context.lower()) if p]
    return any(p in _doc_context_keys() for p in parts)


def _is_doc_text(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return True
    if any(tok in stripped for tok in ("(", ")", "'", '"', "`", ";", "|", "&", "$", "/", "\\")):
        return False
    return not re.search(
        r"(?<![A-Za-z0-9_])(?:os\.system|subprocess|eval|exec|import)(?![A-Za-z0-9_])",
        stripped,
        re.IGNORECASE,
    )


def _iter_string_meta(
    value: Any,
    context: str = "root",
    depth: int = 0,
    depth_cap: set[str] | None = None,
) -> list[tuple[str, str]]:
    if depth >= _MAX_METADATA_DEPTH:
        if depth_cap is not None:
            depth_cap.add(context)
        return []
    results = []
    if isinstance(value, str):
        results.append((context, value))
    elif isinstance(value, dict):
        for k, v in value.items():
            results.extend(_iter_string_meta(v, f"{context}.{k}", depth + 1, depth_cap))
    elif isinstance(value, (list, tuple, set)):
        for i, v in enumerate(value):
            results.extend(_iter_string_meta(v, f"{context}[{i}]", depth + 1, depth_cap))
    return results


def _scan_patterns_in_text(
    text: str,
    context: str,
    filepath: str,
    findings: list[Finding],
    finding_count: list[int],
) -> None:
    if _is_doc_context(context) and _is_doc_text(text):
        return
    for rule_id, pattern, title, description, cwe_ids in _suspicious_patterns():
        if finding_count[0] >= _MAX_PATTERN_FINDINGS:
            return
        if pattern.search(text):
            findings.append(Finding.artifact(
                rule_id=rule_id,
                title=title,
                description=description or f"Suspicious JAX pattern matched: {pattern.pattern}",
                severity=Severity.CRITICAL,
                target=filepath,
                evidence=f"context={context}; matched={pattern.pattern}",
                cwe_ids=cwe_ids,
            ))
            finding_count[0] += 1


def _analyze_pickle_globals(path: Path, data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    dangerous = _dangerous_globals()
    opcode_count = 0
    stack: list[Any] = []
    memo: OrderedDict[int, Any] = OrderedDict()

    def push(v: Any) -> None:
        stack.append(v)
        if len(stack) > _STACK_LIMIT:
            del stack[: -_STACK_LIMIT]

    def memoize(idx: int) -> None:
        if not stack:
            return
        v = stack[-1]
        if len(memo) >= _MEMO_LIMIT:
            try:
                memo.popitem(last=False)
            except KeyError:
                pass
        memo[idx] = v

    try:
        for opcode, arg, _ in pickletools.genops(data):
            name = opcode.name
            if name in ("GLOBAL", "INST"):
                ref = _parse_global_ref(str(arg) if arg is not None else "")
                if ref:
                    mod, sym = ref
                    push((mod, sym))
                    if (mod.lower(), sym.lower()) in dangerous:
                        if opcode_count < _MAX_PICKLE_OPCODE_FINDINGS:
                            findings.append(Finding.artifact(
                                rule_id="JAX-PKL-001",
                                title="Dangerous pickle GLOBAL in JAX checkpoint",
                                description=(
                                    f"Pickle GLOBAL opcode references {mod}.{sym} — "
                                    "a dangerous function that executes arbitrary code "
                                    "when the checkpoint is deserialized."
                                ),
                                severity=Severity.CRITICAL,
                                target=str(path),
                                evidence=f"{mod}.{sym}",
                                cwe_ids=["CWE-502", "CWE-94"],
                            ))
                            opcode_count += 1
            elif name in ("PUT", "BINPUT", "LONG_BINPUT"):
                try:
                    memoize(int(arg))
                except (TypeError, ValueError):
                    pass
            elif name in ("GET", "BINGET", "LONG_BINGET"):
                try:
                    v = memo.get(int(arg))
                    if v is not None:
                        push(v)
                except (TypeError, ValueError):
                    pass
    except Exception:
        pass

    return findings


def _parse_global_ref(arg: str) -> tuple[str, str] | None:
    normalized = arg.replace("\n", " ").strip()
    if not normalized:
        return None
    parts = normalized.split()
    if len(parts) < 2:
        return None
    return parts[0].strip(), " ".join(parts[1:]).strip()


class JAXCheckpointScanner:
    """Scanner for JAX/Orbax/Flax checkpoint files.

    Detection rules are loaded from rules/jax_rules.yaml. Performs:
      - JAX indicator-based file routing (content sniffing)
      - Orbax checkpoint directory detection and metadata analysis
      - Orbax restore_fn dangerous pattern matching
      - Full metadata string traversal with JAX suspicious pattern matching
        (host_callback, io_callback, debug.callback, lax.cond+exec, etc.)
      - Pickle-format anomaly detection in JAX context
      - Pickle GLOBAL/INST opcode enumeration (80+ dangerous globals)
      - Anomalous .pkl files inside Orbax directories
      - Bounded scan budget + traversal depth cap to avoid unbounded work
    """

    EXTENSIONS = frozenset({".jax", ".checkpoint", ".orbax-checkpoint", ".orbax", ".msgpack"})

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        if not path.exists():
            return findings

        ext = path.suffix.lower()

        if path.is_dir():
            if _is_orbax_dir(path):
                findings.extend(self._scan_orbax_dir(path))
            return findings

        if ext not in self.EXTENSIONS:
            return findings

        if not _is_likely_jax_file(path):
            return findings

        try:
            with open(path, "rb") as fh:
                header = fh.read(1024)
        except OSError:
            return findings

        if header[:1] == b"\x80" or header[:1] in _PICKLE_TEXT_OPCODES:
            findings.extend(self._scan_pickle_checkpoint(path))
        elif _header_is_json(header):
            findings.extend(self._scan_json_checkpoint(path))
        elif header.startswith(b"\x93NUMPY"):
            findings.extend(self._scan_numpy_checkpoint(path))

        return findings

    def _scan_orbax_dir(self, dir_path: Path) -> list[Finding]:
        findings: list[Finding] = []

        for meta_name in _orbax_metadata_files():
            meta_path = dir_path / meta_name
            if meta_path.exists() and meta_path.is_file():
                findings.extend(self._scan_json_checkpoint(meta_path))

        for pkl in dir_path.rglob("*.pkl"):
            findings.append(Finding.artifact(
                rule_id="JAX-PKL-002",
                title="Pickle file inside Orbax checkpoint directory",
                description=(
                    "Orbax checkpoints use msgpack/numpy natively. "
                    "A .pkl file inside the checkpoint directory is anomalous "
                    "and may carry an arbitrary code-execution payload."
                ),
                severity=Severity.HIGH,
                target=str(pkl),
                cwe_ids=["CWE-502"],
            ))
        for pkl in dir_path.rglob("*.pickle"):
            findings.append(Finding.artifact(
                rule_id="JAX-PKL-002",
                title="Pickle file inside Orbax checkpoint directory",
                description=(
                    "Orbax checkpoints use msgpack/numpy natively. "
                    "A .pickle file inside the checkpoint directory is anomalous "
                    "and may carry an arbitrary code-execution payload."
                ),
                severity=Severity.HIGH,
                target=str(pkl),
                cwe_ids=["CWE-502"],
            ))

        for ckpt_file in dir_path.glob("checkpoint*"):
            if ckpt_file.is_file():
                try:
                    with open(ckpt_file, "rb") as fh:
                        header = fh.read(16)
                    if header[:1] == b"\x80" or header[:1] in _PICKLE_TEXT_OPCODES:
                        findings.extend(self._scan_pickle_checkpoint(ckpt_file))
                except OSError:
                    pass

        return findings

    def _scan_json_checkpoint(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            with open(path, encoding="utf-8") as fh:
                metadata = json.load(fh)
        except json.JSONDecodeError as exc:
            findings.append(Finding.artifact(
                rule_id="JAX-META-001",
                title="Invalid JSON in JAX/Orbax metadata file",
                description=f"JSON parse error in {path.name}: {exc}",
                severity=Severity.MEDIUM,
                target=str(path),
                evidence=str(exc),
            ))
            return findings
        except OSError:
            return findings

        if isinstance(metadata, dict):
            restore_fn = metadata.get("restore_fn")
            if restore_fn is not None:
                findings.extend(self._check_restore_fn(str(restore_fn), str(path)))

        finding_count = [0]
        depth_cap: set[str] = set()
        for context, text in _iter_string_meta(metadata, "metadata", depth_cap=depth_cap):
            _scan_patterns_in_text(text, context, str(path), findings, finding_count)

        for ctx in sorted(depth_cap):
            findings.append(Finding.artifact(
                rule_id="JAX-META-002",
                title="Metadata traversal depth cap reached in JAX checkpoint",
                description=(
                    f"Metadata traversal stopped at context '{ctx}' "
                    f"(depth > {_MAX_METADATA_DEPTH}). "
                    "Deeply nested metadata was not scanned."
                ),
                severity=Severity.MEDIUM,
                target=str(path),
                evidence=f"context={ctx}, max_depth={_MAX_METADATA_DEPTH}",
            ))

        return findings

    def _check_restore_fn(self, restore_fn_value: str, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        dangerous_re = re.compile(
            r"\b(?:eval|exec|__import__|os\.system|os\.popen|subprocess\.(?:popen|run|call|check_call|check_output))\b",
            re.IGNORECASE,
        )
        is_dangerous = bool(dangerous_re.search(restore_fn_value))
        findings.append(Finding.artifact(
            rule_id="JAX-PAT-009",
            title=(
                "Dangerous restore_fn in Orbax metadata"
                if is_dangerous
                else "Custom restore_fn in Orbax metadata"
            ),
            description=(
                "The Orbax metadata contains a 'restore_fn' key. "
                + (
                    "Its value matches an eval/exec/os.system/subprocess pattern — "
                    "this function executes on checkpoint restore."
                    if is_dangerous
                    else "Custom restore functions can execute arbitrary code on restore."
                )
            ),
            severity=Severity.CRITICAL if is_dangerous else Severity.HIGH,
            target=filepath,
            evidence=restore_fn_value[:200],
            cwe_ids=["CWE-94", "CWE-502"],
        ))
        return findings

    def _scan_pickle_checkpoint(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []

        findings.append(Finding.artifact(
            rule_id="JAX-PKL-003",
            title="Pickle serialization in JAX checkpoint",
            description=(
                "JAX checkpoints normally use msgpack or numpy serialization. "
                "A pickle-format file in a JAX context is anomalous and enables "
                "arbitrary code execution via unsafe deserialization."
            ),
            severity=Severity.HIGH,
            target=str(path),
            cwe_ids=["CWE-502"],
        ))

        try:
            with open(path, "rb") as fh:
                data = fh.read(_MAX_PICKLE_SCAN_BYTES + 1)
        except OSError:
            return findings

        truncated = len(data) > _MAX_PICKLE_SCAN_BYTES
        data = data[:_MAX_PICKLE_SCAN_BYTES]

        if truncated:
            findings.append(Finding.artifact(
                rule_id="JAX-PKL-TRUNC",
                title="JAX pickle scan truncated — bounded read limit",
                description=(
                    f"Only the first {_MAX_PICKLE_SCAN_BYTES // (1024 * 1024)} MB of "
                    "the pickle checkpoint were inspected for opcode patterns."
                ),
                severity=Severity.LOW,
                target=str(path),
                evidence=f"max_pickle_scan_bytes={_MAX_PICKLE_SCAN_BYTES}",
            ))

        findings.extend(_analyze_pickle_globals(path, data))

        finding_count = [0]
        text = data.decode("utf-8", "ignore")
        _scan_patterns_in_text(text, "pickle_checkpoint", str(path), findings, finding_count)

        return findings

    def _scan_numpy_checkpoint(self, path: Path) -> list[Finding]:
        if not _contains_jax_indicator(str(path).lower()):
            return []
        return [Finding.artifact(
            rule_id="JAX-NPY-001",
            title="NumPy checkpoint in JAX context",
            description=(
                "A NumPy .npy file was found in a path suggesting JAX context. "
                "NumPy checkpoints can carry executable pickle payloads inside "
                "object arrays (allow_pickle=True risk)."
            ),
            severity=Severity.MEDIUM,
            target=str(path),
            cwe_ids=["CWE-502"],
        )]
