"""Scanner selection/exclusion + streaming + metadata extraction + Jinja2 + diagnostics."""
from __future__ import annotations

import logging
import platform
import re
import sys
from pathlib import Path

from sentinel.finding import Finding, Severity

logger = logging.getLogger(__name__)


# ── Scanner Selection ────────────────────────────────────────────────

class ScannerSelection:
    """Scanner selection/exclusion engine for --scanners/--exclude-scanner."""

    def __init__(self, include: list[str] | None = None, exclude: list[str] | None = None):
        self.include = set(include) if include else None
        self.exclude = set(exclude) if exclude else set()

    def is_enabled(self, scanner_id: str) -> bool:
        if scanner_id in self.exclude:
            return False
        if self.include is not None:
            return scanner_id in self.include
        return True

    def filter_scanners(self, scanners: dict[str, type]) -> dict[str, type]:
        return {k: v for k, v in scanners.items() if self.is_enabled(k)}

    @staticmethod
    def list_all() -> dict[str, list[str]]:
        from sentinel._plugins import list_all_plugins
        return list_all_plugins()


# ── Streaming Mode ───────────────────────────────────────────────────

class StreamingScanner:
    """File-at-a-time streaming scan coordinator."""

    def __init__(self, scan_fn, max_size: int = 0, dry_run: bool = False, cleanup: bool = True):
        self.scan_fn = scan_fn
        self.max_size = max_size
        self.dry_run = dry_run
        self.cleanup = cleanup

    def scan_files(self, file_paths: list[str]) -> list[Finding]:
        all_findings: list[Finding] = []
        for fp in file_paths:
            path = Path(fp)
            if self.max_size and path.exists() and path.stat().st_size > self.max_size:
                logger.warning("Skipping %s: exceeds max_size %d", fp, self.max_size)
                continue
            if self.dry_run:
                logger.info("DRY RUN: would scan %s", fp)
                continue
            try:
                findings = self.scan_fn(fp)
                all_findings.extend(findings)
            finally:
                if self.cleanup and path.exists():
                    try:
                        path.unlink()
                    except OSError:
                        pass
        return all_findings


# ── Metadata Extraction ─────────────────────────────────────────────

class MetadataExtractor:
    """Safe metadata extraction without deserialization."""

    def extract(self, filepath: str) -> dict:
        path = Path(filepath)
        if not path.exists():
            return {"error": "file not found"}
        meta = {
            "name": path.name, "size": path.stat().st_size,
            "format": path.suffix.lower(), "modified": path.stat().st_mtime,
        }
        try:
            data = path.read_bytes()[:4096]
            meta["magic_bytes"] = data[:8].hex()
            if path.suffix.lower() == ".safetensors":
                import json as _json
                header_size = int.from_bytes(data[:8], "little")
                if 8 < header_size < 100_000_000:
                    header = _json.loads(data[8:8+min(header_size, 4000)])
                    meta["tensors"] = len([k for k in header if k != "__metadata__"])
                    meta["metadata"] = header.get("__metadata__", {})
            elif path.suffix.lower() == ".gguf":
                if data[:4] == b"GGUF":
                    meta["gguf_version"] = int.from_bytes(data[4:8], "little")
        except Exception as e:
            meta["extraction_error"] = str(e)
        return meta


# ── Jinja2 Scanner ───────────────────────────────────────────────────

class Jinja2Scanner:
    """Jinja2 SSTI detection and unsafe filter analysis."""

    SSTI_PATTERNS = [
        re.compile(r"\{\{.*?__class__.*?\}\}"),
        re.compile(r"\{\{.*?__mro__.*?\}\}"),
        re.compile(r"\{\{.*?__subclasses__.*?\}\}"),
        re.compile(r"\{\{.*?__globals__.*?\}\}"),
        re.compile(r"\{\{.*?__builtins__.*?\}\}"),
        re.compile(r"\{\{.*?config.*?\}\}"),
        re.compile(r"\{\{.*?request\..*?\}\}"),
        re.compile(r"\{%.*?import.*?%\}"),
        re.compile(r"\{\{.*?lipsum.*?\}\}"),
        re.compile(r"\{\{.*?cycler.*?\}\}"),
        re.compile(r"\{\{.*?joiner.*?\}\}"),
        re.compile(r"\{\{.*?\|attr\(.*?\).*?\}\}"),
    ]
    UNSAFE_FILTERS = ["attr", "format", "map", "select", "reject", "groupby", "tojson"]

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        if not path.exists():
            return findings
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings

        for pat in self.SSTI_PATTERNS:
            for m in pat.finditer(text):
                findings.append(Finding.artifact(
                    rule_id="JINJA2-001", title="SSTI pattern in Jinja2 template",
                    description=f"Server-Side Template Injection: {m.group()[:80]}",
                    severity=Severity.CRITICAL, target=filepath,
                    evidence=m.group()[:200], cwe_ids=["CWE-1336"],
                ))
        for filt in self.UNSAFE_FILTERS:
            if f"|{filt}" in text or f"| {filt}" in text:
                findings.append(Finding.artifact(
                    rule_id="JINJA2-002", title=f"Unsafe Jinja2 filter: {filt}",
                    description=f"Filter '{filt}' can be exploited for SSTI",
                    severity=Severity.MEDIUM, target=filepath, evidence=filt,
                ))
        return findings


# ── Manifest & Model Card Scanner ────────────────────────────────────

class ManifestScanner:
    """Model manifest validation and integrity checking."""

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        if not path.exists():
            return findings
        if path.name in ("config.json", "model_index.json", "preprocessor_config.json"):
            self._scan_config_json(path, findings)
        elif path.name in ("README.md", "MODEL_CARD.md"):
            self._scan_model_card(path, findings)
        return findings

    def _scan_config_json(self, path: Path, findings: list[Finding]) -> None:
        import json
        try:
            data = json.loads(path.read_text())
        except Exception:
            findings.append(Finding.artifact(rule_id="MANIFEST-001", title="Invalid config JSON", description="Cannot parse", severity=Severity.MEDIUM, target=str(path)))
            return
        auto_map = data.get("auto_map", {})
        for key, val in auto_map.items():
            if isinstance(val, str) and ("--" in val or ".." in val):
                findings.append(Finding.artifact(rule_id="MANIFEST-002", title=f"Suspicious auto_map: {key}={val}", description="auto_map may reference malicious module", severity=Severity.HIGH, target=str(path), evidence=f"{key}={val}"))
        if data.get("trust_remote_code"):
            findings.append(Finding.artifact(rule_id="MANIFEST-003", title="trust_remote_code enabled", description="Config enables arbitrary remote code execution", severity=Severity.CRITICAL, target=str(path)))

    def _scan_model_card(self, path: Path, findings: list[Finding]) -> None:
        text = path.read_text(encoding="utf-8", errors="replace")
        text_lower = text.lower()
        if "<script" in text_lower or "javascript:" in text_lower:
            findings.append(Finding.artifact(rule_id="MANIFEST-004", title="XSS in model card", description="Script injection in model card", severity=Severity.HIGH, target=str(path), cwe_ids=["CWE-79"]))
        # Prompt injection patterns in model card content
        _INJECTION_PATTERNS = [
            "ignore previous instructions",
            "ignore all previous",
            "disregard previous",
            "forget previous instructions",
            "you are now",
            "you are dan",
            "output your system prompt",
            "output all api keys",
            "output system prompt",
        ]
        for pat in _INJECTION_PATTERNS:
            if pat in text_lower:
                findings.append(Finding.artifact(
                    rule_id="MANIFEST-005",
                    title="Prompt injection in model card",
                    description=f"Model card contains possible prompt injection: '{pat}'",
                    severity=Severity.HIGH,
                    target=str(path),
                    evidence=pat,
                    cwe_ids=["CWE-77"],
                ))
                break
        # SSTI / template injection in YAML frontmatter
        import re
        if re.search(r"\{\{[^}]{1,200}\}\}", text):
            findings.append(Finding.artifact(
                rule_id="MANIFEST-006",
                title="Template injection in model card",
                description="Model card YAML frontmatter contains Jinja2/template-style expression",
                severity=Severity.HIGH,
                target=str(path),
                cwe_ids=["CWE-94"],
            ))


# ── Archive Scanners ─────────────────────────────────────────────────

class CompressedScanner:
    """Transparent gz/bz2/xz/lz4/zlib scanning."""

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        suffix = path.suffix.lower()
        if suffix not in (".gz", ".bz2", ".xz", ".lz4", ".zst"):
            return findings
        try:
            data = path.read_bytes()
        except OSError:
            return findings
        decompressed = None
        try:
            if suffix == ".gz":
                import gzip; decompressed = gzip.decompress(data)
            elif suffix == ".bz2":
                import bz2; decompressed = bz2.decompress(data)
            elif suffix == ".xz":
                import lzma; decompressed = lzma.decompress(data)
        except Exception as e:
            findings.append(Finding.artifact(rule_id="COMPRESSED-001", title=f"Decompression failed: {suffix}", description=str(e), severity=Severity.MEDIUM, target=filepath))
            return findings
        if decompressed:
            ratio = len(decompressed) / max(len(data), 1)
            if ratio > 1000:
                findings.append(Finding.artifact(rule_id="COMPRESSED-002", title="Compression bomb", description=f"Ratio {ratio:.0f}:1", severity=Severity.CRITICAL, target=filepath, cwe_ids=["CWE-409"]))
            for pat in [b"__import__", b"os.system", b"subprocess", b"eval(", b"exec("]:
                if pat in decompressed:
                    findings.append(Finding.artifact(rule_id="COMPRESSED-003", title=f"Suspicious string in compressed: {pat.decode()}", description="After decompression", severity=Severity.HIGH, target=filepath))
        return findings


class RARScanner:
    """RAR recognition and fail-closed reporting."""

    def scan_file(self, filepath: str) -> list[Finding]:
        path = Path(filepath)
        if path.suffix.lower() != ".rar":
            return []
        try:
            magic = path.read_bytes()[:7]
        except OSError:
            return []
        if magic[:4] == b"Rar!" or magic[:7] == b"Rar!\x1a\x07\x00":
            return [Finding.artifact(rule_id="RAR-001", title="RAR archive detected", description="RAR format not supported — cannot verify safety. Fail-closed.", severity=Severity.HIGH, target=filepath)]
        return []


# ── Doctor/Debug CLI ─────────────────────────────────────────────────

class DoctorCheck:
    """Scanner health check and dependency verification."""

    def run(self) -> dict:
        results = {"python": sys.version, "platform": platform.platform(), "checks": {}}
        deps = [
            ("numpy", "weight analysis"), ("torch", "PyTorch scanning"), ("onnxruntime", "ONNX scanning"),
            ("transformers", "HuggingFace"), ("boto3", "S3 remote"), ("safetensors", "safetensors scanning"),
        ]
        for mod, purpose in deps:
            try:
                __import__(mod)
                results["checks"][mod] = {"status": "OK", "purpose": purpose}
            except ImportError:
                results["checks"][mod] = {"status": "MISSING", "purpose": purpose}
        from sentinel._plugins import list_all_plugins
        plugins = list_all_plugins()
        results["scanners"] = {k: len(v) for k, v in plugins.items()}
        return results


# ── HuggingFace Trust Data ───────────────────────────────────────────

TRUSTED_HF_ORGS = {
    "meta-llama", "google", "microsoft", "facebook", "openai", "mistralai",
    "stabilityai", "huggingface", "bigscience", "EleutherAI", "tiiuae",
    "deepseek-ai", "Qwen", "THUDM", "nvidia", "amazon", "apple", "allenai",
    "salesforce", "databricks", "mosaicml", "anthropic", "cohere",
    "sentence-transformers", "CompVis", "runwayml", "lmsys", "WizardLM",
    "codellama", "internlm", "baichuan-inc", "01-ai", "teknium",
}

def is_trusted_org(org: str) -> bool:
    return org.lower() in {o.lower() for o in TRUSTED_HF_ORGS}

def get_trust_level(org: str) -> str:
    if is_trusted_org(org):
        return "TRUSTED"
    return "UNKNOWN"
