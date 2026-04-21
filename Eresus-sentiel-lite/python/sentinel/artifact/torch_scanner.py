"""PyTorch model scanner — ZIP extraction, TorchScript IR, metadata injection."""

from __future__ import annotations

import logging
import struct
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Optional

from sentinel.finding import Finding, Severity, Location
from sentinel.artifact.pickle_scanner import PickleScanner
from sentinel.artifact.relaxed_zip import RelaxedZipFile

logger = logging.getLogger(__name__)

# ── PyTorch magic numbers ─────────────────────────────────────────

PYTORCH_MAGIC_NUMBER = 0x5071306F     # PyTorch v1+ ZIP format
PICKLE_MAGIC_NUMBER = 0x70636B6C      # Raw pickle (legacy)

# ── Known pickle-containing entries inside PyTorch ZIP archives ──

PICKLE_ENTRY_PATTERNS = [
    "archive/data.pkl",
    "data.pkl",
    ".data/",
]

# ── File extensions we handle ─────────────────────────────────────

TORCH_EXTENSIONS = {".pt", ".pth", ".bin", ".ckpt"}

# ── Torch-specific safe globals (rebuilders used in legitimate models) ──

SAFE_TORCH_GLOBALS = {
    # Standard tensor rebuilders
    "torch._utils._rebuild_tensor_v2",
    "torch._utils._rebuild_parameter",
    "torch._utils._rebuild_parameter_with_state",
    "torch._utils._rebuild_sparse_tensor",
    "torch._utils._rebuild_sparse_csr_tensor",
    "torch._utils._rebuild_nested_tensor",
    "torch._utils._rebuild_device_tensor_v2",
    # Storage types
    "torch.FloatStorage", "torch.LongStorage", "torch.IntStorage",
    "torch.ShortStorage", "torch.DoubleStorage", "torch.HalfStorage",
    "torch.BFloat16Storage", "torch.ByteStorage", "torch.CharStorage",
    "torch.BoolStorage", "torch.ComplexFloatStorage",
    "torch.ComplexDoubleStorage", "torch.TypedStorage",
    "torch.UntypedStorage", "torch.storage._load_from_bytes",
    "torch._C._rebuild_tensor_v2",
    # Common utilities
    "collections.OrderedDict",
    "numpy.ndarray", "numpy.dtype", "numpy.core.multiarray.scalar",
    "numpy.core.multiarray._reconstruct",
    "copyreg._reconstructor", "copyreg.__newobj__",
}

# ── Dangerous patterns specific to PyTorch exploitation ──────────

TORCH_DANGEROUS_REDUCE_TARGETS = {
    "os.system", "os.popen", "os.exec",
    "subprocess.call", "subprocess.Popen", "subprocess.run",
    "subprocess.check_output", "subprocess.check_call",
    "builtins.eval", "builtins.exec", "builtins.compile",
    "builtins.__import__", "builtins.getattr",
    "nt.system",  # Windows
}


class TorchScanner:
    """
    Advanced PyTorch model scanner with comprehensive attack coverage.

    Detection capabilities:
    - REDUCE chain confirmation with payload extraction
    - TorchScript IR code detection
    - Torch-specific safe/unsafe global classification
    - Metadata dictionary injection scanning
    - Weight-only vs full-model risk classification
    """

    def __init__(self, pickle_scanner: Optional[PickleScanner] = None):
        self._pickle_scanner = pickle_scanner or PickleScanner()

    def scan_file(self, file_path: str | Path) -> list[Finding]:
        """Scan a PyTorch model file for all known attack vectors."""
        path = Path(file_path)
        if not path.exists():
            logger.warning("File not found: %s", path)
            return []
        data = path.read_bytes()
        return self.scan_bytes(data, source=str(path))

    def scan_bytes(self, data: bytes, source: str = "<bytes>") -> list[Finding]:
        """Scan PyTorch model bytes with format auto-detection."""
        findings: list[Finding] = []
        fmt = self._detect_format(data)

        if fmt == "zip":
            findings.extend(self._scan_zip(data, source))
        elif fmt == "tar":
            findings.extend(self._scan_tar(data, source))
        elif fmt == "pickle":
            findings.extend(self._scan_raw_pickle(data, source))
        elif fmt == "unknown":
            if self._try_as_zip(data):
                findings.extend(self._scan_zip(data, source))
            else:
                findings.extend(self._scan_raw_pickle(data, source))

        return findings

    # ─── Format Detection ─────────────────────────────────────

    def _detect_format(self, data: bytes) -> str:
        """Detect format using magic numbers and heuristics."""
        if len(data) < 4:
            return "unknown"

        magic = struct.unpack("<I", data[:4])[0]

        if magic == PYTORCH_MAGIC_NUMBER:
            return "zip"
        if magic == PICKLE_MAGIC_NUMBER:
            return "pickle"
        if data[:2] == b"PK":
            return "zip"
        if len(data) > 262 and data[257:262] == b"ustar":
            return "tar"
        if data[0:2] in (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"):
            return "pickle"

        return "unknown"

    def _try_as_zip(self, data: bytes) -> bool:
        """Try opening data as ZIP."""
        try:
            with zipfile.ZipFile(BytesIO(data), "r") as zf:
                return len(zf.namelist()) > 0
        except (zipfile.BadZipFile, Exception):
            return False

    # ─── ZIP Scanning ─────────────────────────────────────────

    def _scan_zip(self, data: bytes, source: str) -> list[Finding]:
        """Deep-scan PyTorch ZIP archive with relaxed fallback."""
        findings: list[Finding] = []

        try:
            zip_data = self._find_zip_start(data)
            zf, zip_findings = RelaxedZipFile.try_standard_then_relaxed(
                zip_data, target=source
            )
            findings.extend(zip_findings)
        except Exception as e:
            logger.warning("Cannot open ZIP in '%s': %s", source, e)
            findings.append(Finding.artifact(
                rule_id="ARTIFACT-020",
                title="Corrupt PyTorch archive",
                description=(
                    f"Failed to open '{source}' as a ZIP archive. "
                    f"The file may be corrupted or use an unsupported format."
                ),
                severity=Severity.MEDIUM,
                target=source,
                evidence=f"ZIP parse error: {e}",
            ))
            return findings

        # Get entry list — works for both zipfile.ZipFile and RelaxedZipFile
        is_relaxed = isinstance(zf, RelaxedZipFile)

        if not is_relaxed:
            # Standard zipfile path
            with zf:
                entries = zf.namelist()
                findings.extend(self._scan_zip_entries(zf, entries, source))
        else:
            # Relaxed parser path — no context manager needed
            entries = zf.namelist()
            findings.extend(self._scan_zip_entries(zf, entries, source))

        return findings

    def _scan_zip_entries(
        self, zf: zipfile.ZipFile | RelaxedZipFile,
        entries: list[str], source: str
    ) -> list[Finding]:
        """Scan entries from either standard or relaxed ZIP parser."""
        findings: list[Finding] = []
        is_relaxed = isinstance(zf, RelaxedZipFile)

        # ── TorchScript detection ──
        if self._has_torchscript(entries):
            findings.extend(self._scan_torchscript(zf, source))

        # ── Classify model type ──
        model_type = self._classify_model_type(entries)
        if model_type == "full_model":
            findings.append(Finding.artifact(
                rule_id="TORCH-010",
                title="Full model serialization (advisory)",
                description=(
                    "This file contains a full PyTorch model (architecture + weights) "
                    "serialized via pickle. This is standard for most PyTorch models "
                    "but carries inherent deserialization risk. Consider using "
                    "safetensors format for weight-only storage."
                ),
                severity=Severity.LOW,
                target=source,
                evidence=f"Model type: {model_type}, entries: {len(entries)}",
            ))

        # ── Scan pickle entries ──
        for entry_name in entries:
            if self._is_pickle_entry(entry_name):
                logger.debug("Scanning ZIP entry: %s!%s", source, entry_name)
                entry_findings = self._pickle_scanner.scan_zip_entry(
                    zf, entry_name, source=source
                )

                # Enhance findings with PyTorch context
                for finding in entry_findings:
                    finding.tags = list(set(
                        (finding.tags or []) + ["pytorch", "model-file"]
                    ))

                findings.extend(entry_findings)

        # ── Metadata injection scan ──
        findings.extend(self._scan_metadata(zf, source))

        # ── Archive slip detection ──
        if not is_relaxed:  # Only standard ZipFile has infolist()
            findings.extend(self._check_archive_slip(zf, source))

        return findings

    def _has_torchscript(self, entries: list[str]) -> bool:
        """Check if ZIP contains TorchScript IR."""
        return any(
            e.startswith("code/") or e.endswith(".py") or "constants.pkl" in e
            for e in entries
        )

    def _scan_torchscript(
        self, zf: zipfile.ZipFile, source: str
    ) -> list[Finding]:
        """Scan TorchScript IR entries for code execution risks."""
        findings = []

        findings.append(Finding.artifact(
            rule_id="TORCH-011",
            title="TorchScript model detected",
            description=(
                "This file contains TorchScript IR (code/ directory). TorchScript "
                "models contain executable Python-like code that runs during model "
                "loading. This is a direct code execution surface."
            ),
            severity=Severity.HIGH,
            target=source,
            evidence="Detected code/ directory or .py files in archive",
            cwe_ids=["CWE-94"],
        ))

        # Scan code files for dangerous patterns
        dangerous_ts_patterns = [
            "os.system", "subprocess", "__import__",
            "eval(", "exec(", "open(",
            "socket.", "http.", "urllib",
            "torch.utils.model_zoo",
        ]

        for entry in zf.namelist():
            if entry.startswith("code/") and entry.endswith(".py"):
                try:
                    code_content = zf.read(entry).decode("utf-8", errors="replace")
                    for pattern in dangerous_ts_patterns:
                        if pattern in code_content:
                            findings.append(Finding.artifact(
                                rule_id="TORCH-012",
                                title=f"Dangerous code in TorchScript: {pattern}",
                                description=(
                                    f"TorchScript file '{entry}' contains '{pattern}' "
                                    f"which could enable code execution or network access "
                                    f"during model loading."
                                ),
                                severity=Severity.CRITICAL,
                                target=source,
                                evidence=f"File: {entry}, Pattern: {pattern}",
                                cwe_ids=["CWE-94"],
                            ))
                            break
                except Exception:
                    pass

        return findings

    def _classify_model_type(self, entries: list[str]) -> str:
        """Classify whether this is a full model or weights-only."""
        has_pickle = any(self._is_pickle_entry(e) for e in entries)
        has_data = any("data/" in e or e.endswith(".data") for e in entries)
        has_code = any(e.startswith("code/") for e in entries)

        if has_code:
            return "torchscript"
        elif has_pickle and has_data:
            return "full_model"
        elif has_data and not has_pickle:
            return "weights_only"
        return "unknown"

    def _scan_metadata(
        self, zf: zipfile.ZipFile, source: str
    ) -> list[Finding]:
        """Scan model metadata for injection attacks."""
        findings = []

        # PyTorch may store metadata in various entries
        metadata_entries = [e for e in zf.namelist() if "metadata" in e.lower()]

        for entry in metadata_entries:
            try:
                content = zf.read(entry).decode("utf-8", errors="replace")
                dangerous_patterns = [
                    "__import__", "os.system", "eval(", "exec(",
                    "subprocess", "socket", "http://", "https://",
                ]
                for pattern in dangerous_patterns:
                    if pattern in content:
                        findings.append(Finding.artifact(
                            rule_id="TORCH-013",
                            title=f"Suspicious content in model metadata: {pattern}",
                            description=(
                                f"Metadata entry '{entry}' contains '{pattern}' "
                                f"which may indicate an injection attack."
                            ),
                            severity=Severity.HIGH,
                            target=source,
                            evidence=f"Entry: {entry}, Pattern: {pattern}",
                            cwe_ids=["CWE-94"],
                        ))
                        break
            except Exception:
                pass

        return findings

    def _check_archive_slip(
        self, zf: zipfile.ZipFile, source: str
    ) -> list[Finding]:
        """Check for path traversal in PyTorch ZIP archive."""
        findings = []
        for info in zf.infolist():
            if info.filename.startswith("/") or ".." in info.filename:
                findings.append(Finding.artifact(
                    rule_id="TORCH-014",
                    title="Path traversal in PyTorch archive",
                    description=(
                        f"Archive member '{info.filename}' contains path traversal. "
                        f"Loading this model could write files outside the target directory."
                    ),
                    severity=Severity.CRITICAL,
                    target=source,
                    evidence=f"Member: {info.filename}",
                    cwe_ids=["CWE-22"],
                ))

            # Symlink check
            if (info.external_attr >> 28) == 0xA:
                findings.append(Finding.artifact(
                    rule_id="TORCH-015",
                    title="Symlink in PyTorch archive",
                    description=(
                        f"Archive member '{info.filename}' is a symlink. "
                        f"Symlinks in model archives can escape the extraction sandbox."
                    ),
                    severity=Severity.HIGH,
                    target=source,
                    cwe_ids=["CWE-59"],
                ))

        return findings

    # ─── Utility Methods ──────────────────────────────────────

    def _find_zip_start(self, data: bytes) -> bytes:
        """Find the start of ZIP data (PyTorch may have custom header)."""
        if data[:2] == b"PK":
            return data
        pk_offset = data.find(b"PK\x03\x04")
        if pk_offset > 0:
            return data[pk_offset:]
        return data

    def _is_pickle_entry(self, entry_name: str) -> bool:
        """Check if a ZIP entry likely contains pickle data."""
        name_lower = entry_name.lower()
        if name_lower.endswith((".pkl", ".pickle", ".p")):
            return True
        for pattern in PICKLE_ENTRY_PATTERNS:
            if pattern in name_lower:
                return True
        if "/data/" in name_lower and not name_lower.endswith(
            (".bin", ".pt", ".npy")
        ):
            return False
        return False

    def _scan_raw_pickle(self, data: bytes, source: str) -> list[Finding]:
        """Scan raw pickle data (legacy format).

        Also detects magic-number bypass: in old-format PyTorch files the
        first pickle is supposed to contain a single integer (the magic
        number ``0x1950A86A20F9469CFC6C``).  If that first pickle contains
        GLOBAL opcodes, the magic was produced via ``eval()`` or similar —
        a direct RCE indicator.
        """
        findings: list[Finding] = []

        # ── Magic-number bypass detection ──────────────────────
        # Parse *only* the first pickle stream to check for globals.
        magic_bypass = False
        try:
            import pickletools
            first_ops = list(pickletools.genops(BytesIO(data)))
            has_globals = any(
                op[0].name in ("GLOBAL", "INST", "STACK_GLOBAL")
                for op in first_ops
            )
            if has_globals:
                magic_bypass = True
                findings.append(Finding.artifact(
                    rule_id="TORCH-018",
                    title="PyTorch magic-number bypass detected",
                    description=(
                        "The first pickle stream in this old-format PyTorch file "
                        "contains GLOBAL/INST opcodes.  A legitimate magic-number "
                        "pickle contains only a plain integer.  GLOBAL opcodes here "
                        "indicate the magic was produced via eval() or exec() — "
                        "this is a confirmed RCE bypass technique."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    target=source,
                    evidence="GLOBAL opcodes in magic-number pickle",
                    cwe_ids=["CWE-502"],
                ))
        except Exception:
            pass

        # Scan full data through the pickle scanner
        findings.extend(self._pickle_scanner.scan_bytes(data, source=source))

        # Legacy format advisory (only when no bypass — bypass is worse)
        if not magic_bypass:
            findings.append(Finding.artifact(
                rule_id="TORCH-016",
                title="Legacy raw pickle PyTorch format",
                description=(
                    "This file uses the legacy raw pickle format instead of "
                    "the modern ZIP-based format. Legacy format has fewer "
                    "validation options and a simpler attack surface."
                ),
                severity=Severity.LOW,
                target=source,
            ))

        return findings

    def _scan_tar(self, data: bytes, source: str) -> list[Finding]:
        """Scan old-format TAR PyTorch archive.

        PyTorch < 1.6 used TAR format. torch.load() still supports it.
        """
        import tarfile as _tarfile

        findings = []
        findings.append(Finding.artifact(
            rule_id="TORCH-017",
            title="Legacy TAR-format PyTorch model",
            description=(
                "This file uses the legacy TAR archive format (PyTorch < 1.6). "
                "TAR models are fully supported by torch.load() and contain "
                "pickle data that can execute arbitrary code."
            ),
            severity=Severity.HIGH,
            target=source,
            evidence="TAR magic 'ustar' at offset 257",
            cwe_ids=["CWE-502"],
        ))

        try:
            tf = _tarfile.open(fileobj=BytesIO(data), mode="r:*")
            for member in tf.getmembers():
                if member.isfile():
                    name_lower = member.name.lower()
                    is_pickle = name_lower.endswith((".pkl", ".pickle", ".p"))
                    is_data = "data.pkl" in name_lower or "data" in name_lower

                    if is_pickle or is_data:
                        try:
                            f = tf.extractfile(member)
                            if f:
                                entry_data = f.read()
                                entry_findings = self._pickle_scanner.scan_bytes(
                                    entry_data,
                                    source=f"{source}!{member.name}",
                                )
                                for ef in entry_findings:
                                    ef.tags = list(set(
                                        (ef.tags or []) + ["pytorch", "tar-format"]
                                    ))
                                findings.extend(entry_findings)
                        except Exception as exc:
                            logger.warning("Failed to extract TAR entry '%s': %s", member.name, exc)
            tf.close()
        except Exception as exc:
            logger.warning("Failed to parse TAR archive '%s': %s", source, exc)

        return findings
