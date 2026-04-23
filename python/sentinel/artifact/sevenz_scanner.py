"""7-Zip archive scanner — fail-closed analysis for .7z model archives."""
from __future__ import annotations
import logging
from pathlib import Path
from sentinel.finding import Finding, Severity

logger = logging.getLogger(__name__)

SEVEN_ZIP_MAGIC = b"7z\xbc\xaf\x27\x1c"

MODEL_EXTENSIONS = {
    ".pt", ".pth", ".bin", ".ckpt", ".safetensors", ".gguf", ".onnx", ".pb",
    ".pkl", ".pickle", ".joblib", ".npy", ".npz", ".keras", ".h5",
}


class SevenZipScanner:
    """7-Zip archive security scanner with optional py7zr support."""

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        if not path.exists() or path.suffix.lower() != ".7z":
            return findings
        try:
            magic = path.read_bytes()[:6]
        except OSError:
            return findings
        if magic != SEVEN_ZIP_MAGIC:
            return findings

        try:
            import py7zr
            return self._scan_with_py7zr(filepath, path, findings)
        except ImportError:
            findings.append(Finding.artifact(
                rule_id="7Z-001", title="7-Zip archive detected (fail-closed)",
                description="py7zr not installed — cannot verify archive safety. Install with: pip install py7zr",
                severity=Severity.HIGH, target=filepath,
            ))
            return self._scan_header_only(path, findings)

    def _scan_with_py7zr(self, filepath: str, path: Path, findings: list[Finding]) -> list[Finding]:
        import py7zr
        try:
            with py7zr.SevenZipFile(str(path), mode="r") as archive:
                entries = archive.list()
                total_uncompressed = 0
                model_files: list[str] = []
                pickle_files: list[str] = []

                for entry in entries:
                    name = entry.filename
                    total_uncompressed += entry.uncompressed if hasattr(entry, "uncompressed") else 0

                    if ".." in name or name.startswith("/"):
                        findings.append(Finding.artifact(
                            rule_id="7Z-002", title=f"Path traversal in 7z: {name}",
                            description="Archive entry with path traversal",
                            severity=Severity.CRITICAL, target=filepath,
                            evidence=name, cwe_ids=["CWE-22"],
                        ))

                    suffix = Path(name).suffix.lower()
                    if suffix in MODEL_EXTENSIONS:
                        model_files.append(name)
                    if suffix in (".pkl", ".pickle"):
                        pickle_files.append(name)

                compressed_size = path.stat().st_size
                if compressed_size > 0 and total_uncompressed / compressed_size > 1000:
                    findings.append(Finding.artifact(
                        rule_id="7Z-003", title="7z compression bomb",
                        description=f"Ratio {total_uncompressed / compressed_size:.0f}:1",
                        severity=Severity.CRITICAL, target=filepath,
                        cwe_ids=["CWE-409"],
                    ))

                for pf in pickle_files:
                    findings.append(Finding.artifact(
                        rule_id="7Z-004", title=f"Pickle in 7z archive: {pf}",
                        description="Pickle file inside 7z — potential code execution",
                        severity=Severity.HIGH, target=filepath,
                        evidence=pf, cwe_ids=["CWE-502"],
                    ))

                if model_files:
                    findings.append(Finding.artifact(
                        rule_id="7Z-005", title=f"Model files in 7z: {len(model_files)} found",
                        description=f"Files: {', '.join(model_files[:10])}",
                        severity=Severity.INFO, target=filepath,
                    ))

                if archive.needs_password():
                    findings.append(Finding.artifact(
                        rule_id="7Z-006", title="Password-protected 7z archive",
                        description="Cannot verify contents of encrypted archive",
                        severity=Severity.MEDIUM, target=filepath,
                    ))

        except Exception as e:
            findings.append(Finding.artifact(
                rule_id="7Z-007", title="7z archive parse error",
                description=str(e), severity=Severity.MEDIUM, target=filepath,
            ))
        return findings

    def _scan_header_only(self, path: Path, findings: list[Finding]) -> list[Finding]:
        try:
            data = path.read_bytes()[:64]
            if len(data) >= 32:
                major = data[6]
                minor = data[7]
                if major > 0 or minor > 4:
                    findings.append(Finding.artifact(
                        rule_id="7Z-008", title=f"Unusual 7z version: {major}.{minor}",
                        description="Non-standard 7z version may indicate tampering",
                        severity=Severity.MEDIUM, target=str(path),
                    ))
        except OSError:
            pass
        return findings
