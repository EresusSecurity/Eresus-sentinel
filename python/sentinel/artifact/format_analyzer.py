"""
Eresus Sentinel — Unified Format Analyzer.

Dispatches to per-format reverse engines based on content-based magic number
detection (primary) and file extension (fallback).

Supported format engines:
  - gguf_engine.py         → GGUF (.gguf, .ggml)
  - safetensors_engine.py  → SafeTensors (.safetensors)
  - pytorch_engine.py      → PyTorch (.pt, .pth, .bin)
  - onnx_engine.py         → ONNX (.onnx)
  - tensorflow_scanner.py  → TensorFlow SavedModel (.pb)
  - torchscript_scanner.py → TorchScript (.torchscript)
  - tflite_scanner.py      → TFLite (.tflite)
  - torchmobile_scanner.py → TorchMobile Lite (.ptl)
  - llamafile_scanner.py   → LlamaFile (.llamafile)

Format detection priority:
  1. Content-based magic number sniffing (most reliable)
  2. Extension-based lookup (fallback for ambiguous cases)
"""

from __future__ import annotations

import json
import logging
import struct
import zipfile
from io import BytesIO
from pathlib import Path
from typing import List, Optional

from ..finding import Finding, Severity
from .format_common import TensorInfo, FormatReport
from .gguf_engine import GGUFReverseEngine, GGUFHeader, GGUF_MAGIC, GGUFValueType
from .safetensors_engine import SafeTensorsReverseEngine
from .pytorch_engine import PyTorchReverseEngine
from .onnx_engine import ONNXReverseEngine
from .tensorflow_scanner import TensorFlowScanner
from .torchscript_scanner import TorchScriptScanner
from .tflite_scanner import TFLiteScanner
from .torchmobile_scanner import TorchMobileScanner
from .llamafile_scanner import LlamaFileScanner
from .protobuf_parser import ProtobufParser

logger = logging.getLogger(__name__)


class FormatAnalyzer:
    """Unified entry point for model format reverse engineering.

    Auto-detects format using content-based magic number detection
    (primary) and file extension (fallback), then dispatches to
    the appropriate reverse engine.
    """

    # Extension → format name mapping (fallback for content detection)
    FORMAT_MAP = {
        # Existing formats
        ".gguf": "gguf",
        ".ggml": "gguf",
        ".safetensors": "safetensors",
        ".pt": "pytorch",
        ".pth": "pytorch",
        ".bin": "pytorch",
        ".onnx": "onnx",
        ".pb": "tensorflow",
        ".torchscript": "torchscript",
        ".tflite": "tflite",
        ".ptl": "torchmobile",
        ".llamafile": "llamafile",
        # Pickle formats
        ".pkl": "pickle",
        ".pickle": "pickle",
        ".joblib": "pickle",
    }

    # Formats that have implemented engines
    _IMPLEMENTED_FORMATS = {
        "gguf", "safetensors", "pytorch", "onnx",
        "tensorflow", "torchscript", "tflite", "torchmobile", "llamafile",
        "pickle",
    }

    def __init__(self) -> None:
        self.gguf_engine = GGUFReverseEngine()
        self.safetensors_engine = SafeTensorsReverseEngine()
        self.pytorch_engine = PyTorchReverseEngine()
        self.onnx_engine = ONNXReverseEngine()
        self.tf_scanner = TensorFlowScanner()
        self.ts_scanner = TorchScriptScanner()
        self.tflite_scanner = TFLiteScanner()
        self.torchmobile_scanner = TorchMobileScanner()
        self.llamafile_scanner = LlamaFileScanner()

    def _detect_format(self, filepath: str) -> Optional[str]:
        """Detect model format by file content (magic numbers).

        Returns format name string or None if unrecognized.
        Priority-ordered checks:
          1. GGUF magic (bytes: "GGUF")
          2. ZIP magic → inspect contents for PyTorch/Keras/TorchScript
          3. SafeTensors (uint64 LE header size + valid JSON)
          4. Protobuf content → ONNX vs TensorFlow SavedModel
          5. TFLite FlatBuffer magic
          6. LlamaFile APE/ELF header
        """
        path = Path(filepath)
        if not path.exists() or not path.is_file():
            return None

        try:
            file_size = path.stat().st_size
            if file_size < 4:
                return None

            with open(filepath, "rb") as f:
                header = f.read(min(file_size, 8192))  # Read up to 8KB for detection

            # ─── 1. GGUF magic ───
            if header[:4] == b"GGUF":
                return "gguf"

            # ─── 2. ZIP magic → PyTorch / Keras / TorchScript ───
            if header[:4] == b"PK\x03\x04":
                return self._detect_zip_format(filepath)

            # ─── 3. SafeTensors detection ───
            # SafeTensors starts with 8-byte LE uint64 header size
            if file_size >= 16:
                header_size = struct.unpack("<Q", header[:8])[0]
                if 2 <= header_size <= 100_000_000 and 8 + header_size <= file_size:
                    # Try to parse the header as JSON
                    try:
                        candidate = header[8:8 + min(header_size, 8184)]
                        if candidate[:1] == b"{":
                            json.loads(candidate.decode("utf-8", errors="replace"))
                            return "safetensors"
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        pass

            # ─── 4. Protobuf detection → ONNX or TF SavedModel ───
            if self._looks_like_protobuf(header):
                return self._detect_protobuf_format(header)

            # ─── 5. TFLite FlatBuffer ───
            if file_size >= 8:
                # TFLite files have "TFL3" identifier at offset 4
                if header[4:8] == b"TFL3":
                    return "tflite"

            # ─── 6. LlamaFile (Cosmopolitan APE / ELF) ───
            if header[:2] == b"MZ" or header[:4] == b"\x7fELF":
                # Could be a llamafile if it also has GGUF further in
                # Check for GGUF magic after the executable section
                if file_size > 4096:
                    with open(filepath, "rb") as f:
                        f.seek(0)
                        # Scan first 1MB for GGUF marker
                        scan_data = f.read(min(file_size, 1_048_576))
                        if b"GGUF" in scan_data[4:]:  # Skip the first 4 bytes (header)
                            return "llamafile"

            # ─── 7. Pickle content detection ───
            # Pickle protocols 2-5 start with \x80\x02-\x05
            if header[0:1] == b"\x80" and len(header) > 1 and header[1] in range(2, 6):
                return "pickle"
            # Pickle protocol 0/1: starts with typical opcodes like '(' or 'c'
            if header[0:1] in (b"(", b"c", b"]", b"}"):
                # Heuristic: check for GLOBAL opcode pattern 'c<module>\n<name>\n'
                if b"\n" in header[:200]:
                    return "pickle"

        except (OSError, struct.error):
            pass

        return None

    def _detect_zip_format(self, filepath: str) -> str:
        """Detect specific format inside a ZIP archive."""
        try:
            with zipfile.ZipFile(filepath, "r") as zf:
                names = zf.namelist()
                name_set = set(names)

                # TorchScript: has code/ directory
                if any(n.startswith("code/") for n in names):
                    return "torchscript"

                # PyTorch: has archive/data.pkl or data.pkl
                if any("data.pkl" in n or "constants.pkl" in n for n in names):
                    return "pytorch"

                # Keras: has config.json with class_name
                if "config.json" in name_set:
                    try:
                        config_data = zf.read("config.json")
                        config = json.loads(config_data)
                        if "class_name" in config:
                            return "keras"
                    except (json.JSONDecodeError, KeyError):
                        pass

                # Default ZIP → treat as PyTorch
                return "pytorch"
        except zipfile.BadZipFile:
            return None  # Don't assume pytorch on corrupt ZIP

    def _looks_like_protobuf(self, header: bytes) -> bool:
        """Quick heuristic: does this look like protobuf-encoded data?

        Requires at least 2 successfully parsed fields with reasonable
        field numbers (1-100) to avoid false positives on arbitrary data.
        """
        if len(header) < 4:
            return False
        try:
            fields = ProtobufParser.parse_fields(header[:512])
            if len(fields) < 2:
                return False
            # All field numbers should be reasonable (1-100)
            return all(1 <= fn <= 100 for fn, _, _ in fields)
        except Exception:
            return False

    def _detect_protobuf_format(self, header: bytes) -> str:
        """Distinguish ONNX from TF SavedModel in protobuf data."""
        try:
            fields = ProtobufParser.parse_fields(header)
            field_numbers = {fn for fn, _, _ in fields}

            # ONNX ModelProto has distinctive fields:
            #   field 7 = graph (GraphProto)  — ONLY ONNX has field 7
            #   field 8 = opset_import        — ONLY ONNX has field 8
            #   field 2 = producer_name       (both ONNX and TF have field 2)
            #   field 14 = metadata_props     — ONLY ONNX has field 14
            # Check field 7 first — it's the strongest ONNX signal
            if 7 in field_numbers:
                return "onnx"

            if 8 in field_numbers:
                return "onnx"

            if 14 in field_numbers:
                return "onnx"

            # TF SavedModel has:
            #   field 1 = saved_model_schema_version (int64)
            #   field 2 = meta_graphs (MetaGraphDef)
            #   TF SavedModel ONLY has fields 1 and 2 at top level
            if 1 in field_numbers and 2 in field_numbers:
                # Check field count — TF SavedModel only has 2 fields
                if field_numbers <= {1, 2}:
                    schema_ver = ProtobufParser.get_field_varint(fields, 1)
                    if 0 < schema_ver < 100:
                        return "tensorflow"

        except Exception:
            pass

        # Can't determine — caller should use extension
        return "onnx"  # Default for .onnx extension

    def analyze(self, filepath: str) -> FormatReport:
        """Auto-detect format and run full analysis."""
        path = Path(filepath)
        ext = path.suffix.lower()

        # Primary: content-based detection
        detected_format = self._detect_format(filepath)

        # Fallback: extension-based
        ext_format = self.FORMAT_MAP.get(ext)

        # Use content detection if available, else extension
        fmt = detected_format or ext_format

        # ── Polyglot detection (fickling-inspired) ────────────────
        # Check if file matches multiple format signatures
        polyglot_formats = self._detect_polyglot(filepath)
        polyglot_finding = None
        if len(polyglot_formats) > 1:
            polyglot_finding = Finding.artifact(
                rule_id="ARTIFACT-035",
                title=f"Polyglot file detected: {' + '.join(polyglot_formats)}",
                description=(
                    f"This file matches multiple format signatures: "
                    f"{', '.join(polyglot_formats)}. Polyglot files can trick "
                    f"different parsers into interpreting the same file differently, "
                    f"potentially hiding malicious payloads in one interpretation "
                    f"while appearing safe in another."
                ),
                severity=Severity.HIGH,
                confidence=0.9,
                target=filepath,
                evidence=f"Detected formats: {polyglot_formats}",
                cwe_ids=["CWE-434"],
            )

        # Log disagreements — potential extension spoofing
        extra_findings: list = []
        if detected_format and ext_format and detected_format != ext_format:
            logger.warning(
                "Format mismatch: content=%s, extension=%s for %s — using content detection. "
                "This may indicate extension spoofing.",
                detected_format, ext_format, filepath
            )
            # Run BOTH scanners when there's a mismatch (anti-spoofing)
            # The content-detected format is primary, but also scan as extension format
            extra_findings = self._scan_as_format(filepath, ext_format)

        # Dispatch to engines
        if fmt == "pickle":
            from .pickle_scanner import PickleScanner
            scanner = PickleScanner()
            findings = scanner.scan_file(filepath)
            if polyglot_finding:
                findings.append(polyglot_finding)
            report = FormatReport(
                format_name="Pickle", file_path=filepath,
                file_size=path.stat().st_size if path.exists() else 0,
            )
            report.findings = findings
        elif fmt == "gguf":
            report = self.gguf_engine.analyze(filepath)
            if polyglot_finding:
                report.findings.append(polyglot_finding)
        elif fmt == "safetensors":
            report = self.safetensors_engine.analyze(filepath)
            if polyglot_finding:
                report.findings.append(polyglot_finding)
        elif fmt == "pytorch":
            report = self.pytorch_engine.analyze(filepath)
            if polyglot_finding:
                report.findings.append(polyglot_finding)
        elif fmt == "onnx":
            report = self.onnx_engine.analyze(filepath)
        elif fmt == "tensorflow":
            findings = self.tf_scanner.scan_file(filepath)
            report = FormatReport(
                format_name="TensorFlow", file_path=filepath,
                file_size=path.stat().st_size if path.exists() else 0,
            )
            report.findings = findings
        elif fmt == "torchscript":
            findings = self.ts_scanner.scan_file(filepath)
            report = FormatReport(
                format_name="TorchScript", file_path=filepath,
                file_size=path.stat().st_size if path.exists() else 0,
            )
            report.findings = findings
        elif fmt == "tflite":
            findings = self.tflite_scanner.scan_file(filepath)
            report = FormatReport(
                format_name="TFLite/LiteRT", file_path=filepath,
                file_size=path.stat().st_size if path.exists() else 0,
            )
            report.findings = findings
        elif fmt == "llamafile":
            findings = self.llamafile_scanner.scan_file(filepath)
            report = FormatReport(
                format_name="LlamaFile", file_path=filepath,
                file_size=path.stat().st_size if path.exists() else 0,
            )
            report.findings = findings
        elif fmt in self._IMPLEMENTED_FORMATS:
            report = self.onnx_engine.analyze(filepath)
        elif fmt == "torchmobile":
            findings = self.torchmobile_scanner.scan_file(filepath)
            report = FormatReport(
                format_name="TorchMobile", file_path=filepath,
                file_size=path.stat().st_size if path.exists() else 0,
            )
            report.findings = findings
        elif fmt == "keras":
            report = FormatReport(
                format_name="Keras",
                file_path=filepath,
                file_size=path.stat().st_size if path.exists() else 0,
            )
            report.findings.append(Finding.artifact(
                rule_id="FMT-001",
                title=f"Keras format detected — use dedicated Keras scanner",
                description="File detected as Keras format. Use KerasScanner.scan_file() "
                            "for comprehensive Lambda layer and config.json analysis.",
                severity=Severity.INFO,
                target=filepath,
            ))
        else:
            report = FormatReport(
                format_name="unknown",
                file_path=filepath,
                file_size=path.stat().st_size if path.exists() else 0,
            )
            report.findings.append(Finding.artifact(
                rule_id="FMT-000",
                title=f"Unsupported format: {ext}",
                description=f"File extension '{ext}' is not supported. "
                            f"Supported: {list(self.FORMAT_MAP.keys())}",
                severity=Severity.INFO,
                target=filepath,
            ))

        # Merge anti-spoofing findings from the extension-format scan
        if extra_findings:
            report.findings.extend(extra_findings)

        return report

    def analyze_directory(self, dirpath: str) -> List[FormatReport]:
        """Analyze all model files in a directory."""
        reports = []
        path = Path(dirpath)
        if not path.is_dir():
            return reports
        for fpath in path.rglob("*"):
            if fpath.is_file() and fpath.suffix.lower() in self.FORMAT_MAP:
                reports.append(self.analyze(str(fpath)))
        return reports

    def _scan_as_format(self, filepath: str, fmt: str) -> list[Finding]:
        """Run a specific format scanner regardless of content detection.

        Used for anti-spoofing: when content and extension disagree,
        run the extension's scanner too to catch renamed files.
        """
        try:
            if fmt == "pickle":
                from .pickle_scanner import PickleScanner
                return PickleScanner().scan_file(filepath)
            elif fmt == "gguf":
                report = self.gguf_engine.analyze(filepath)
                return report.findings if hasattr(report, "findings") else []
            elif fmt == "safetensors":
                report = self.safetensors_engine.analyze(filepath)
                return report.findings if hasattr(report, "findings") else []
            elif fmt == "pytorch":
                report = self.pytorch_engine.analyze(filepath)
                return report.findings if hasattr(report, "findings") else []
        except Exception as e:
            logger.debug("Anti-spoofing scan as %s failed: %s", fmt, e)
        return []

    def _detect_polyglot(self, filepath: str) -> list[str]:
        """Detect if a file matches multiple format signatures (polyglot).

        Returns list of format names matched. More than 1 = polyglot.
        Inspired by fickling's polyglot detection approach.
        """
        path = Path(filepath)
        if not path.exists() or not path.is_file():
            return []

        matched: list[str] = []

        try:
            file_size = path.stat().st_size
            if file_size < 4:
                return []

            with open(filepath, "rb") as f:
                header = f.read(min(file_size, 8192))

            # Check ZIP magic
            if header[:4] == b"PK\x03\x04":
                matched.append("zip")

            # Check GGUF magic
            if header[:4] == b"GGUF":
                matched.append("gguf")

            # Check pickle protocol markers
            if header[0:1] == b"\x80" and len(header) > 1 and header[1] in range(2, 6):
                matched.append("pickle")
            elif header[0:1] in (b"(", b"c") and b"\n" in header[:200]:
                matched.append("pickle")

            # Check ELF/PE (llamafile, polyglot binary)
            if header[:4] == b"\x7fELF" or header[:2] == b"MZ":
                matched.append("executable")

            # Check TAR magic
            if file_size > 262 and header[257:262] == b"ustar":
                matched.append("tar")

            # Check numpy magic
            if header[:6] == b"\x93NUMPY":
                matched.append("numpy")

            # Check if ZIP also contains pickle (PyTorch/TorchScript)
            if "zip" in matched:
                try:
                    with zipfile.ZipFile(filepath, "r") as zf:
                        names = zf.namelist()
                        if any("data.pkl" in n for n in names):
                            if "pickle" not in matched:
                                matched.append("pytorch+pickle")
                except zipfile.BadZipFile:
                    pass

            # Look for secondary pickle embedded deeper in binary
            # (polyglot: binary executable + pickle payload)
            if "executable" in matched and file_size > 4096:
                with open(filepath, "rb") as f:
                    tail = f.read()
                    for hdr in [b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"]:
                        if hdr in tail[256:]:
                            if "pickle" not in matched:
                                matched.append("pickle")
                            break

        except OSError:
            pass

        return matched
