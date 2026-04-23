"""Analysis pipeline — opcode sequence, semantic, ML context, entropy, pattern detection."""
from __future__ import annotations
import logging
import math
import os
import re
from pathlib import Path
from sentinel.finding import Finding, Severity

logger = logging.getLogger(__name__)


class OpcodeSequenceAnalyzer:
    """Detects known malicious pickle opcode sequences."""

    DANGEROUS_SEQUENCES = [
        (b"c", b"R", "GLOBAL+REDUCE: arbitrary code execution"),
        (b"\x93", b"R", "STACK_GLOBAL+REDUCE: dynamic import + call"),
        (b"c", b"\x81", "GLOBAL+NEWOBJ: arbitrary class instantiation"),
        (b"\x93", b"\x81", "STACK_GLOBAL+NEWOBJ: dynamic class creation"),
        (b"\x93", b"\x92", "STACK_GLOBAL+NEWOBJ_EX: kwargs class creation"),
        (b"i", None, "INST: combined import+call"),
    ]

    def analyze(self, data: bytes, filepath: str = "") -> list[Finding]:
        findings: list[Finding] = []
        for i, byte in enumerate(data):
            for first, second, desc in self.DANGEROUS_SEQUENCES:
                if bytes([byte]) == first:
                    if second is None:
                        findings.append(Finding.artifact(
                            rule_id="OPSEQ-001", title=f"Dangerous opcode: {desc}",
                            description=f"At offset 0x{i:x}", severity=Severity.HIGH,
                            target=filepath, evidence=desc,
                        ))
                    else:
                        window = data[i:i+200]
                        if second in window:
                            findings.append(Finding.artifact(
                                rule_id="OPSEQ-002", title=f"Dangerous sequence: {desc}",
                                description=f"Starting at offset 0x{i:x}",
                                severity=Severity.CRITICAL, target=filepath, evidence=desc,
                            ))
        return findings


class FileEntropyScanner:
    """Information entropy analysis across files."""

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        if not path.exists():
            return findings

        if path.is_dir():
            for child in path.rglob("*"):
                if child.is_file() and child.stat().st_size < 100_000_000:
                    findings.extend(self._analyze_file(child))
        else:
            findings.extend(self._analyze_file(path))
        return findings

    def _analyze_file(self, path: Path) -> list[Finding]:
        findings = []
        try:
            data = path.read_bytes()
        except OSError:
            return findings
        if len(data) < 100:
            return findings
        entropy = self._shannon_entropy(data)
        if entropy > 7.9:
            findings.append(Finding.artifact(
                rule_id="ENTROPY-001", title=f"High entropy file: {path.name}",
                description=f"Entropy={entropy:.3f}/8.0 — possibly encrypted/compressed payload",
                severity=Severity.MEDIUM, target=str(path),
                evidence=f"entropy={entropy:.3f}",
            ))
        if entropy < 0.5 and len(data) > 10000:
            findings.append(Finding.artifact(
                rule_id="ENTROPY-002", title=f"Very low entropy: {path.name}",
                description=f"Entropy={entropy:.3f} — possibly zeroed/corrupted",
                severity=Severity.LOW, target=str(path),
            ))
        return findings

    def _shannon_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        n = len(data)
        entropy = 0.0
        for f in freq:
            if f > 0:
                p = f / n
                entropy -= p * math.log2(p)
        return entropy


class PatternDetector:
    """Enhanced pattern detection with context for model metadata and configs."""

    PATTERNS = [
        (re.compile(rb"__import__\s*\("), "Dynamic import", Severity.CRITICAL),
        (re.compile(rb"eval\s*\("), "eval() call", Severity.CRITICAL),
        (re.compile(rb"exec\s*\("), "exec() call", Severity.CRITICAL),
        (re.compile(rb"os\.system\s*\("), "os.system() call", Severity.CRITICAL),
        (re.compile(rb"subprocess\.\w+\s*\("), "subprocess call", Severity.CRITICAL),
        (re.compile(rb"socket\.socket\s*\("), "Socket creation", Severity.HIGH),
        (re.compile(rb"http[s]?://\d+\.\d+\.\d+\.\d+"), "Hardcoded IP URL", Severity.HIGH),
        (re.compile(rb"base64\.b64decode\s*\("), "Base64 decode", Severity.MEDIUM),
        (re.compile(rb"marshal\.loads?\s*\("), "Marshal deserialization", Severity.CRITICAL),
        (re.compile(rb"ctypes\.\w+"), "ctypes usage", Severity.HIGH),
        (re.compile(rb"\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){10,}"), "Long hex escape sequence", Severity.MEDIUM),
    ]

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = Path(filepath).read_bytes()
        except OSError:
            return findings
        for pat, desc, severity in self.PATTERNS:
            for m in pat.finditer(data[:5_000_000]):
                findings.append(Finding.artifact(
                    rule_id="PATTERN-001", title=f"Pattern: {desc}",
                    description=f"At offset 0x{m.start():x} in {filepath}",
                    severity=severity, target=filepath,
                    evidence=m.group().decode(errors="replace")[:200],
                ))
        return findings


class SemanticAnalyzer:
    """Semantic analysis of model computation graphs."""

    def analyze(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        suffix = path.suffix.lower()
        if suffix == ".onnx":
            findings.extend(self._analyze_onnx(path))
        return findings

    def _analyze_onnx(self, path: Path) -> list[Finding]:
        findings = []
        try:
            data = path.read_bytes()
        except OSError:
            return findings
        suspicious_ops = [b"Loop", b"If", b"Scan", b"SequenceConstruct"]
        for op in suspicious_ops:
            if op in data:
                findings.append(Finding.artifact(
                    rule_id="SEMANTIC-001", title=f"Control flow op in ONNX: {op.decode()}",
                    description="Control flow operations can hide malicious logic",
                    severity=Severity.LOW, target=str(path), evidence=op.decode(),
                ))
        return findings


class MLContextAnalyzer:
    """Framework-aware context analysis."""

    EXPECTED_STRUCTURES = {
        ".pt": [".pt", ".pth", ".bin"],
        ".safetensors": [".safetensors"],
        ".onnx": [".onnx"],
        ".pb": [".pb", ".pbtxt"],
        ".h5": [".h5", ".hdf5", ".keras"],
    }

    def analyze_directory(self, dirpath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(dirpath)
        if not path.is_dir():
            return findings
        formats_found = set()
        for f in path.rglob("*"):
            if f.is_file():
                formats_found.add(f.suffix.lower())
        dangerous_exts = {".py", ".sh", ".bat", ".exe", ".dll", ".so"}
        for ext in dangerous_exts & formats_found:
            findings.append(Finding.artifact(
                rule_id="MLCTX-001", title=f"Executable file type in model dir: {ext}",
                description="Model directories should not contain executables",
                severity=Severity.HIGH, target=dirpath,
            ))
        return findings


class IntegratedAnalyzer:
    """Combined multi-signal analysis pipeline."""

    def __init__(self):
        self.entropy = FileEntropyScanner()
        self.pattern = PatternDetector()
        self.opcode = OpcodeSequenceAnalyzer()
        self.semantic = SemanticAnalyzer()
        self.context = MLContextAnalyzer()

    def analyze(self, target_path: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(target_path)
        if path.is_dir():
            findings.extend(self.context.analyze_directory(target_path))
            for f in path.rglob("*"):
                if f.is_file() and f.stat().st_size < 100_000_000:
                    findings.extend(self._analyze_single(f))
        elif path.is_file():
            findings.extend(self._analyze_single(path))
        return findings

    def _analyze_single(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self.entropy.scan_file(str(path)))
        findings.extend(self.pattern.scan_file(str(path)))
        findings.extend(self.semantic.analyze(str(path)))
        if path.suffix.lower() in (".pkl", ".pickle", ".pt", ".pth"):
            try:
                data = path.read_bytes()
                findings.extend(self.opcode.analyze(data, str(path)))
            except OSError:
                pass
        return findings
