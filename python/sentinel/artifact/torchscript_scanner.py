"""
Eresus Sentinel — TorchScript Scanner.

Deep-inspects TorchScript model archives (.pt, .ptc, .torchscript) for
security threats. TorchScript models are ZIP archives containing serialized
computation graphs, bytecode, and optional Python source.

Covers PAIT threat IDs:
  - PAIT-TS-200: Backdoor via malicious custom C++ operators
  - PAIT-TS-300: Code execution via TorchScript bytecode
  - PAIT-TS-301: Pickle-based deserialization attack within archive
  - PAIT-TS-302: Path traversal via archive entry names

TorchScript archive structure:
  model.pt (ZIP)
  ├── code/                    ← serialized TorchScript source
  │   ├── __torch__/
  │   │   └── model.py        ← TorchScript Python-like IR
  │   └── __torch__.py
  ├── data/                    ← serialized tensors + data
  │   ├── 0                    ← raw tensor data
  │   └── ...
  ├── constants.pkl            ← pickled constants (attack surface!)
  └── data.pkl                 ← pickled metadata (attack surface!)

No torch pip dependency required.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import List, Set, Tuple

from ..finding import Finding, Severity
from ..rules import load_scanner_rules

_rules = load_scanner_rules()
_ts_rules = _rules.get("torchscript", {})
_common = _rules.get("common", {})

def _load_code_patterns() -> List[Tuple[str, str, Severity]]:
    """Load dangerous code patterns from YAML, with inline fallback."""
    _SEVERITY_MAP = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }
    patterns = _ts_rules.get("code_patterns", None)
    if patterns:
        return [
            (p["pattern"], p["description"], _SEVERITY_MAP.get(p["severity"], Severity.HIGH))
            for p in patterns
        ]
    return [
        ("os.system", "System command execution", Severity.CRITICAL),
        ("os.popen", "System command execution", Severity.CRITICAL),
        ("subprocess", "Subprocess invocation", Severity.CRITICAL),
        ("__import__", "Dynamic import", Severity.CRITICAL),
        ("eval(", "Dynamic code evaluation", Severity.CRITICAL),
        ("exec(", "Dynamic code execution", Severity.CRITICAL),
        ("open(", "File access", Severity.HIGH),
        ("os.remove", "File deletion", Severity.HIGH),
        ("os.unlink", "File deletion", Severity.HIGH),
        ("shutil.rmtree", "Directory deletion", Severity.CRITICAL),
        ("socket", "Network socket access", Severity.HIGH),
        ("http.client", "HTTP client access", Severity.HIGH),
        ("urllib", "URL access", Severity.HIGH),
        ("requests.", "HTTP requests", Severity.HIGH),
    ]

DANGEROUS_CODE_PATTERNS = _load_code_patterns()

PICKLE_GLOBAL = b"c"
PICKLE_STACK_GLOBAL = b"\x93"
PICKLE_INST = b"i"
PICKLE_REDUCE = b"R"

PICKLE_DANGEROUS_MODULES: Set[str] = set(
    _ts_rules.get("pickle_dangerous_modules", [
        "os", "posixpath", "nt", "ntpath",
        "subprocess", "shutil", "builtins",
        "webbrowser", "socket", "http",
        "ctypes", "importlib", "runpy",
    ])
)

SUSPICIOUS_NAMES = _common.get("suspicious_names", [
    "backdoor", "trojan", "payload", "exploit", "malware",
    "reverse_shell", "c2", "exfil", "keylogger",
])

SAFE_EXTENSIONS: Set[str] = set(
    _ts_rules.get("safe_extensions", [".py", ".pkl", ".json", ".txt", "", ".debug_pkl"])
)

EXECUTABLE_EXTENSIONS: Set[str] = set(
    _common.get("executable_extensions", [
        ".sh", ".bash", ".bat", ".cmd", ".ps1",
        ".exe", ".dll", ".so", ".dylib",
    ])
)


class TorchScriptScanner:
    """Deep-inspect TorchScript model archives for security threats.

    Supports ZIP-based TorchScript archives. Does NOT require torch.
    """

    def __init__(self) -> None:
        self.findings: List[Finding] = []

    def scan_file(self, path: str) -> List[Finding]:
        """Scan a TorchScript model archive.

        Args:
            path: Path to a .pt/.ptc/.torchscript file.

        Returns:
            List of security findings.
        """
        self.findings = []
        p = Path(path)

        if not p.exists():
            self.findings.append(Finding.artifact(
                rule_id="TS-000", title="File not found",
                description=f"TorchScript file not found: {path}",
                severity=Severity.HIGH, target=path,
            ))
            return self.findings

        if not p.is_file():
            self.findings.append(Finding.artifact(
                rule_id="TS-000", title="Not a file",
                description=f"Path is not a file: {path}",
                severity=Severity.HIGH, target=path,
            ))
            return self.findings

        if not zipfile.is_zipfile(path):
            self.findings.append(Finding.artifact(
                rule_id="TS-050", title="Not a ZIP archive",
                description="TorchScript file is not a valid ZIP archive.",
                severity=Severity.HIGH, target=path,
            ))
            return self.findings

        try:
            with zipfile.ZipFile(path, "r") as zf:
                self._check_path_traversal(zf, path)
                self._check_archive_structure(zf, path)
                self._check_code_files(zf, path)
                self._check_pickle_files(zf, path)
                self._check_custom_ops(zf, path)

        except zipfile.BadZipFile:
            self.findings.append(Finding.artifact(
                rule_id="TS-050", title="Corrupt ZIP archive",
                description="TorchScript file is a corrupt ZIP archive.",
                severity=Severity.HIGH, target=path,
            ))
        except Exception as e:
            self.findings.append(Finding.artifact(
                rule_id="TS-099", title="TorchScript scan error",
                description=f"Failed to scan TorchScript archive: {e}",
                severity=Severity.MEDIUM, target=path,
                evidence=str(e),
            ))

        return self.findings

    def _check_path_traversal(self, zf: zipfile.ZipFile, filepath: str) -> None:
        """Check archive entries for path traversal attacks."""
        for info in zf.infolist():
            name = info.filename
            if ".." in name or name.startswith("/") or name.startswith("\\"):
                self.findings.append(Finding.artifact(
                    rule_id="TS-040",
                    title=f"Path traversal in archive: {name}",
                    description=f"Archive entry '{name}' contains directory traversal. "
                                "This could overwrite files outside the model directory.",
                    severity=Severity.CRITICAL, target=filepath,
                    evidence=f"entry={name}",
                    cwe_ids=["CWE-22"],
                ))

    def _check_archive_structure(self, zf: zipfile.ZipFile, filepath: str) -> None:
        """Analyze the archive structure for anomalies."""
        names = zf.namelist()
        has_code = any(n.startswith("code/") for n in names)

        if not has_code:
            self.findings.append(Finding.artifact(
                rule_id="TS-051", title="Missing code/ directory",
                description="TorchScript archive has no code/ directory — "
                            "may be corrupted or not a TorchScript model.",
                severity=Severity.MEDIUM, target=filepath,
            ))

        for info in zf.infolist():
            if info.is_dir():
                continue

            name = info.filename
            ext = Path(name).suffix.lower()

            if ext in EXECUTABLE_EXTENSIONS and ext not in SAFE_EXTENSIONS:
                self.findings.append(Finding.artifact(
                    rule_id="TS-041",
                    title=f"Executable in archive: {name}",
                    description=f"Archive contains executable file '{name}' "
                                f"with extension '{ext}'.",
                    severity=Severity.HIGH, target=filepath,
                    evidence=f"entry={name}, extension={ext}",
                    cwe_ids=["CWE-94"],
                ))

            if info.file_size > 1_000_000_000:
                self.findings.append(Finding.artifact(
                    rule_id="TS-042",
                    title=f"Oversized entry: {name} ({info.file_size / 1e9:.1f}GB)",
                    description=f"Archive entry '{name}' has uncompressed size "
                                f"{info.file_size / 1e6:.0f}MB — may cause DoS.",
                    severity=Severity.MEDIUM, target=filepath,
                    evidence=f"entry={name}, size={info.file_size}",
                    cwe_ids=["CWE-400"],
                ))

    def _check_code_files(self, zf: zipfile.ZipFile, filepath: str) -> None:
        """Analyze TorchScript source code files for dangerous patterns."""
        code_files = [n for n in zf.namelist() if n.startswith("code/") and n.endswith(".py")]

        for code_file in code_files:
            try:
                content = zf.read(code_file).decode("utf-8", errors="replace")
                self._analyze_code_content(content, code_file, filepath)
            except Exception:
                pass

    def _analyze_code_content(
        self, content: str, source_file: str, filepath: str
    ) -> None:
        """Check TorchScript code for dangerous patterns."""
        content_lower = content.lower()

        for pattern, desc, severity in DANGEROUS_CODE_PATTERNS:
            if pattern.lower() in content_lower:
                line_num = 0
                for i, line in enumerate(content.split("\n"), 1):
                    if pattern.lower() in line.lower():
                        line_num = i
                        break

                self.findings.append(Finding.artifact(
                    rule_id="TS-010",
                    title=f"Dangerous code pattern: {pattern}",
                    description=f"TorchScript code in '{source_file}' contains "
                                f"'{pattern}' ({desc}). This could enable "
                                "arbitrary code execution during model loading.",
                    severity=severity, target=filepath,
                    evidence=f"file={source_file}, line={line_num}, pattern={pattern}",
                    cwe_ids=["CWE-94"],
                ))

        for name in SUSPICIOUS_NAMES:
            if name in content_lower:
                self.findings.append(Finding.artifact(
                    rule_id="TS-011",
                    title=f"Suspicious name in code: {name}",
                    description=f"TorchScript code in '{source_file}' contains "
                                f"suspicious identifier '{name}'.",
                    severity=Severity.HIGH, target=filepath,
                    evidence=f"file={source_file}, name={name}",
                ))

    def _check_pickle_files(self, zf: zipfile.ZipFile, filepath: str) -> None:
        """Analyze pickle files within the archive for exploits."""
        pickle_files = [
            n for n in zf.namelist()
            if n.endswith(".pkl") or n.endswith(".debug_pkl")
        ]

        for pkl_file in pickle_files:
            try:
                data = zf.read(pkl_file)
                self._analyze_pickle_data(data, pkl_file, filepath)
            except Exception:
                pass

    def _analyze_pickle_data(
        self, data: bytes, pkl_name: str, filepath: str
    ) -> None:
        """Check pickle data for dangerous opcodes and imports."""
        self.findings.append(Finding.artifact(
            rule_id="TS-020",
            title=f"Pickle file in archive: {pkl_name}",
            description=f"Archive contains pickle file '{pkl_name}'. "
                        "Pickle deserialization is inherently dangerous "
                        "and can execute arbitrary code.",
            severity=Severity.MEDIUM, target=filepath,
            evidence=f"file={pkl_name}, size={len(data)}",
            cwe_ids=["CWE-502"],
        ))
        self._scan_pickle_globals(data, pkl_name, filepath)

    def _scan_pickle_globals(
        self, data: bytes, pkl_name: str, filepath: str
    ) -> None:
        """Scan pickle data for dangerous GLOBAL imports."""
        offset = 0
        while offset < len(data):
            if data[offset:offset+1] == PICKLE_GLOBAL:
                offset += 1
                nl1 = data.find(b"\n", offset)
                if nl1 == -1:
                    break
                module = data[offset:nl1].decode("utf-8", errors="replace")
                offset = nl1 + 1

                nl2 = data.find(b"\n", offset)
                if nl2 == -1:
                    break
                func = data[offset:nl2].decode("utf-8", errors="replace")
                offset = nl2 + 1

                module_base = module.split(".")[0]
                if module_base in PICKLE_DANGEROUS_MODULES:
                    self.findings.append(Finding.artifact(
                        rule_id="TS-021",
                        title=f"Dangerous pickle import: {module}.{func}",
                        description=f"Pickle file '{pkl_name}' imports "
                                    f"'{module}.{func}' which could execute "
                                    "arbitrary code during deserialization.",
                        severity=Severity.CRITICAL, target=filepath,
                        evidence=f"file={pkl_name}, module={module}, func={func}",
                        cwe_ids=["CWE-502"],
                    ))
            elif data[offset:offset+1] == PICKLE_STACK_GLOBAL:
                self.findings.append(Finding.artifact(
                    rule_id="TS-022",
                    title=f"STACK_GLOBAL opcode in pickle: {pkl_name}",
                    description=f"Pickle file '{pkl_name}' uses STACK_GLOBAL opcode "
                                "(protocol 4+). Requires stack analysis for full audit.",
                    severity=Severity.HIGH, target=filepath,
                    evidence=f"file={pkl_name}, offset=0x{offset:x}",
                    cwe_ids=["CWE-502"],
                ))
                offset += 1
            else:
                offset += 1

    def _check_custom_ops(self, zf: zipfile.ZipFile, filepath: str) -> None:
        """Detect custom C++ operator references in TorchScript code."""
        code_files = [n for n in zf.namelist() if n.startswith("code/") and n.endswith(".py")]

        custom_op_patterns = _ts_rules.get("custom_op_patterns", [
            "torch.ops.",
            "torch._C._jit",
            "torch.classes.",
            "torch.cuda.",
        ])

        for code_file in code_files:
            try:
                content = zf.read(code_file).decode("utf-8", errors="replace")
                for pattern in custom_op_patterns:
                    if pattern in content:
                        self.findings.append(Finding.artifact(
                            rule_id="TS-030",
                            title=f"Custom operator reference: {pattern}",
                            description=f"Code file '{code_file}' references '{pattern}' "
                                        "which may invoke custom C++ operators. "
                                        "Custom ops can execute arbitrary native code.",
                            severity=Severity.HIGH, target=filepath,
                            evidence=f"file={code_file}, pattern={pattern}",
                            cwe_ids=["CWE-94"],
                        ))
            except Exception:
                pass
