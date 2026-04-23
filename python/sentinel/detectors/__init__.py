"""Cross-cutting detector modules — network comm, suspicious symbols, JIT, CVE, secrets in models."""
from __future__ import annotations
import logging
import re
from pathlib import Path
from sentinel.finding import Finding, Severity

logger = logging.getLogger(__name__)


class NetworkCommDetector:
    """URL/IP/socket/DNS detection in model files."""
    URL_RE = re.compile(rb"https?://[^\s\x00\"'<>]{5,200}")
    IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    SOCKET_PATTERNS = [b"socket.socket", b"socket.connect", b"socket.bind", b"socket.listen", b"urllib.request", b"http.client"]
    DNS_PATTERNS = [b"socket.gethostbyname", b"socket.getaddrinfo", b"dns.resolver"]

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = Path(filepath).read_bytes()
        except OSError:
            return findings
        for m in self.URL_RE.finditer(data[:10_000_000]):
            url = m.group().decode(errors="replace")
            if not any(safe in url for safe in ["pytorch.org", "huggingface.co", "tensorflow.org", "github.com"]):
                findings.append(Finding.artifact(rule_id="NET-001", title=f"URL in model: {url[:60]}", description=f"At offset 0x{m.start():x}", severity=Severity.HIGH, target=filepath, evidence=url[:200]))
        for m in self.IP_RE.finditer(data[:10_000_000]):
            ip = m.group().decode()
            parts = ip.split(".")
            if all(0 <= int(p) <= 255 for p in parts) and not ip.startswith(("0.", "127.", "255.")):
                findings.append(Finding.artifact(rule_id="NET-002", title=f"IP address in model: {ip}", description=f"At offset 0x{m.start():x}", severity=Severity.HIGH, target=filepath, evidence=ip))
        for pat in self.SOCKET_PATTERNS + self.DNS_PATTERNS:
            if pat in data:
                findings.append(Finding.artifact(rule_id="NET-003", title=f"Network API in model: {pat.decode()}", description="Model contains network communication code", severity=Severity.CRITICAL, target=filepath, evidence=pat.decode()))
        return findings


class SuspiciousSymbolsDetector:
    """Dangerous import/function call detection."""
    DANGEROUS = [
        (b"__import__", "CRITICAL"), (b"eval(", "CRITICAL"), (b"exec(", "CRITICAL"),
        (b"os.system", "CRITICAL"), (b"os.popen", "CRITICAL"), (b"subprocess.", "CRITICAL"),
        (b"shutil.rmtree", "HIGH"), (b"ctypes.CDLL", "HIGH"), (b"ctypes.cdll", "HIGH"),
        (b"marshal.loads", "CRITICAL"), (b"pickle.loads", "CRITICAL"), (b"shelve.open", "HIGH"),
        (b"importlib.import_module", "HIGH"), (b"builtins.globals", "HIGH"),
        (b"webbrowser.open", "MEDIUM"), (b"pty.spawn", "CRITICAL"), (b"code.interact", "HIGH"),
        (b"compile(", "HIGH"), (b"getattr(", "MEDIUM"), (b"setattr(", "MEDIUM"),
    ]

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = Path(filepath).read_bytes()
        except OSError:
            return findings
        for pat, sev in self.DANGEROUS:
            idx = data.find(pat)
            if idx != -1:
                sev_enum = getattr(Severity, sev)
                findings.append(Finding.artifact(rule_id="SYM-001", title=f"Dangerous symbol: {pat.decode()}", description=f"At offset 0x{idx:x}", severity=sev_enum, target=filepath, evidence=pat.decode()))
        return findings


class JITScriptAnalyzer:
    """TorchScript/JIT security analysis."""
    DANGEROUS_OPS = [b"aten::_prim_", b"prim::PythonOp", b"prim::CallFunction", b"prim::CallMethod", b"aten::_native_"]
    DANGEROUS_CODE = [b"torch.jit._script", b"torch._C._jit_script_compile", b"torch.ops.custom"]

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = Path(filepath).read_bytes()
        except OSError:
            return findings
        for op in self.DANGEROUS_OPS:
            if op in data:
                findings.append(Finding.artifact(rule_id="JIT-001", title=f"Dangerous JIT op: {op.decode()}", description="TorchScript op may execute arbitrary code", severity=Severity.HIGH, target=filepath, evidence=op.decode()))
        for pat in self.DANGEROUS_CODE:
            if pat in data:
                findings.append(Finding.artifact(rule_id="JIT-002", title=f"JIT compilation call: {pat.decode()}", description="Dynamic JIT compilation detected", severity=Severity.MEDIUM, target=filepath))
        return findings


class CVEPatternDetector:
    """Known CVE pattern matching in model files."""
    CVE_PATTERNS = [
        ("CVE-2022-45907", b"torch.load", "PyTorch arbitrary code execution via torch.load"),
        ("CVE-2023-47248", b"pyarrow", "PyArrow IPC deserialization vulnerability"),
        ("CVE-2024-3660", b"keras.*Lambda", "Keras Lambda layer code execution"),
        ("CVE-2024-5480", b"transformers.*pipeline", "Transformers remote code execution"),
        ("CVE-2024-34359", b"llama-cpp", "llama.cpp RCE via GGUF"),
    ]

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = Path(filepath).read_bytes()
        except OSError:
            return findings
        for cve_id, pattern, desc in self.CVE_PATTERNS:
            if pattern in data:
                findings.append(Finding.artifact(rule_id=f"CVE-{cve_id}", title=f"Potential {cve_id}", description=desc, severity=Severity.HIGH, target=filepath, evidence=pattern.decode(errors="replace")))
        return findings


class SecretsInModelsDetector:
    """API keys/tokens embedded in model weights/metadata."""
    PATTERNS = [
        ("AWS Key", re.compile(rb"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}")),
        ("OpenAI Key", re.compile(rb"sk-[A-Za-z0-9]{20,}T3BlbkFJ")),
        ("GitHub Token", re.compile(rb"ghp_[A-Za-z0-9]{36}")),
        ("Private Key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
        ("Generic Secret", re.compile(rb"(?i)(?:api[_-]?key|secret[_-]?key|password|token)\s*[=:]\s*['\"][A-Za-z0-9_-]{20,}['\"]")),
    ]

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = Path(filepath).read_bytes()
        except OSError:
            return findings
        for label, pat in self.PATTERNS:
            for m in pat.finditer(data[:50_000_000]):
                findings.append(Finding.artifact(rule_id="MODEL-SECRET-001", title=f"Secret in model: {label}", description=f"At offset 0x{m.start():x}", severity=Severity.CRITICAL, target=filepath, evidence=f"{label} at 0x{m.start():x}", cwe_ids=["CWE-798"]))
        return findings
