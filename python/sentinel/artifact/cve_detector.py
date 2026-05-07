"""CVE attribution detector — maps model/code patterns to known CVEs.

Multi-line context-aware detection that checks for indicator COMBINATIONS,
not single keywords. Each CVE match includes CVSS, CWE, and remediation.

"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..finding import Finding, Location, Severity

logger = logging.getLogger(__name__)


@dataclass
class CVEEntry:
    cve_id: str
    description: str
    severity: Severity
    cvss: float
    cwe_ids: list[str]
    affected: str
    remediation: str
    indicators: list[list[str]]  # List of indicator groups (ANY group match triggers)
    binary_indicators: list[list[bytes]] = field(default_factory=list)


# CVE database with multi-line context-aware detection
CVE_DATABASE: list[CVEEntry] = [
    CVEEntry(
        cve_id="CVE-2024-34359",
        description=(
            "Llama Drama — Jinja2 SSTI in llama-cpp-python chat_template. "
            "Arbitrary code execution via crafted GGUF chat_template metadata."
        ),
        severity=Severity.CRITICAL,
        cvss=9.8,
        cwe_ids=["CWE-94", "CWE-1336"],
        affected="llama-cpp-python<0.2.72",
        remediation="Upgrade to llama-cpp-python>=0.2.72. Use jinja2.sandbox.SandboxedEnvironment.",
        indicators=[
            ["chat_template", "__class__"],
            ["chat_template", "__mro__"],
            ["chat_template", "__subclasses__"],
            ["chat_template", "__globals__"],
            ["chat_template", "__builtins__"],
            ["chat_template", "os.system"],
            ["chat_template", "subprocess"],
            ["chat_template", "|attr("],
        ],
    ),
    CVEEntry(
        cve_id="CVE-2020-13092",
        description=(
            "sklearn/joblib deserialization vulnerability. "
            "Malicious pickle payload via joblib.load() in scikit-learn models."
        ),
        severity=Severity.CRITICAL,
        cvss=9.8,
        cwe_ids=["CWE-502"],
        affected="scikit-learn (all versions using joblib.load on untrusted data)",
        remediation="Use skops.io or safetensors for model serialization.",
        indicators=[
            ["sklearn", "os.system"],
            ["sklearn", "subprocess"],
            ["sklearn", "eval("],
            ["sklearn", "exec("],
            ["joblib", "os.system"],
            ["joblib", "subprocess"],
            ["joblib.load", "__reduce__"],
        ],
    ),
    CVEEntry(
        cve_id="CVE-2024-34997",
        description=(
            "joblib NumpyArrayWrapper arbitrary code execution. "
            "Crafted NumpyArrayWrapper in joblib files can execute code during load."
        ),
        severity=Severity.CRITICAL,
        cvss=9.8,
        cwe_ids=["CWE-502"],
        affected="joblib (all versions with NumpyArrayWrapper)",
        remediation="Do not use joblib.load on untrusted files. Use safetensors.",
        indicators=[
            ["NumpyArrayWrapper", "pickle"],
            ["NumpyArrayWrapper", "system"],
            ["NumpyArrayWrapper", "__reduce__"],
        ],
    ),
    CVEEntry(
        cve_id="CVE-2026-24747",
        description=(
            "PyTorch weights_only bypass via _rebuild_tensor. "
            "Crafted pickle with _rebuild_tensor + SETITEM can bypass weights_only=True."
        ),
        severity=Severity.CRITICAL,
        cvss=9.1,
        cwe_ids=["CWE-502"],
        affected="PyTorch<2.6",
        remediation="Upgrade to PyTorch>=2.6. Audit allowlisted globals.",
        indicators=[
            ["_rebuild_tensor", "SETITEM"],
            ["_rebuild_tensor", "storage"],
            ["weights_only", "bypass"],
        ],
        binary_indicators=[
            [b"_rebuild_tensor", b"\x93"],  # STACK_GLOBAL + known class
        ],
    ),
    CVEEntry(
        cve_id="CVE-2022-45907",
        description=(
            "PyTorch torch.jit eval injection. "
            "parse_type_line passes user input to eval() in TorchScript."
        ),
        severity=Severity.HIGH,
        cvss=8.8,
        cwe_ids=["CWE-94"],
        affected="PyTorch<1.13.1",
        remediation="Upgrade to PyTorch>=1.13.1.",
        indicators=[
            ["parse_type_line", "eval"],
            ["torch.jit", "eval("],
            ["torchscript", "eval("],
        ],
    ),
    CVEEntry(
        cve_id="CVE-2024-5480",
        description=(
            "PyTorch distributed RPC remote code execution. "
            "rpc_sync/rpc_async can execute arbitrary code on remote workers."
        ),
        severity=Severity.CRITICAL,
        cvss=9.8,
        cwe_ids=["CWE-94"],
        affected="PyTorch distributed (all versions)",
        remediation="Restrict RPC endpoints. Use TLS authentication.",
        indicators=[
            ["rpc_sync", "eval"],
            ["rpc_async", "exec"],
            ["rpc_sync", "system"],
            ["rpc_async", "system"],
        ],
    ),
    CVEEntry(
        cve_id="CVE-2024-48063",
        description=(
            "PyTorch RemoteModule pickle RCE. "
            "RemoteModule uses __reduce__ for serialization, enabling code execution."
        ),
        severity=Severity.HIGH,
        cvss=8.1,
        cwe_ids=["CWE-502"],
        affected="PyTorch distributed (all versions with RemoteModule)",
        remediation="Do not deserialize untrusted RemoteModule objects.",
        indicators=[
            ["RemoteModule", "__reduce__"],
            ["RemoteModule", "pickle"],
        ],
    ),
    CVEEntry(
        cve_id="CVE-2024-3568",
        description=(
            "HuggingFace Transformers arbitrary code execution via "
            "malicious model card/config in from_pretrained()."
        ),
        severity=Severity.HIGH,
        cvss=8.1,
        cwe_ids=["CWE-94"],
        affected="transformers (trust_remote_code=True)",
        remediation="Never use trust_remote_code=True on untrusted models.",
        indicators=[
            ["trust_remote_code", "True"],
            ["trust_remote_code", "true"],
            ["from_pretrained", "trust_remote_code"],
        ],
    ),
    CVEEntry(
        cve_id="CVE-2023-43654",
        description=(
            "PyTorch TorchServe SSRF/RCE via model URL loading. "
            "Unrestricted model URL in management API allows SSRF/RCE."
        ),
        severity=Severity.CRITICAL,
        cvss=9.8,
        cwe_ids=["CWE-918"],
        affected="TorchServe<0.8.2",
        remediation="Upgrade TorchServe>=0.8.2. Restrict allowed_urls.",
        indicators=[
            ["torchserve", "register"],
            ["model_url", "http"],
        ],
    ),
    CVEEntry(
        cve_id="CVE-2024-27132",
        description=(
            "MLflow XSS via logged model artifacts. "
            "Malicious HTML in artifact names allows stored XSS."
        ),
        severity=Severity.MEDIUM,
        cvss=6.1,
        cwe_ids=["CWE-79"],
        affected="MLflow<2.11.1",
        remediation="Upgrade MLflow>=2.11.1. Sanitize artifact names.",
        indicators=[
            ["mlflow", "<script"],
            ["mlflow", "javascript:"],
            ["artifact", "<script"],
        ],
    ),
]


class CVEDetector:
    """Maps file contents to known ML/AI CVEs via multi-indicator matching."""

    def __init__(self, cve_db: Optional[list[CVEEntry]] = None):
        self.cve_db = cve_db or CVE_DATABASE

    def scan_file(self, file_path: str | Path) -> list[Finding]:
        """Scan a file for known CVE indicators."""
        path = Path(file_path)
        source = str(path)
        findings: list[Finding] = []

        if not path.exists():
            return []

        try:
            # Read text content (for text-based indicators)
            text_content: Optional[str] = None
            binary_content: Optional[bytes] = None

            file_size = path.stat().st_size
            if file_size > 50 * 1024 * 1024:  # Skip files > 50MB for text scan
                # Binary-only scan
                with open(path, "rb") as f:
                    binary_content = f.read(min(file_size, 10 * 1024 * 1024))
            else:
                with open(path, "rb") as f:
                    binary_content = f.read()
                try:
                    text_content = binary_content.decode("utf-8", errors="replace")
                except Exception:
                    pass

            for cve in self.cve_db:
                matched = self._check_cve(cve, text_content, binary_content)
                if matched:
                    indicators_str, group_desc = matched
                    findings.append(Finding.artifact(
                        rule_id=f"CVE-{cve.cve_id.replace('CVE-', '')}",
                        title=f"{cve.cve_id}: {cve.description[:80]}",
                        description=(
                            f"{cve.description}\n\n"
                            f"Affected: {cve.affected}\n"
                            f"Remediation: {cve.remediation}"
                        ),
                        severity=cve.severity,
                        confidence=0.8,
                        target=source,
                        evidence=(
                            f"Matched indicators: {indicators_str}. "
                            f"CVSS: {cve.cvss}"
                        ),
                        location=Location(file=source),
                        cwe_ids=cve.cwe_ids,
                        tags=[
                            f"cve:{cve.cve_id}",
                            f"cvss:{cve.cvss}",
                            "mitre-atlas:AML.T0010",
                        ],
                    ))
        except OSError as exc:
            logger.debug("Could not read %s: %s", path, exc)

        return findings

    def _check_cve(
        self, cve: CVEEntry,
        text: Optional[str], binary: Optional[bytes],
    ) -> Optional[tuple[str, str]]:
        """Check if a CVE's indicator groups match the content."""
        text_lower = text.lower() if text else ""

        # Check text indicator groups
        for group in cve.indicators:
            if all(ind.lower() in text_lower for ind in group):
                return ", ".join(group), "text"

        # Check binary indicator groups
        if binary:
            for group in cve.binary_indicators:
                if all(ind in binary for ind in group):
                    return ", ".join(repr(b) for b in group), "binary"

        return None

    def scan_text(self, text: str, source: str = "<text>") -> list[Finding]:
        """Scan text content (code, configs) for CVE indicators."""
        findings: list[Finding] = []
        text_lower = text.lower()

        for cve in self.cve_db:
            for group in cve.indicators:
                if all(ind.lower() in text_lower for ind in group):
                    findings.append(Finding.artifact(
                        rule_id=f"CVE-{cve.cve_id.replace('CVE-', '')}",
                        title=f"{cve.cve_id}: {cve.description[:80]}",
                        description=(
                            f"{cve.description}\n\n"
                            f"Affected: {cve.affected}\n"
                            f"Remediation: {cve.remediation}"
                        ),
                        severity=cve.severity,
                        confidence=0.75,
                        target=source,
                        evidence=f"Matched: {', '.join(group)}. CVSS: {cve.cvss}",
                        location=Location(file=source),
                        cwe_ids=cve.cwe_ids,
                        tags=[f"cve:{cve.cve_id}", f"cvss:{cve.cvss}"],
                    ))
                    break  # One match per CVE is enough

        return findings
