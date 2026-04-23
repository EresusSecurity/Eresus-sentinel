"""LightGBM model scanner (.lgb, .lightgbm, .txt model files)."""
from __future__ import annotations
import logging
import re
from pathlib import Path
from ..finding import Finding, Severity

logger = logging.getLogger(__name__)

LGBM_HEADER_MARKERS = ["tree", "version=", "num_class=", "num_tree_per_iteration="]
SUSPICIOUS_FEATURE_PATTERNS = [
    re.compile(r"<script[^>]*>", re.IGNORECASE),
    re.compile(r"javascript:", re.IGNORECASE),
    re.compile(r"on\w+=", re.IGNORECASE),
    re.compile(r"__import__"),
    re.compile(r"eval\s*\("),
    re.compile(r"exec\s*\("),
    re.compile(r"os\.system"),
    re.compile(r"subprocess"),
]
PICKLE_MARKERS = [b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"]


class LightGBMScanner:
    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        if not path.exists():
            return findings
        suffix = path.suffix.lower()
        if suffix not in (".lgb", ".lightgbm"):
            return findings

        try:
            data = path.read_bytes()
        except OSError as e:
            logger.warning("Cannot read %s: %s", filepath, e)
            return findings

        is_text = self._is_text_format(data)
        if is_text:
            text = data.decode(errors="replace")
            self._check_text_format(text, filepath, findings)
        else:
            self._check_binary_format(data, filepath, findings)

        self._check_pickle_inside(data, filepath, findings)
        self._check_embedded_executables(data, filepath, findings)
        return findings

    def _is_text_format(self, data: bytes) -> bool:
        try:
            header = data[:1000].decode("utf-8")
            return any(m in header for m in LGBM_HEADER_MARKERS)
        except UnicodeDecodeError:
            return False

    def _check_text_format(self, text: str, fp: str, findings: list[Finding]) -> None:
        lines = text.split("\n")
        feature_section = False
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("feature_names="):
                feature_section = True
                feature_str = stripped[len("feature_names="):]
                features = feature_str.split(" ")
                for feat in features:
                    for pat in SUSPICIOUS_FEATURE_PATTERNS:
                        if pat.search(feat):
                            findings.append(Finding.artifact(
                                rule_id="LGBM-001",
                                title="Malicious feature name in LightGBM model",
                                description=f"Feature name contains injection payload: {feat[:100]}",
                                severity=Severity.HIGH, target=fp,
                                evidence=feat[:200], cwe_ids=["CWE-79"],
                            ))

            if stripped.startswith("objective="):
                obj = stripped[len("objective="):]
                if any(d in obj for d in ["system", "exec", "eval", "import"]):
                    findings.append(Finding.artifact(
                        rule_id="LGBM-002",
                        title="Suspicious objective function in LightGBM",
                        description=f"Objective contains dangerous reference: {obj}",
                        severity=Severity.CRITICAL, target=fp,
                        evidence=obj[:200],
                    ))

            if stripped.startswith("num_class="):
                try:
                    num_class = int(stripped.split("=")[1])
                    if num_class > 100000:
                        findings.append(Finding.artifact(
                            rule_id="LGBM-003",
                            title="Abnormal num_class in LightGBM model",
                            description=f"num_class={num_class} is suspiciously large",
                            severity=Severity.MEDIUM, target=fp,
                            evidence=stripped,
                        ))
                except ValueError:
                    pass

            if stripped.startswith("num_trees=") or stripped.startswith("num_tree_per_iteration="):
                try:
                    val = int(stripped.split("=")[1])
                    if val > 1000000:
                        findings.append(Finding.artifact(
                            rule_id="LGBM-004",
                            title="Abnormal tree count in LightGBM model",
                            description=f"{stripped} — unusually high",
                            severity=Severity.MEDIUM, target=fp,
                            evidence=stripped,
                        ))
                except ValueError:
                    pass

        for pat in SUSPICIOUS_FEATURE_PATTERNS:
            m = pat.search(text)
            if m:
                findings.append(Finding.artifact(
                    rule_id="LGBM-005",
                    title="Code injection pattern in LightGBM text model",
                    description=f"Pattern '{pat.pattern}' found in model text",
                    severity=Severity.HIGH, target=fp,
                    evidence=m.group()[:200],
                ))

    def _check_binary_format(self, data: bytes, fp: str, findings: list[Finding]) -> None:
        dangerous = [b"__import__", b"os.system", b"eval(", b"exec(", b"subprocess"]
        for pat in dangerous:
            idx = data.find(pat)
            if idx != -1:
                findings.append(Finding.artifact(
                    rule_id="LGBM-006",
                    title=f"Suspicious string in LightGBM binary: {pat.decode()}",
                    description=f"Found at offset 0x{idx:x}",
                    severity=Severity.HIGH, target=fp,
                    evidence=f"offset=0x{idx:x}",
                ))

    def _check_pickle_inside(self, data: bytes, fp: str, findings: list[Finding]) -> None:
        for marker in PICKLE_MARKERS:
            idx = data.find(marker)
            if idx != -1:
                findings.append(Finding.artifact(
                    rule_id="LGBM-007", title="Pickle stream inside LightGBM model",
                    description=f"Pickle data at offset 0x{idx:x}",
                    severity=Severity.CRITICAL, target=fp,
                    evidence=f"offset=0x{idx:x}", cwe_ids=["CWE-502"],
                ))
                break

    def _check_embedded_executables(self, data: bytes, fp: str, findings: list[Finding]) -> None:
        for label, magic in [("ELF", b"\x7fELF"), ("PE", b"MZ")]:
            idx = data.find(magic)
            if idx > 10:
                findings.append(Finding.artifact(
                    rule_id="LGBM-008",
                    title=f"Embedded {label} executable in LightGBM model",
                    description=f"{label} binary at offset 0x{idx:x}",
                    severity=Severity.CRITICAL, target=fp,
                    evidence=f"offset=0x{idx:x}", cwe_ids=["CWE-506"],
                ))
