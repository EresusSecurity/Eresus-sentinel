"""
Eresus Sentinel — PyTorch Reverse Engine.

Inspects PyTorch .pt/.pth ZIP archives for pickle payloads,
path traversal, unexpected executables, and zip bombs.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

from ..finding import Finding, Severity
from .format_common import FormatReport


class PyTorchReverseEngine:
    """Deep-inspect PyTorch .pt/.pth files."""

    def __init__(self) -> None:
        self.findings: list[Finding] = []

    def analyze(self, filepath: str) -> FormatReport:
        self.findings = []
        path = Path(filepath)
        report = FormatReport(
            format_name="PyTorch", file_path=filepath,
            file_size=path.stat().st_size if path.exists() else 0,
        )

        if not path.exists():
            report.findings = self.findings
            return report

        if not zipfile.is_zipfile(filepath):
            self.findings.append(Finding.artifact(
                rule_id="FMT-200", title="PyTorch file is not a valid ZIP",
                description="PyTorch .pt/.pth files should be ZIP archives. May be raw pickle.",
                severity=Severity.HIGH, target=filepath,
            ))
            report.findings = self.findings
            return report

        try:
            with zipfile.ZipFile(filepath, "r") as zf:
                names = zf.namelist()
                report.metadata["zip_entries"] = names
                report.metadata["zip_entry_count"] = len(names)

                pkl_files = [n for n in names if n.endswith(".pkl")]
                data_files = [n for n in names if "/data/" in n or n.startswith("data/")]
                other_files = [n for n in names if n not in pkl_files and n not in data_files]

                report.metadata["pickle_files"] = pkl_files
                report.metadata["data_files"] = len(data_files)
                report.metadata["other_files"] = other_files

                if pkl_files:
                    self.findings.append(Finding.artifact(
                        rule_id="FMT-210",
                        title="PyTorch file contains pickle payload",
                        description=f"Found {len(pkl_files)} pickle file(s): {pkl_files}. "
                                    "Pickle enables arbitrary code execution.",
                        severity=Severity.HIGH, target=filepath,
                        evidence=f"pickle_files={pkl_files}",
                    ))

                for other in other_files:
                    if any(other.endswith(ext) for ext in [".py", ".sh", ".bat", ".exe", ".dll"]):
                        self.findings.append(Finding.artifact(
                            rule_id="FMT-211",
                            title=f"Unexpected file in PyTorch archive: {other}",
                            description=f"Archive contains unexpected file '{other}' — possible backdoor.",
                            severity=Severity.CRITICAL, target=filepath,
                            evidence=f"file={other}",
                        ))

                for name in names:
                    if ".." in name or name.startswith("/"):
                        self.findings.append(Finding.artifact(
                            rule_id="FMT-212",
                            title=f"Path traversal in PyTorch archive: {name}",
                            description=f"ZIP entry '{name}' — ZipSlip attack vector.",
                            severity=Severity.CRITICAL, target=filepath,
                            evidence=f"entry={name}",
                        ))

                for info in zf.infolist():
                    if info.compress_size > 0:
                        ratio = info.file_size / info.compress_size
                        if ratio > 1000:
                            self.findings.append(Finding.artifact(
                                rule_id="FMT-213",
                                title=f"Suspicious compression ratio: {info.filename}",
                                description=f"Entry '{info.filename}' ratio {ratio:.0f}:1 — possible bomb.",
                                severity=Severity.HIGH, target=filepath,
                                evidence=f"entry={info.filename}, ratio={ratio:.0f}:1",
                            ))

                # Symlink detection via external attributes
                for info in zf.infolist():
                    # Unix symlinks: high 16 bits of external_attr encode st_mode
                    # 0o120000 = symlink flag in st_mode
                    unix_mode = (info.external_attr >> 16) & 0xFFFF
                    if unix_mode != 0 and (unix_mode & 0o170000) == 0o120000:
                        self.findings.append(Finding.artifact(
                            rule_id="FMT-214",
                            title=f"Symlink in PyTorch archive: {info.filename}",
                            description=(
                                f"ZIP entry '{info.filename}' is a symbolic link. "
                                f"Symlinks in model archives can escape the extraction "
                                f"directory and overwrite arbitrary files."
                            ),
                            severity=Severity.CRITICAL, target=filepath,
                            evidence=f"entry={info.filename}, unix_mode=0o{unix_mode:o}",
                            cwe_ids=["CWE-59"],
                        ))

                # Inline pickle dangerous import scan
                _PICKLE_DANGER = [
                    b"__import__", b"os.system", b"subprocess",
                    b"builtins.exec", b"builtins.eval", b"nt.system",
                    b"posixpath", b"webbrowser.open", b"shutil.rmtree",
                    b"socket.socket", b"http.client",
                ]
                for pkl_name in pkl_files:
                    try:
                        pkl_data = zf.read(pkl_name)
                        if len(pkl_data) > 10_000_000:
                            continue  # skip very large files to avoid DoS
                        matched = [
                            p.decode("utf-8", errors="replace")
                            for p in _PICKLE_DANGER
                            if p in pkl_data
                        ]
                        if matched:
                            self.findings.append(Finding.artifact(
                                rule_id="FMT-215",
                                title=f"Dangerous imports in pickle payload: {pkl_name}",
                                description=(
                                    f"Pickle file '{pkl_name}' contains dangerous import "
                                    f"patterns: {', '.join(matched[:5])}. These enable "
                                    f"arbitrary code execution on torch.load()."
                                ),
                                severity=Severity.CRITICAL, target=filepath,
                                evidence=f"file={pkl_name}, patterns={matched[:5]}",
                                cwe_ids=["CWE-502"],
                            ))
                    except Exception:
                        pass

                # data.pkl size anomaly — if data.pkl is very large relative to
                # data/ tensor storage, it may contain embedded payloads
                for pkl_name in pkl_files:
                    if "data.pkl" in pkl_name:
                        try:
                            info = zf.getinfo(pkl_name)
                            if info.file_size > 50_000_000:  # >50MB data.pkl
                                self.findings.append(Finding.artifact(
                                    rule_id="FMT-216",
                                    title=f"Oversized data.pkl: {info.file_size / 1e6:.1f}MB",
                                    description=(
                                        f"data.pkl is {info.file_size / 1e6:.1f}MB — legitimate "
                                        f"PyTorch data.pkl files are typically small. An oversized "
                                        f"data.pkl may contain embedded executable payloads."
                                    ),
                                    severity=Severity.MEDIUM, target=filepath,
                                    evidence=f"file={pkl_name}, size={info.file_size}",
                                ))
                        except KeyError:
                            pass

        except zipfile.BadZipFile as e:
            self.findings.append(Finding.artifact(
                rule_id="FMT-201", title="Corrupted PyTorch ZIP archive",
                description=f"ZIP archive corrupted: {e}",
                severity=Severity.MEDIUM, target=filepath, evidence=str(e),
            ))

        report.findings = self.findings
        return report

