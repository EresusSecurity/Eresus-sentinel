"""Tests for the TorchScript Scanner.

Uses synthetic ZIP-based archives — no torch dependency required.
"""

import zipfile
from pathlib import Path

import pytest

from sentinel.artifact.torchscript_scanner import TorchScriptScanner
from sentinel.finding import Severity


# ======================== HELPERS ========================

def _create_torchscript_zip(
    tmp_path, name: str = "model.pt",
    code_files: dict = None,
    pickle_files: dict = None,
    extra_files: dict = None,
) -> str:
    """Create a TorchScript-like ZIP archive."""
    fpath = tmp_path / name
    with zipfile.ZipFile(str(fpath), "w") as zf:
        # Add code/ directory entries
        if code_files:
            for fname, content in code_files.items():
                zf.writestr(f"code/{fname}", content)
        else:
            # Minimal valid TorchScript structure
            zf.writestr("code/__torch__/model.py", "def forward(self, x):\n  return x\n")
            zf.writestr("code/__torch__.py", "")

        # Add pickle files
        if pickle_files:
            for fname, content in pickle_files.items():
                zf.writestr(fname, content)

        # Add extra files
        if extra_files:
            for fname, content in extra_files.items():
                if isinstance(content, str):
                    zf.writestr(fname, content)
                else:
                    zf.writestr(fname, content)

    return str(fpath)


def _make_pickle_with_global(module: str, func: str) -> bytes:
    """Create minimal pickle data with a GLOBAL opcode."""
    # Protocol 0-2 GLOBAL: 'c' + module + '\n' + func + '\n'
    data = bytearray()
    data.append(0x80)  # PROTO opcode
    data.append(2)     # protocol 2
    data.append(ord("c"))  # GLOBAL
    data.extend(module.encode("utf-8"))
    data.append(ord("\n"))
    data.extend(func.encode("utf-8"))
    data.append(ord("\n"))
    data.append(ord("."))  # STOP
    return bytes(data)


def _make_pickle_with_stack_global() -> bytes:
    """Create pickle data with STACK_GLOBAL opcode (protocol 4)."""
    data = bytearray()
    data.append(0x80)  # PROTO
    data.append(4)     # protocol 4
    data.append(0x93)  # STACK_GLOBAL
    data.append(ord("."))  # STOP
    return bytes(data)


# ======================== TEST CASES ========================

class TestTorchScriptScanner:
    def setup_method(self):
        self.scanner = TorchScriptScanner()

    def test_clean_model_no_critical_findings(self, tmp_path):
        """Clean TorchScript model → no CRITICAL/HIGH findings."""
        fpath = _create_torchscript_zip(tmp_path)
        findings = self.scanner.scan_file(fpath)
        critical_high = [f for f in findings
                         if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(critical_high) == 0

    def test_os_system_in_code_detected(self, tmp_path):
        """TorchScript code with os.system → CRITICAL finding."""
        fpath = _create_torchscript_zip(tmp_path, code_files={
            "__torch__/model.py": """
def forward(self, x):
    os.system('whoami')
    return x
""",
        })
        findings = self.scanner.scan_file(fpath)
        code_findings = [f for f in findings if f.rule_id == "TS-010"]
        assert len(code_findings) >= 1
        assert code_findings[0].severity == Severity.CRITICAL
        assert "os.system" in code_findings[0].evidence

    def test_eval_in_code_detected(self, tmp_path):
        """TorchScript code with eval() → CRITICAL finding."""
        fpath = _create_torchscript_zip(tmp_path, code_files={
            "__torch__/model.py": "x = eval('malicious_code')\n",
        })
        findings = self.scanner.scan_file(fpath)
        code_findings = [f for f in findings
                         if f.rule_id == "TS-010" and "eval(" in f.evidence]
        assert len(code_findings) >= 1
        assert code_findings[0].severity == Severity.CRITICAL

    def test_pickle_global_os_detected(self, tmp_path):
        """Pickle file with GLOBAL os.system → CRITICAL finding."""
        pkl_data = _make_pickle_with_global("os", "system")
        fpath = _create_torchscript_zip(tmp_path, pickle_files={
            "constants.pkl": pkl_data,
        })
        findings = self.scanner.scan_file(fpath)
        pkl_findings = [f for f in findings if f.rule_id == "TS-021"]
        assert len(pkl_findings) >= 1
        assert pkl_findings[0].severity == Severity.CRITICAL
        assert "os" in pkl_findings[0].evidence

    def test_pickle_stack_global_detected(self, tmp_path):
        """Pickle file with STACK_GLOBAL opcode → HIGH finding."""
        pkl_data = _make_pickle_with_stack_global()
        fpath = _create_torchscript_zip(tmp_path, pickle_files={
            "data.pkl": pkl_data,
        })
        findings = self.scanner.scan_file(fpath)
        stack_findings = [f for f in findings if f.rule_id == "TS-022"]
        assert len(stack_findings) >= 1
        assert stack_findings[0].severity == Severity.HIGH

    def test_path_traversal_detected(self, tmp_path):
        """Archive entry with ../ → CRITICAL finding."""
        fpath = tmp_path / "evil.pt"
        with zipfile.ZipFile(str(fpath), "w") as zf:
            zf.writestr("code/__torch__/model.py", "pass")
            zf.writestr("../../etc/passwd", "root:x:0:0")
        findings = self.scanner.scan_file(str(fpath))
        trav = [f for f in findings if f.rule_id == "TS-040"]
        assert len(trav) >= 1
        assert trav[0].severity == Severity.CRITICAL
        assert "CWE-22" in trav[0].cwe_ids

    def test_executable_in_archive_detected(self, tmp_path):
        """Archive with executable file → HIGH finding."""
        fpath = _create_torchscript_zip(tmp_path, extra_files={
            "code/__torch__/model.py": "pass",
            "exploit.sh": "#!/bin/bash\nrm -rf /",
        })
        findings = self.scanner.scan_file(fpath)
        exe = [f for f in findings if f.rule_id == "TS-041"]
        assert len(exe) >= 1
        assert exe[0].severity == Severity.HIGH

    def test_custom_ops_detected(self, tmp_path):
        """TorchScript code referencing custom ops → HIGH finding."""
        fpath = _create_torchscript_zip(tmp_path, code_files={
            "__torch__/model.py": """
def forward(self, x):
    return torch.ops.custom_ns.my_op(x)
""",
        })
        findings = self.scanner.scan_file(fpath)
        custom = [f for f in findings if f.rule_id == "TS-030"]
        assert len(custom) >= 1
        assert custom[0].severity == Severity.HIGH

    def test_suspicious_name_in_code(self, tmp_path):
        """Code with suspicious variable name → finding."""
        fpath = _create_torchscript_zip(tmp_path, code_files={
            "__torch__/model.py": "backdoor_layer = self.layer(x)\n",
        })
        findings = self.scanner.scan_file(fpath)
        sus = [f for f in findings if f.rule_id == "TS-011"]
        assert len(sus) >= 1
        assert "backdoor" in sus[0].evidence

    def test_finding_has_cwe(self, tmp_path):
        """TorchScript findings include CWE IDs."""
        fpath = _create_torchscript_zip(tmp_path, code_files={
            "__torch__/model.py": "os.system('pwd')\n",
        })
        findings = self.scanner.scan_file(fpath)
        code_findings = [f for f in findings if f.rule_id == "TS-010"]
        assert len(code_findings) > 0
        assert "CWE-94" in code_findings[0].cwe_ids

    def test_nonexistent_file(self):
        """Scanning nonexistent file → error finding."""
        findings = self.scanner.scan_file("/nonexistent/model.pt")
        assert len(findings) == 1
        assert findings[0].rule_id == "TS-000"

    def test_not_a_zip(self, tmp_path):
        """Scanning a non-ZIP file → error finding."""
        fpath = tmp_path / "model.pt"
        fpath.write_bytes(b"this is not a zip file")
        findings = self.scanner.scan_file(str(fpath))
        assert any(f.rule_id == "TS-050" for f in findings)

    def test_safe_pickle_import(self, tmp_path):
        """Pickle with safe import (torch) → no CRITICAL finding."""
        pkl_data = _make_pickle_with_global("torch._utils", "_rebuild_tensor_v2")
        fpath = _create_torchscript_zip(tmp_path, pickle_files={
            "constants.pkl": pkl_data,
        })
        findings = self.scanner.scan_file(fpath)
        dangerous = [f for f in findings if f.rule_id == "TS-021"]
        assert len(dangerous) == 0
