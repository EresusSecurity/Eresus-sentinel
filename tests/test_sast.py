"""
Unit tests for the SAST Engine.
"""

import os
import tempfile
import unittest

from sentinel.sast.analyzer import SASTAnalyzer
from sentinel.finding import Severity


class TestSASTAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = SASTAnalyzer()

    def _write_temp_py(self, code: str) -> str:
        """Write code to a temp .py file and return path."""
        f = tempfile.NamedTemporaryFile(
            suffix=".py", mode="w", delete=False, encoding="utf-8"
        )
        f.write(code)
        f.close()
        return f.name

    def test_unsafe_pickle_load(self):
        path = self._write_temp_py("import pickle\ndata = pickle.load(open('model.pkl', 'rb'))")
        findings = self.analyzer.scan_path(path)
        os.unlink(path)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("SAST-001", rule_ids)

    def test_unsafe_torch_load(self):
        path = self._write_temp_py("import torch\nmodel = torch.load('model.pt')")
        findings = self.analyzer.scan_path(path)
        os.unlink(path)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("SAST-002", rule_ids)  # torch.load rule

    def test_hardcoded_api_key(self):
        path = self._write_temp_py('api_key = "sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890ab"')
        findings = self.analyzer.scan_path(path)
        os.unlink(path)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("SAST-030", rule_ids)  # hardcoded OpenAI key
        key_finding = [f for f in findings if f.rule_id == "SAST-030"][0]
        self.assertEqual(key_finding.severity, Severity.CRITICAL)

    def test_unsafe_eval_output(self):
        path = self._write_temp_py("result = eval(response.text)")
        findings = self.analyzer.scan_path(path)
        os.unlink(path)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("SAST-020", rule_ids)  # eval() rule

    def test_clean_code_no_findings(self):
        path = self._write_temp_py("x = 1 + 2\nprint(x)")
        findings = self.analyzer.scan_path(path)
        os.unlink(path)
        self.assertEqual(len(findings), 0)

    def test_scan_directory(self):
        """Scanning a directory should find issues in all files."""
        tmpdir = tempfile.mkdtemp()
        with open(os.path.join(tmpdir, "bad.py"), "w") as f:
            f.write("eval(response)")
        with open(os.path.join(tmpdir, "safe.py"), "w") as f:
            f.write("print('hello')")

        findings = self.analyzer.scan_path(tmpdir)

        os.unlink(os.path.join(tmpdir, "bad.py"))
        os.unlink(os.path.join(tmpdir, "safe.py"))
        os.rmdir(tmpdir)

        # Should find issue in bad.py but not safe.py
        self.assertGreater(len(findings), 0)

    def test_finding_has_location(self):
        path = self._write_temp_py("import pickle\ndata = pickle.load(f)")
        findings = self.analyzer.scan_path(path)
        os.unlink(path)
        if findings:
            self.assertIsNotNone(findings[0].location)
            self.assertIsNotNone(findings[0].location.line_start)


if __name__ == "__main__":
    unittest.main()
