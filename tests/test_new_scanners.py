"""
Unit tests for new artifact scanners:
- KerasScanner
- ONNXScanner
- ArchiveSlipDetector
- HuggingFaceScanner
"""

import json
import os
import struct
import tarfile
import tempfile
import unittest
import zipfile

from sentinel.artifact.keras_scanner import KerasScanner
from sentinel.artifact.onnx_scanner import ONNXScanner
from sentinel.artifact.archive_slip import ArchiveSlipDetector
from sentinel.artifact.huggingface_scanner import HuggingFaceScanner
from sentinel.finding import Severity


class TestKerasScanner(unittest.TestCase):

    def setUp(self):
        self.scanner = KerasScanner()

    def test_lambda_layer_detected(self):
        """Lambda layers in .keras files should be flagged as CRITICAL."""
        config = {
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "module": "keras.layers",
                        "config": {
                            "function": {
                                "class_name": "function",
                                "config": {
                                    "code": "YWRkX3R3bw==",  # base64 bytecode
                                },
                            },
                        },
                    }
                ]
            },
        }
        f = tempfile.NamedTemporaryFile(suffix=".keras", delete=False)
        with zipfile.ZipFile(f.name, "w") as zf:
            zf.writestr("config.json", json.dumps(config))
        f.close()

        findings = self.scanner.scan_file(f.name)
        os.unlink(f.name)

        rule_ids = [f.rule_id for f in findings]
        self.assertIn("KERAS-004", rule_ids)  # Lambda layer
        self.assertIn("KERAS-005", rule_ids)  # Bytecode
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        self.assertGreater(len(critical), 0)

    def test_non_keras_module_flagged(self):
        """CVE-2025-1550: modules outside keras ecosystem should be flagged."""
        config = {
            "class_name": "Custom",
            "module": "malicious_package.backdoor",
        }
        f = tempfile.NamedTemporaryFile(suffix=".keras", delete=False)
        with zipfile.ZipFile(f.name, "w") as zf:
            zf.writestr("config.json", json.dumps(config))
        f.close()

        findings = self.scanner.scan_file(f.name)
        os.unlink(f.name)

        rule_ids = [f.rule_id for f in findings]
        self.assertIn("KERAS-006", rule_ids)

    def test_suspicious_config_value(self):
        """Config values with __import__ should be flagged."""
        config = {
            "class_name": "Dense",
            "module": "keras.layers",
            "config": {
                "custom_param": "__import__('os').system('id')",
            },
        }
        f = tempfile.NamedTemporaryFile(suffix=".keras", delete=False)
        with zipfile.ZipFile(f.name, "w") as zf:
            zf.writestr("config.json", json.dumps(config))
        f.close()

        findings = self.scanner.scan_file(f.name)
        os.unlink(f.name)

        rule_ids = [f.rule_id for f in findings]
        self.assertIn("KERAS-008", rule_ids)

    def test_clean_keras_model(self):
        """Valid Keras model with safe layers should pass."""
        config = {
            "class_name": "Sequential",
            "module": "keras",
            "config": {
                "layers": [
                    {
                        "class_name": "Dense",
                        "module": "keras.layers",
                        "config": {"units": 64},
                    }
                ]
            },
        }
        f = tempfile.NamedTemporaryFile(suffix=".keras", delete=False)
        with zipfile.ZipFile(f.name, "w") as zf:
            zf.writestr("config.json", json.dumps(config))
        f.close()

        findings = self.scanner.scan_file(f.name)
        os.unlink(f.name)

        self.assertEqual(len(findings), 0)

    def test_hdf5_format_warning(self):
        """Legacy HDF5 format should generate a warning."""
        f = tempfile.NamedTemporaryFile(suffix=".h5", delete=False)
        f.write(b"\x89HDF\r\n\x1a\n")  # HDF5 magic
        f.close()

        findings = self.scanner.scan_file(f.name)
        os.unlink(f.name)

        self.assertGreater(len(findings), 0)
        self.assertIn("KERAS-010", [f.rule_id for f in findings])

    def test_archive_slip_in_keras(self):
        """Path traversal in .keras ZIP should be flagged."""
        f = tempfile.NamedTemporaryFile(suffix=".keras", delete=False)
        with zipfile.ZipFile(f.name, "w") as zf:
            zf.writestr("../../etc/passwd", "root:x:0:0")
            zf.writestr("config.json", "{}")
        f.close()

        findings = self.scanner.scan_file(f.name)
        os.unlink(f.name)

        rule_ids = [f.rule_id for f in findings]
        self.assertIn("KERAS-002", rule_ids)


class TestArchiveSlipDetector(unittest.TestCase):

    def setUp(self):
        self.detector = ArchiveSlipDetector()

    def test_zip_path_traversal(self):
        """ZIP files with ../ paths should be flagged."""
        f = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
        with zipfile.ZipFile(f.name, "w") as zf:
            zf.writestr("../../etc/shadow", "evil")
        f.close()

        findings = self.detector.scan_file(f.name)
        os.unlink(f.name)

        rule_ids = [f.rule_id for f in findings]
        self.assertIn("ARCHSLIP-001", rule_ids)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        self.assertGreater(len(critical), 0)

    def test_tar_path_traversal(self):
        """TAR files with ../ paths should be flagged."""
        f = tempfile.NamedTemporaryFile(suffix=".tar", delete=False)
        with tarfile.open(f.name, "w") as tf:
            import io
            data = b"evil content"
            info = tarfile.TarInfo(name="../../etc/passwd")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        f.close()

        findings = self.detector.scan_file(f.name)
        os.unlink(f.name)

        rule_ids = [f.rule_id for f in findings]
        self.assertIn("ARCHSLIP-004", rule_ids)

    def test_clean_zip(self):
        """Clean ZIP should have no findings."""
        f = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
        with zipfile.ZipFile(f.name, "w") as zf:
            zf.writestr("model/weights.bin", b"\x00" * 100)
            zf.writestr("model/config.json", "{}")
        f.close()

        findings = self.detector.scan_file(f.name)
        os.unlink(f.name)

        self.assertEqual(len(findings), 0)


class TestHuggingFaceScanner(unittest.TestCase):

    def setUp(self):
        self.scanner = HuggingFaceScanner()

    def test_dangerous_file_types(self):
        """Repo with .pkl files should flag dangerous file types."""
        tmpdir = tempfile.mkdtemp()
        with open(os.path.join(tmpdir, "model.pkl"), "wb") as f:
            f.write(b"\x80\x04")
        with open(os.path.join(tmpdir, "config.json"), "w") as f:
            f.write("{}")

        findings = self.scanner.scan_local_repo(tmpdir)

        os.unlink(os.path.join(tmpdir, "model.pkl"))
        os.unlink(os.path.join(tmpdir, "config.json"))
        os.rmdir(tmpdir)

        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HF-002", rule_ids)

    def test_auto_map_detected(self):
        """Config with auto_map should be flagged as custom code loading."""
        tmpdir = tempfile.mkdtemp()
        config = {
            "auto_map": {
                "AutoModel": "modeling_custom.CustomModel"
            }
        }
        with open(os.path.join(tmpdir, "config.json"), "w") as f:
            json.dump(config, f)

        findings = self.scanner.scan_local_repo(tmpdir)

        os.unlink(os.path.join(tmpdir, "config.json"))
        os.rmdir(tmpdir)

        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HF-005", rule_ids)

    def test_trust_remote_code_flagged(self):
        """Config with trust_remote_code=True should be CRITICAL."""
        tmpdir = tempfile.mkdtemp()
        config = {"trust_remote_code": True}
        with open(os.path.join(tmpdir, "config.json"), "w") as f:
            json.dump(config, f)

        findings = self.scanner.scan_local_repo(tmpdir)

        os.unlink(os.path.join(tmpdir, "config.json"))
        os.rmdir(tmpdir)

        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HF-006", rule_ids)
        critical = [f for f in findings if f.rule_id == "HF-006"]
        self.assertEqual(critical[0].severity, Severity.CRITICAL)

    def test_unsafe_readme_instructions(self):
        """README with trust_remote_code=true instructions should be flagged."""
        tmpdir = tempfile.mkdtemp()
        with open(os.path.join(tmpdir, "README.md"), "w") as f:
            f.write("# My Model\n\nLoad with: trust_remote_code=true\n")

        findings = self.scanner.scan_local_repo(tmpdir)

        os.unlink(os.path.join(tmpdir, "README.md"))
        os.rmdir(tmpdir)

        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HF-009", rule_ids)

    def test_missing_readme(self):
        """Repo without README should get INFO finding."""
        tmpdir = tempfile.mkdtemp()
        with open(os.path.join(tmpdir, "model.safetensors"), "wb") as f:
            f.write(b"\x00" * 10)

        findings = self.scanner.scan_local_repo(tmpdir)

        os.unlink(os.path.join(tmpdir, "model.safetensors"))
        os.rmdir(tmpdir)

        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HF-008", rule_ids)

    def test_clean_repo(self):
        """Clean repo with safetensors and proper config should have minimal findings."""
        tmpdir = tempfile.mkdtemp()
        with open(os.path.join(tmpdir, "model.safetensors"), "wb") as f:
            f.write(b"\x00" * 10)
        with open(os.path.join(tmpdir, "config.json"), "w") as f:
            json.dump({"model_type": "bert"}, f)
        with open(os.path.join(tmpdir, "README.md"), "w") as f:
            f.write("# Safe Model\n\nA properly configured model.\n")

        findings = self.scanner.scan_local_repo(tmpdir)

        os.unlink(os.path.join(tmpdir, "model.safetensors"))
        os.unlink(os.path.join(tmpdir, "config.json"))
        os.unlink(os.path.join(tmpdir, "README.md"))
        os.rmdir(tmpdir)

        # Should have no HIGH/CRITICAL findings
        high_critical = [f for f in findings
                        if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        self.assertEqual(len(high_critical), 0)


class TestRulesLoader(unittest.TestCase):
    """Test that YAML rule loading works correctly."""

    def test_secret_patterns_load(self):
        from sentinel.rules import load_secret_patterns
        patterns = load_secret_patterns()
        self.assertGreater(len(patterns), 30)  # We have 45+ patterns
        # Check structure
        for p in patterns[:5]:
            self.assertIn("id", p)
            self.assertIn("pattern", p)
            self.assertIn("description", p)

    def test_sast_rules_load(self):
        from sentinel.rules import load_sast_rules
        rules = load_sast_rules()
        self.assertGreater(len(rules), 20)
        for r in rules[:5]:
            self.assertIn("id", r)
            self.assertIn("pattern", r)
            self.assertIn("severity", r)

    def test_artifact_blocklist_load(self):
        from sentinel.rules import load_artifact_blocklist
        blocklist = load_artifact_blocklist()
        self.assertIn("os", blocklist)
        self.assertIn("system", blocklist["os"])
        self.assertIn("subprocess", blocklist)

    def test_artifact_allowlist_load(self):
        from sentinel.rules import load_artifact_allowlist
        allowlist = load_artifact_allowlist()
        self.assertIn("collections", allowlist)
        self.assertIn("OrderedDict", allowlist["collections"])
        self.assertIn("torch", allowlist)

    def test_injection_patterns_load(self):
        from sentinel.rules import load_injection_patterns
        patterns = load_injection_patterns()
        self.assertIn("direct_injection", patterns)
        self.assertIn("jailbreak", patterns)
        self.assertGreater(len(patterns["direct_injection"]), 5)


if __name__ == "__main__":
    unittest.main()
