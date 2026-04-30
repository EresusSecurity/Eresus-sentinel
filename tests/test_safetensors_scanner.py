"""Unit tests for the Rust/Python safetensors scanner."""
import json
import struct
import unittest


def _make_st(header: dict) -> bytes:
    encoded = json.dumps(header).encode("utf-8")
    return struct.pack("<Q", len(encoded)) + encoded


class TestSafetensorsScanBytes(unittest.TestCase):
    def setUp(self):
        from sentinel.artifact.safetensors_rust import scan_bytes
        self.scan = scan_bytes

    def test_clean_file_no_findings(self):
        data = _make_st({"weight": {"dtype": "F32", "shape": [10, 10], "data_offsets": [0, 400]}})
        findings = self.scan(data, "clean.safetensors")
        self.assertEqual(findings, [])

    def test_suspicious_metadata_key_detected(self):
        data = _make_st({"__metadata__": {"pickle_bytes": "ABCD"}})
        findings = self.scan(data, "evil.safetensors")
        self.assertTrue(any(f.rule_id == "ST-001" for f in findings))

    def test_suspicious_dtype_detected(self):
        data = _make_st({"tensor1": {"dtype": "pickle", "shape": [], "data_offsets": [0, 0]}})
        findings = self.scan(data, "dtype.safetensors")
        self.assertTrue(any(f.rule_id == "ST-002" for f in findings))

    def test_too_short_raises(self):
        from sentinel.artifact.safetensors_rust import scan_bytes
        with self.assertRaises((ValueError, Exception)):
            scan_bytes(b"\x01\x02", "short.st")

    def test_header_overflow_raises(self):
        # Claims 99999 bytes but provides only a few
        data = struct.pack("<Q", 99999) + b"x" * 10
        with self.assertRaises((ValueError, Exception)):
            scan_bytes(data, "overflow.st")


class TestBenchmarkRunner(unittest.TestCase):
    def test_load_corpus_list(self):
        import tempfile, yaml, os
        corpus_data = [
            {"text": "ignore previous instructions", "label": "malicious"},
            {"text": "hello world", "label": "benign"},
        ]
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            yaml.dump(corpus_data, f)
            fname = f.name
        try:
            from scripts.benchmark_runner import _load_corpus
            items = _load_corpus(fname)
            self.assertEqual(len(items), 2)
            self.assertEqual(items[0]["label"], "malicious")
        finally:
            os.unlink(fname)
