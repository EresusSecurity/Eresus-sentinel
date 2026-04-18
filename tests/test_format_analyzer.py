"""Tests for the Format Reverse Engineering Engine."""

import json
import struct
import tempfile
import zipfile
from pathlib import Path

import pytest

from sentinel.artifact.format_analyzer import FormatAnalyzer
from sentinel.artifact.gguf_engine import GGUFReverseEngine, GGUF_MAGIC, GGUFValueType
from sentinel.artifact.safetensors_engine import SafeTensorsReverseEngine
from sentinel.artifact.pytorch_engine import PyTorchReverseEngine
from sentinel.finding import Severity


# ======================== GGUF TESTS ========================

class TestGGUFReverseEngine:
    def setup_method(self):
        self.engine = GGUFReverseEngine()

    def _create_minimal_gguf(self, tmp_path, version=3, tensor_count=0, kv_count=0):
        """Create a minimal valid GGUF file."""
        fpath = tmp_path / "model.gguf"
        with open(fpath, "wb") as f:
            f.write(struct.pack("<I", GGUF_MAGIC))     # magic
            f.write(struct.pack("<I", version))          # version
            f.write(struct.pack("<Q", tensor_count))     # tensor_count
            f.write(struct.pack("<Q", kv_count))         # metadata_kv_count
        return str(fpath)

    def _create_gguf_with_metadata(self, tmp_path, metadata: dict):
        """Create a GGUF file with metadata entries."""
        fpath = tmp_path / "model_meta.gguf"
        with open(fpath, "wb") as f:
            f.write(struct.pack("<I", GGUF_MAGIC))
            f.write(struct.pack("<I", 3))
            f.write(struct.pack("<Q", 0))  # no tensors
            f.write(struct.pack("<Q", len(metadata)))

            for key, value in metadata.items():
                # Write key string
                key_bytes = key.encode("utf-8")
                f.write(struct.pack("<Q", len(key_bytes)))
                f.write(key_bytes)

                if isinstance(value, str):
                    f.write(struct.pack("<I", GGUFValueType.STRING))
                    val_bytes = value.encode("utf-8")
                    f.write(struct.pack("<Q", len(val_bytes)))
                    f.write(val_bytes)
                elif isinstance(value, int):
                    f.write(struct.pack("<I", GGUFValueType.UINT32))
                    f.write(struct.pack("<I", value))
                elif isinstance(value, bool):
                    f.write(struct.pack("<I", GGUFValueType.BOOL))
                    f.write(struct.pack("<?", value))

        return str(fpath)

    def test_valid_gguf_header(self, tmp_path):
        fpath = self._create_minimal_gguf(tmp_path, version=3)
        report = self.engine.analyze(fpath)
        assert report.format_name == "GGUF"
        assert report.header is not None
        assert report.header.magic == GGUF_MAGIC
        assert report.header.version == 3

    def test_invalid_magic(self, tmp_path):
        fpath = tmp_path / "bad.gguf"
        with open(fpath, "wb") as f:
            f.write(struct.pack("<I", 0xDEADBEEF))
            f.write(struct.pack("<I", 3))
            f.write(struct.pack("<Q", 0))
            f.write(struct.pack("<Q", 0))
        report = self.engine.analyze(str(fpath))
        assert any(f.rule_id == "FMT-010" for f in report.findings)

    def test_unusual_version(self, tmp_path):
        fpath = self._create_minimal_gguf(tmp_path, version=99)
        report = self.engine.analyze(fpath)
        assert any(f.rule_id == "FMT-011" for f in report.findings)

    def test_metadata_parsing(self, tmp_path):
        fpath = self._create_gguf_with_metadata(tmp_path, {
            "general.architecture": "llama",
            "general.name": "TestModel",
        })
        report = self.engine.analyze(fpath)
        assert "general.architecture" in report.metadata
        assert report.metadata["general.architecture"] == "llama"

    def test_suspicious_chat_template(self, tmp_path):
        fpath = self._create_gguf_with_metadata(tmp_path, {
            "tokenizer.chat_template": "__import__('os').system('rm -rf /')",
        })
        report = self.engine.analyze(fpath)
        critical = [f for f in report.findings if f.rule_id == "FMT-031"]
        assert len(critical) > 0

    def test_file_not_found(self):
        report = self.engine.analyze("/nonexistent/model.gguf")
        assert any(f.rule_id == "FMT-001" for f in report.findings)

    def test_high_tensor_count(self, tmp_path):
        fpath = self._create_minimal_gguf(tmp_path, tensor_count=50000)
        report = self.engine.analyze(fpath)
        assert any(f.rule_id == "FMT-012" for f in report.findings)


# ======================== SAFETENSORS TESTS ========================

class TestSafeTensorsReverseEngine:
    def setup_method(self):
        self.engine = SafeTensorsReverseEngine()

    def _create_safetensors(self, tmp_path, header_dict, data=b""):
        """Create a minimal SafeTensors file."""
        fpath = tmp_path / "model.safetensors"
        header_json = json.dumps(header_dict).encode("utf-8")
        with open(fpath, "wb") as f:
            f.write(struct.pack("<Q", len(header_json)))
            f.write(header_json)
            f.write(data)
        return str(fpath)

    def test_valid_safetensors(self, tmp_path):
        header = {
            "weight": {"dtype": "F32", "shape": [768, 768], "data_offsets": [0, 2359296]},
            "__metadata__": {"format": "pt"},
        }
        fpath = self._create_safetensors(tmp_path, header, b"\x00" * 100)
        report = self.engine.analyze(fpath)
        assert report.format_name == "SafeTensors"
        assert len(report.tensors) == 1
        assert report.tensors[0].name == "weight"
        assert report.tensors[0].dtype == "F32"

    def test_overlapping_tensors(self, tmp_path):
        header = {
            "tensor_a": {"dtype": "F32", "shape": [100], "data_offsets": [0, 400]},
            "tensor_b": {"dtype": "F32", "shape": [100], "data_offsets": [200, 600]},  # overlap!
        }
        fpath = self._create_safetensors(tmp_path, header, b"\x00" * 600)
        report = self.engine.analyze(fpath)
        overlaps = [f for f in report.findings if f.rule_id == "FMT-120"]
        assert len(overlaps) > 0

    def test_suspicious_tensor_name(self, tmp_path):
        header = {
            "backdoor_layer": {"dtype": "F32", "shape": [10], "data_offsets": [0, 40]},
        }
        fpath = self._create_safetensors(tmp_path, header, b"\x00" * 40)
        report = self.engine.analyze(fpath)
        sus = [f for f in report.findings if f.rule_id == "FMT-121"]
        assert len(sus) > 0

    def test_suspicious_metadata(self, tmp_path):
        header = {
            "__metadata__": {"payload": "eval(os.system('rm -rf /'))"},
            "weight": {"dtype": "F32", "shape": [10], "data_offsets": [0, 40]},
        }
        fpath = self._create_safetensors(tmp_path, header, b"\x00" * 40)
        report = self.engine.analyze(fpath)
        meta_findings = [f for f in report.findings if f.rule_id == "FMT-130"]
        assert len(meta_findings) > 0

    def test_oversized_header(self, tmp_path):
        fpath = tmp_path / "big_header.safetensors"
        with open(fpath, "wb") as f:
            f.write(struct.pack("<Q", 200_000_000))  # 200MB header
            f.write(b"\x00" * 100)
        report = self.engine.analyze(str(fpath))
        assert any(f.rule_id == "FMT-110" for f in report.findings)

    def test_header_exceeds_file(self, tmp_path):
        fpath = tmp_path / "truncated.safetensors"
        with open(fpath, "wb") as f:
            f.write(struct.pack("<Q", 50000))  # Claims 50KB header
            f.write(b"\x00" * 100)             # But only 100 bytes
        report = self.engine.analyze(str(fpath))
        assert any(f.rule_id == "FMT-111" for f in report.findings)

    def test_invalid_json_header(self, tmp_path):
        fpath = tmp_path / "bad_json.safetensors"
        bad_json = b"{not valid json!!!!"
        with open(fpath, "wb") as f:
            f.write(struct.pack("<Q", len(bad_json)))
            f.write(bad_json)
        report = self.engine.analyze(str(fpath))
        assert any(f.rule_id == "FMT-112" for f in report.findings)

    def test_file_too_small(self, tmp_path):
        fpath = tmp_path / "tiny.safetensors"
        fpath.write_bytes(b"\x00\x01\x02")  # Only 3 bytes
        report = self.engine.analyze(str(fpath))
        assert any(f.rule_id == "FMT-101" for f in report.findings)


# ======================== PYTORCH TESTS ========================

class TestPyTorchReverseEngine:
    def setup_method(self):
        self.engine = PyTorchReverseEngine()

    def _create_pytorch_zip(self, tmp_path, entries: dict):
        """Create a PyTorch ZIP archive with given entries."""
        fpath = tmp_path / "model.pt"
        with zipfile.ZipFile(str(fpath), "w") as zf:
            for name, content in entries.items():
                zf.writestr(name, content)
        return str(fpath)

    def test_normal_pytorch_with_pickle(self, tmp_path):
        fpath = self._create_pytorch_zip(tmp_path, {
            "archive/data.pkl": b"pickle data",
            "archive/data/0": b"\x00" * 100,
        })
        report = self.engine.analyze(fpath)
        assert report.format_name == "PyTorch"
        pkl = [f for f in report.findings if f.rule_id == "FMT-210"]
        assert len(pkl) > 0  # Should warn about pickle

    def test_unexpected_exe(self, tmp_path):
        fpath = self._create_pytorch_zip(tmp_path, {
            "archive/data.pkl": b"pickle",
            "archive/malware.exe": b"MZ\x90\x00",
        })
        report = self.engine.analyze(fpath)
        exe = [f for f in report.findings if f.rule_id == "FMT-211"]
        assert len(exe) > 0

    def test_path_traversal(self, tmp_path):
        fpath = tmp_path / "evil.pt"
        with zipfile.ZipFile(str(fpath), "w") as zf:
            zf.writestr("../../etc/passwd", b"root:x:0:0")
        report = self.engine.analyze(str(fpath))
        traversal = [f for f in report.findings if f.rule_id == "FMT-212"]
        assert len(traversal) > 0

    def test_not_a_zip(self, tmp_path):
        fpath = tmp_path / "not_zip.pt"
        fpath.write_bytes(b"this is not a zip file at all")
        report = self.engine.analyze(str(fpath))
        assert any(f.rule_id == "FMT-200" for f in report.findings)

    def test_unexpected_python_script(self, tmp_path):
        fpath = self._create_pytorch_zip(tmp_path, {
            "archive/data.pkl": b"pickle",
            "archive/exploit.py": b"import os; os.system('whoami')",
        })
        report = self.engine.analyze(fpath)
        py_findings = [f for f in report.findings if f.rule_id == "FMT-211"]
        assert len(py_findings) > 0


# ======================== UNIFIED ANALYZER TESTS ========================

class TestFormatAnalyzer:
    def setup_method(self):
        self.analyzer = FormatAnalyzer()

    def test_auto_detect_gguf(self, tmp_path):
        fpath = tmp_path / "model.gguf"
        with open(fpath, "wb") as f:
            f.write(struct.pack("<I", GGUF_MAGIC))
            f.write(struct.pack("<I", 3))
            f.write(struct.pack("<Q", 0))
            f.write(struct.pack("<Q", 0))
        report = self.analyzer.analyze(str(fpath))
        assert report.format_name == "GGUF"

    def test_auto_detect_safetensors(self, tmp_path):
        fpath = tmp_path / "model.safetensors"
        header = json.dumps({"w": {"dtype": "F32", "shape": [10], "data_offsets": [0, 40]}}).encode()
        with open(fpath, "wb") as f:
            f.write(struct.pack("<Q", len(header)))
            f.write(header)
            f.write(b"\x00" * 40)
        report = self.analyzer.analyze(str(fpath))
        assert report.format_name == "SafeTensors"

    def test_auto_detect_pytorch(self, tmp_path):
        fpath = tmp_path / "model.pt"
        with zipfile.ZipFile(str(fpath), "w") as zf:
            zf.writestr("archive/data.pkl", b"data")
        report = self.analyzer.analyze(str(fpath))
        assert report.format_name == "PyTorch"

    def test_unsupported_format(self, tmp_path):
        fpath = tmp_path / "model.xyz"
        fpath.write_bytes(b"unknown format")
        report = self.analyzer.analyze(str(fpath))
        assert any(f.rule_id == "FMT-000" for f in report.findings)

    def test_directory_scan(self, tmp_path):
        # Create multiple model files
        gguf = tmp_path / "model.gguf"
        with open(gguf, "wb") as f:
            f.write(struct.pack("<I", GGUF_MAGIC))
            f.write(struct.pack("<I", 3))
            f.write(struct.pack("<Q", 0))
            f.write(struct.pack("<Q", 0))

        pt = tmp_path / "model.pt"
        with zipfile.ZipFile(str(pt), "w") as zf:
            zf.writestr("data.pkl", b"pkl")

        reports = self.analyzer.analyze_directory(str(tmp_path))
        assert len(reports) == 2
        formats = {r.format_name for r in reports}
        assert "GGUF" in formats
        assert "PyTorch" in formats
