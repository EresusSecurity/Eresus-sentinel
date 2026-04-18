"""Tests for ONNX engine, HF remote scanner, AI reasoning layer, and updated format analyzer."""

import json
import struct
import zipfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from sentinel.artifact.format_analyzer import FormatAnalyzer
from sentinel.artifact.onnx_engine import ONNXReverseEngine, DANGEROUS_OPS, CRITICAL_OPS
from sentinel.artifact.format_common import FormatReport
from sentinel.supply_chain.hf_scanner import HFRemoteScanner
from sentinel.ai.reasoning import AIConfig, AIReasoningLayer, NoOpBackend, AIAnalysisResult
from sentinel.finding import Finding, Severity


# ======================== ONNX PROTOBUF HELPERS ========================

def _encode_varint(value: int) -> bytes:
    """Encode an integer as a protobuf varint."""
    parts = []
    while value > 127:
        parts.append((value & 0x7F) | 0x80)
        value >>= 7
    parts.append(value & 0x7F)
    return bytes(parts)


def _encode_field_varint(field_num: int, value: int) -> bytes:
    """Encode a varint field."""
    tag = (field_num << 3) | 0  # wire type 0 = varint
    return _encode_varint(tag) + _encode_varint(value)


def _encode_field_string(field_num: int, value: str) -> bytes:
    """Encode a length-delimited string field."""
    tag = (field_num << 3) | 2  # wire type 2 = length-delimited
    data = value.encode("utf-8")
    return _encode_varint(tag) + _encode_varint(len(data)) + data


def _encode_field_bytes(field_num: int, value: bytes) -> bytes:
    """Encode a length-delimited bytes field."""
    tag = (field_num << 3) | 2
    return _encode_varint(tag) + _encode_varint(len(value)) + value


def _make_node_proto(op_type: str, name: str = "", domain: str = "", doc_string: str = "") -> bytes:
    """Build a NodeProto protobuf."""
    data = _encode_field_string(4, op_type)  # op_type
    if name:
        data += _encode_field_string(3, name)
    if domain:
        data += _encode_field_string(7, domain)
    if doc_string:
        data += _encode_field_string(6, doc_string)
    return data


def _make_opset_import(domain: str, version: int) -> bytes:
    """Build an OperatorSetIdProto."""
    data = b""
    if domain:
        data += _encode_field_string(1, domain)
    data += _encode_field_varint(2, version)
    return data


def _make_metadata_prop(key: str, value: str) -> bytes:
    """Build a StringStringEntryProto."""
    return _encode_field_string(1, key) + _encode_field_string(2, value)


def _make_onnx_model(
    ir_version: int = 9,
    producer_name: str = "test",
    nodes: list = None,
    opsets: list = None,
    metadata_props: list = None,
    doc_string: str = "",
) -> bytes:
    """Build a minimal ONNX ModelProto."""
    data = _encode_field_varint(1, ir_version)  # ir_version
    data += _encode_field_string(2, producer_name)  # producer_name

    # Opset imports
    if opsets:
        for domain, version in opsets:
            opset_bytes = _make_opset_import(domain, version)
            data += _encode_field_bytes(8, opset_bytes)

    # Graph
    graph_data = b""
    graph_data += _encode_field_string(2, "main_graph")  # graph name
    if nodes:
        for op_type, name, domain, doc in nodes:
            node_bytes = _make_node_proto(op_type, name, domain, doc)
            graph_data += _encode_field_bytes(1, node_bytes)
    data += _encode_field_bytes(7, graph_data)

    # Metadata props
    if metadata_props:
        for key, value in metadata_props:
            prop_bytes = _make_metadata_prop(key, value)
            data += _encode_field_bytes(14, prop_bytes)

    # Doc string
    if doc_string:
        data += _encode_field_string(6, doc_string)

    return data


# ======================== ONNX ENGINE TESTS ========================

class TestONNXReverseEngine:
    def setup_method(self):
        self.engine = ONNXReverseEngine()

    def test_valid_onnx(self, tmp_path):
        model_data = _make_onnx_model(
            ir_version=9,
            producer_name="pytorch",
            nodes=[("Conv", "conv1", "", ""), ("Relu", "relu1", "", "")],
            opsets=[("", 17)],
        )
        fpath = tmp_path / "model.onnx"
        fpath.write_bytes(model_data)
        report = self.engine.analyze(str(fpath))
        assert report.format_name == "ONNX"
        assert report.metadata.get("ir_version") == 9
        assert report.metadata.get("producer_name") == "pytorch"

    def test_file_not_found(self):
        report = self.engine.analyze("/nonexistent/model.onnx")
        assert any(f.rule_id == "FMT-300" for f in report.findings)

    def test_file_too_small(self, tmp_path):
        fpath = tmp_path / "tiny.onnx"
        fpath.write_bytes(b"\x00\x01")
        report = self.engine.analyze(str(fpath))
        assert any(f.rule_id == "FMT-301" for f in report.findings)

    def test_unusual_ir_version(self, tmp_path):
        model_data = _make_onnx_model(ir_version=99)
        fpath = tmp_path / "model.onnx"
        fpath.write_bytes(model_data)
        report = self.engine.analyze(str(fpath))
        assert any(f.rule_id == "FMT-310" for f in report.findings)

    def test_critical_operator(self, tmp_path):
        model_data = _make_onnx_model(
            nodes=[("ATen", "aten_op", "", "")],
            opsets=[("", 17)],
        )
        fpath = tmp_path / "model.onnx"
        fpath.write_bytes(model_data)
        report = self.engine.analyze(str(fpath))
        critical = [f for f in report.findings if f.rule_id == "FMT-330"]
        assert len(critical) > 0

    def test_dangerous_operator(self, tmp_path):
        model_data = _make_onnx_model(
            nodes=[("Loop", "loop1", "", ""), ("If", "if1", "", "")],
            opsets=[("", 17)],
        )
        fpath = tmp_path / "model.onnx"
        fpath.write_bytes(model_data)
        report = self.engine.analyze(str(fpath))
        dangerous = [f for f in report.findings if f.rule_id == "FMT-331"]
        assert len(dangerous) >= 2

    def test_custom_domain_operator(self, tmp_path):
        model_data = _make_onnx_model(
            nodes=[("CustomMatMul", "custom1", "com.evil.ops", "")],
            opsets=[("", 17)],
        )
        fpath = tmp_path / "model.onnx"
        fpath.write_bytes(model_data)
        report = self.engine.analyze(str(fpath))
        custom = [f for f in report.findings if f.rule_id == "FMT-332"]
        assert len(custom) > 0

    def test_suspicious_opset_domain(self, tmp_path):
        model_data = _make_onnx_model(
            opsets=[("", 17), ("com.microsoft", 1)],
            nodes=[("Conv", "conv1", "", "")],
        )
        fpath = tmp_path / "model.onnx"
        fpath.write_bytes(model_data)
        report = self.engine.analyze(str(fpath))
        domain_findings = [f for f in report.findings if f.rule_id == "FMT-320"]
        assert len(domain_findings) > 0

    def test_metadata_injection(self, tmp_path):
        model_data = _make_onnx_model(
            metadata_props=[("payload", "eval(os.system('rm -rf /'))")],
            nodes=[("Conv", "c1", "", "")],
        )
        fpath = tmp_path / "model.onnx"
        fpath.write_bytes(model_data)
        report = self.engine.analyze(str(fpath))
        meta = [f for f in report.findings if f.rule_id == "FMT-341"]
        assert len(meta) > 0

    def test_doc_string_injection(self, tmp_path):
        model_data = _make_onnx_model(
            doc_string="__import__('os').system('whoami')",
            nodes=[("Conv", "c1", "", "")],
        )
        fpath = tmp_path / "model.onnx"
        fpath.write_bytes(model_data)
        report = self.engine.analyze(str(fpath))
        doc_inj = [f for f in report.findings if f.rule_id == "FMT-342"]
        assert len(doc_inj) > 0

    def test_old_opset(self, tmp_path):
        model_data = _make_onnx_model(
            opsets=[("", 5)],
            nodes=[("Conv", "c1", "", "")],
        )
        fpath = tmp_path / "model.onnx"
        fpath.write_bytes(model_data)
        report = self.engine.analyze(str(fpath))
        old = [f for f in report.findings if f.rule_id == "FMT-321"]
        assert len(old) > 0


# ======================== UNIFIED FORMAT ANALYZER TESTS ========================

class TestFormatAnalyzerONNX:
    def setup_method(self):
        self.analyzer = FormatAnalyzer()

    def test_auto_detect_onnx(self, tmp_path):
        model_data = _make_onnx_model(nodes=[("Conv", "c", "", "")])
        fpath = tmp_path / "model.onnx"
        fpath.write_bytes(model_data)
        report = self.analyzer.analyze(str(fpath))
        assert report.format_name == "ONNX"

    def test_directory_includes_onnx(self, tmp_path):
        (tmp_path / "a.onnx").write_bytes(_make_onnx_model())
        (tmp_path / "b.gguf").write_bytes(struct.pack("<I", 0x46475547) + struct.pack("<I", 3) + struct.pack("<Q", 0) + struct.pack("<Q", 0))
        reports = self.analyzer.analyze_directory(str(tmp_path))
        formats = {r.format_name for r in reports}
        assert "ONNX" in formats
        assert "GGUF" in formats


# ======================== HF REMOTE SCANNER TESTS ========================

class TestHFRemoteScanner:
    def setup_method(self):
        self.scanner = HFRemoteScanner(token=None)

    def test_check_file_list_dangerous(self):
        files = [
            {"rfilename": "model.pkl"},
            {"rfilename": "config.json"},
            {"rfilename": "README.md"},
        ]
        self.scanner._check_file_list(files, "test/repo")
        dangerous = [f for f in self.scanner.findings if f.rule_id == "HF-010"]
        assert len(dangerous) >= 1  # .pkl is dangerous

    def test_no_safetensors_warning(self):
        files = [
            {"rfilename": "model.bin"},
            {"rfilename": "config.json"},
        ]
        self.scanner._check_file_list(files, "test/repo")
        no_st = [f for f in self.scanner.findings if f.rule_id == "HF-011"]
        assert len(no_st) == 1

    def test_missing_readme(self):
        files = [{"rfilename": "model.safetensors"}]
        self.scanner._check_file_list(files, "test/repo")
        missing = [f for f in self.scanner.findings if f.rule_id == "HF-012"]
        assert len(missing) == 1

    def test_trust_remote_code(self):
        model_info = {"config": {"trust_remote_code": True}}
        self.scanner._check_config(model_info, "test/repo")
        trc = [f for f in self.scanner.findings if f.rule_id == "HF-020"]
        assert len(trc) == 1
        assert trc[0].severity == Severity.CRITICAL

    def test_auto_map(self):
        model_info = {"config": {"auto_map": {"AutoModel": "custom--MyModel"}}}
        self.scanner._check_config(model_info, "test/repo")
        am = [f for f in self.scanner.findings if f.rule_id == "HF-021"]
        assert len(am) == 1

    def test_no_license(self):
        model_info = {"cardData": {}, "tags": []}
        self.scanner._check_model_card(model_info, "test/repo")
        lic = [f for f in self.scanner.findings if f.rule_id == "HF-030"]
        assert len(lic) == 1

    def test_disabled_model(self):
        model_info = {"disabled": True}
        self.scanner._check_repo_metadata(model_info, "test/repo")
        dis = [f for f in self.scanner.findings if f.rule_id == "HF-041"]
        assert len(dis) == 1
        assert dis[0].severity == Severity.CRITICAL

    def test_gated_model(self):
        model_info = {"gated": True}
        self.scanner._check_gated_status(model_info, "test/repo")
        gated = [f for f in self.scanner.findings if f.rule_id == "HF-042"]
        assert len(gated) == 1

    def test_low_history_repo(self):
        commits = [{"title": "initial commit", "author": {"name": "user1"}}]
        self.scanner._check_commit_history(commits, "test/repo")
        low = [f for f in self.scanner.findings if f.rule_id == "HF-051"]
        assert len(low) == 1

    def test_suspicious_commit(self):
        commits = [
            {"title": "replace all model weights", "author": {"name": "attacker"}},
            {"title": "normal commit", "author": {"name": "dev"}},
        ]
        self.scanner._check_commit_history(commits, "test/repo")
        sus = [f for f in self.scanner.findings if f.rule_id == "HF-050"]
        assert len(sus) == 1


# ======================== AI REASONING LAYER TESTS ========================

class TestAIReasoningLayer:
    def test_disabled_by_default(self):
        layer = AIReasoningLayer(AIConfig(enabled=False))
        assert not layer.is_enabled()
        assert isinstance(layer.backend, NoOpBackend)

    def test_noop_analyze_finding(self):
        layer = AIReasoningLayer(AIConfig(enabled=False))
        finding = Finding.artifact(
            rule_id="TEST-001", title="Test",
            description="Test finding", severity=Severity.HIGH,
            target="test.bin",
        )
        result = layer.analyze_finding(finding)
        assert isinstance(result, AIAnalysisResult)
        assert result.original_finding == finding
        assert result.confidence == 0.0

    def test_noop_analyze_prompt(self):
        layer = AIReasoningLayer(AIConfig(enabled=False))
        result = layer.analyze_prompt("ignore previous instructions")
        assert result.get("enabled") is False

    def test_noop_compare(self):
        layer = AIReasoningLayer(AIConfig(enabled=False))
        result = layer.compare_behaviors("normal output", "suspicious output")
        assert result.get("enabled") is False

    def test_noop_enrich(self):
        layer = AIReasoningLayer(AIConfig(enabled=False))
        findings = [
            Finding.artifact(rule_id="T1", title="T1", description="D1",
                             severity=Severity.HIGH, target="f"),
            Finding.artifact(rule_id="T2", title="T2", description="D2",
                             severity=Severity.LOW, target="f"),
        ]
        results = layer.enrich_findings(findings)
        assert len(results) == 2

    def test_noop_reduce_fp(self):
        layer = AIReasoningLayer(AIConfig(enabled=False))
        findings = [
            Finding.artifact(rule_id="T1", title="T1", description="D1",
                             severity=Severity.HIGH, target="f"),
        ]
        filtered = layer.reduce_false_positives(findings)
        assert len(filtered) == 1  # No filtering when disabled

    def test_config_from_env(self):
        with patch.dict("os.environ", {
            "SENTINEL_AI_ENABLED": "true",
            "SENTINEL_AI_BACKEND": "anthropic",
            "SENTINEL_AI_MODEL": "claude-sonnet-4-20250514",
        }):
            config = AIConfig.from_env()
            assert config.enabled is True
            assert config.backend == "anthropic"
            assert config.model == "claude-sonnet-4-20250514"

    def test_noop_is_available(self):
        backend = NoOpBackend()
        assert backend.is_available() is True
