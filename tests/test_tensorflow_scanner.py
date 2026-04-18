"""Tests for the TensorFlow SavedModel Scanner.

Uses synthetic protobuf payloads — no tensorflow dependency required.
"""

import os
import struct
import tempfile
from pathlib import Path

import pytest

from sentinel.artifact.tensorflow_scanner import TensorFlowScanner
from sentinel.finding import Severity


# ======================== PROTOBUF ENCODING HELPERS ========================

def _encode_varint(value: int) -> bytes:
    """Encode an integer as a protobuf varint."""
    result = bytearray()
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value & 0x7F)
    return bytes(result)


def _encode_tag(field_number: int, wire_type: int) -> bytes:
    """Encode a protobuf field tag."""
    return _encode_varint((field_number << 3) | wire_type)


def _encode_string_field(field_number: int, text: str) -> bytes:
    """Encode a length-delimited string field."""
    data = text.encode("utf-8")
    return _encode_tag(field_number, 2) + _encode_varint(len(data)) + data


def _encode_varint_field(field_number: int, value: int) -> bytes:
    """Encode a varint field."""
    return _encode_tag(field_number, 0) + _encode_varint(value)


def _encode_bytes_field(field_number: int, data: bytes) -> bytes:
    """Encode a length-delimited bytes field."""
    return _encode_tag(field_number, 2) + _encode_varint(len(data)) + data


def _encode_node_def(name: str, op: str) -> bytes:
    """Build a minimal NodeDef protobuf.

    NodeDef: field 1=name (string), field 2=op (string)
    """
    return _encode_string_field(1, name) + _encode_string_field(2, op)


def _make_graph_def(nodes: list[tuple[str, str]]) -> bytes:
    """Build a GraphDef with the given (name, op) node pairs.

    GraphDef: field 1 = repeated NodeDef (length-delimited)
    """
    result = b""
    for name, op in nodes:
        node = _encode_node_def(name, op)
        result += _encode_bytes_field(1, node)  # GD_NODE = 1
    return result


def _make_metagraph(graph_def: bytes) -> bytes:
    """Build a MetaGraphDef wrapping a GraphDef.

    MetaGraphDef: field 2 = GraphDef (length-delimited)
    """
    return _encode_bytes_field(2, graph_def)


def _make_savedmodel_pb(nodes: list[tuple[str, str]], schema_version: int = 1) -> bytes:
    """Build a complete SavedModel protobuf with the given nodes.

    SavedModel: field 1 = schema_version (int64), field 2 = meta_graphs (repeated)
    """
    result = _encode_varint_field(1, schema_version)

    graph_def = _make_graph_def(nodes)
    meta_graph = _make_metagraph(graph_def)
    result += _encode_bytes_field(2, meta_graph)

    return result


def _make_function_library(functions: list[tuple[str, list[tuple[str, str]]]]) -> bytes:
    """Build a FunctionDefLibrary.

    Args:
        functions: list of (func_name, [(node_name, op), ...])
    """
    result = b""
    for func_name, nodes in functions:
        # OpDef (signature): field 1 = name
        signature = _encode_string_field(1, func_name)
        func_def = _encode_bytes_field(1, signature)  # FD_SIGNATURE = 1

        # FD_NODE_DEF = 3
        for name, op in nodes:
            node = _encode_node_def(name, op)
            func_def += _encode_bytes_field(3, node)

        result += _encode_bytes_field(1, func_def)  # FDL_FUNCTION = 1

    return result


def _make_savedmodel_with_functions(
    nodes: list[tuple[str, str]],
    functions: list[tuple[str, list[tuple[str, str]]]],
) -> bytes:
    """Build a SavedModel with both graph nodes and function library."""
    # GraphDef
    graph = _make_graph_def(nodes)
    # Add function library as field 2 of GraphDef
    func_lib = _make_function_library(functions)
    graph += _encode_bytes_field(2, func_lib)  # GD_LIBRARY = 2

    meta_graph = _make_metagraph(graph)
    return _encode_varint_field(1, 1) + _encode_bytes_field(2, meta_graph)


# ======================== TEST CASES ========================

class TestTensorFlowScanner:
    def setup_method(self):
        self.scanner = TensorFlowScanner()

    def test_clean_savedmodel_no_findings(self, tmp_path):
        """Normal model with standard ops → 0 security findings."""
        pb_data = _make_savedmodel_pb([
            ("input", "Placeholder"),
            ("dense/MatMul", "MatMul"),
            ("dense/Add", "AddV2"),
            ("output", "Identity"),
        ])
        pb_file = tmp_path / "saved_model.pb"
        pb_file.write_bytes(pb_data)

        findings = self.scanner.scan_file(str(pb_file))
        # Filter out INFO-level findings (schema version etc.)
        security_findings = [f for f in findings if f.severity != Severity.INFO]
        assert len(security_findings) == 0

    def test_pyfunc_detected(self, tmp_path):
        """Model with PyFunc op → CRITICAL finding."""
        pb_data = _make_savedmodel_pb([
            ("input", "Placeholder"),
            ("evil/pyfunc", "PyFunc"),
            ("output", "Identity"),
        ])
        pb_file = tmp_path / "saved_model.pb"
        pb_file.write_bytes(pb_data)

        findings = self.scanner.scan_file(str(pb_file))
        critical = [f for f in findings if f.rule_id == "TF-001"]
        assert len(critical) == 1
        assert critical[0].severity == Severity.CRITICAL
        assert "PyFunc" in critical[0].evidence

    def test_readfile_detected(self, tmp_path):
        """Model with ReadFile op → HIGH finding."""
        pb_data = _make_savedmodel_pb([
            ("input", "Placeholder"),
            ("sneaky/read", "ReadFile"),
        ])
        pb_file = tmp_path / "saved_model.pb"
        pb_file.write_bytes(pb_data)

        findings = self.scanner.scan_file(str(pb_file))
        high = [f for f in findings if f.rule_id == "TF-002"]
        assert len(high) >= 1
        assert high[0].severity == Severity.HIGH

    def test_multiple_dangerous_ops(self, tmp_path):
        """Model with multiple dangerous ops → multiple findings."""
        pb_data = _make_savedmodel_pb([
            ("step1", "PyFunc"),
            ("step2", "WriteFile"),
            ("step3", "Assert"),
        ])
        pb_file = tmp_path / "saved_model.pb"
        pb_file.write_bytes(pb_data)

        findings = self.scanner.scan_file(str(pb_file))
        dangerous = [f for f in findings if f.rule_id.startswith("TF-00")]
        # TF-001 (PyFunc), TF-002 (WriteFile), TF-003 (Assert)
        assert len(dangerous) >= 3

    def test_malicious_assets(self, tmp_path):
        """SavedModel directory with executable in assets/ → HIGH finding."""
        model_dir = tmp_path / "saved_model"
        model_dir.mkdir()

        pb_data = _make_savedmodel_pb([("output", "Identity")])
        (model_dir / "saved_model.pb").write_bytes(pb_data)

        assets = model_dir / "assets"
        assets.mkdir()
        (assets / "exploit.sh").write_text("#!/bin/bash\nrm -rf /")

        findings = self.scanner.scan_file(str(model_dir))
        exe_findings = [f for f in findings if f.rule_id == "TF-021"]
        assert len(exe_findings) >= 1
        assert exe_findings[0].severity == Severity.HIGH

    def test_symlink_in_assets(self, tmp_path):
        """SavedModel with symlink in assets → CRITICAL finding."""
        model_dir = tmp_path / "saved_model"
        model_dir.mkdir()

        pb_data = _make_savedmodel_pb([("output", "Identity")])
        (model_dir / "saved_model.pb").write_bytes(pb_data)

        assets = model_dir / "assets"
        assets.mkdir()
        symlink_path = assets / "passwd"

        try:
            os.symlink("/etc/passwd", str(symlink_path))
        except OSError:
            pytest.skip("Cannot create symlinks on this platform")

        findings = self.scanner.scan_file(str(model_dir))
        sym_findings = [f for f in findings if f.rule_id == "TF-020"]
        assert len(sym_findings) >= 1
        assert sym_findings[0].severity == Severity.CRITICAL

    def test_function_with_dangerous_op(self, tmp_path):
        """Function library containing PyFunc → CRITICAL finding."""
        pb_data = _make_savedmodel_with_functions(
            nodes=[("input", "Placeholder")],
            functions=[
                ("evil_fn", [("step1", "PyFunc"), ("step2", "MatMul")]),
            ],
        )
        pb_file = tmp_path / "saved_model.pb"
        pb_file.write_bytes(pb_data)

        findings = self.scanner.scan_file(str(pb_file))
        func_findings = [f for f in findings if f.rule_id == "TF-010"]
        assert len(func_findings) >= 1
        assert "evil_fn" in func_findings[0].evidence

    def test_finding_has_cwe(self, tmp_path):
        """TF findings include appropriate CWE IDs."""
        pb_data = _make_savedmodel_pb([
            ("evil", "PyFunc"),
        ])
        pb_file = tmp_path / "saved_model.pb"
        pb_file.write_bytes(pb_data)

        findings = self.scanner.scan_file(str(pb_file))
        tf001 = [f for f in findings if f.rule_id == "TF-001"]
        assert len(tf001) > 0
        assert "CWE-94" in tf001[0].cwe_ids

    def test_standalone_pb_file(self, tmp_path):
        """Scanning a .pb file directly (not a directory) works."""
        pb_data = _make_savedmodel_pb([
            ("input", "Placeholder"),
            ("steal", "EagerPyFunc"),
        ])
        pb_file = tmp_path / "model.pb"
        pb_file.write_bytes(pb_data)

        findings = self.scanner.scan_file(str(pb_file))
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1

    def test_suspicious_node_name(self, tmp_path):
        """Node with suspicious name → finding."""
        pb_data = _make_savedmodel_pb([
            ("backdoor_layer", "MatMul"),
        ])
        pb_file = tmp_path / "saved_model.pb"
        pb_file.write_bytes(pb_data)

        findings = self.scanner.scan_file(str(pb_file))
        sus = [f for f in findings if f.rule_id == "TF-004"]
        assert len(sus) >= 1
        assert "backdoor" in sus[0].evidence

    def test_nonexistent_path(self):
        """Scanning a nonexistent path → error finding."""
        findings = self.scanner.scan_file("/nonexistent/path/to/model")
        assert len(findings) == 1
        assert findings[0].rule_id == "TF-000"

    def test_suspicious_asset_name(self, tmp_path):
        """Asset file with suspicious name → finding."""
        model_dir = tmp_path / "saved_model"
        model_dir.mkdir()

        pb_data = _make_savedmodel_pb([("output", "Identity")])
        (model_dir / "saved_model.pb").write_bytes(pb_data)

        assets = model_dir / "assets"
        assets.mkdir()
        (assets / "payload_data.txt").write_text("innocent data")

        findings = self.scanner.scan_file(str(model_dir))
        sus = [f for f in findings if f.rule_id == "TF-022"]
        assert len(sus) >= 1
