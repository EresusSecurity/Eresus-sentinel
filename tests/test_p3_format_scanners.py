import json

from sentinel.artifact import scan_file


def _rule_ids(findings):
    return {finding.rule_id for finding in findings}


def test_mxnet_catalog_routes_symbol_json(tmp_path):
    path = tmp_path / "model-symbol.json"
    path.write_text(
        json.dumps({"nodes": [{"name": "custom", "op": "CustomPlugin"}]}),
        encoding="utf-8",
    )

    findings = scan_file(path)

    assert "MXNET-005" in _rule_ids(findings)


def test_executorch_scanner_routes_pte(tmp_path):
    path = tmp_path / "edge_model.pte"
    path.write_bytes(b"ET00custom_op")

    findings = scan_file(path)

    assert "EXECUTORCH-003" in _rule_ids(findings)


def test_tensorrt_scanner_routes_plan(tmp_path):
    path = tmp_path / "engine.plan"
    path.write_bytes(b"TRT0IPluginV2")

    findings = scan_file(path)

    assert "TRT-001" in _rule_ids(findings)


def test_paddle_scanner_routes_pdmodel(tmp_path):
    path = tmp_path / "inference.pdmodel"
    path.write_bytes(b"PADDLE custom_op")

    findings = scan_file(path)

    assert "PADDLE-002" in _rule_ids(findings)


def test_coreml_scanner_routes_mlmodel(tmp_path):
    path = tmp_path / "model.mlmodel"
    path.write_bytes(b"\x00")

    findings = scan_file(path)

    assert "COREML-005" in _rule_ids(findings)


def test_pmml_scanner_routes_xxe_fixture(tmp_path):
    path = tmp_path / "model.pmml"
    path.write_text(
        "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM 'file:///etc/passwd'> ]><PMML/>",
        encoding="utf-8",
    )

    findings = scan_file(path)

    assert "PMML-001" in _rule_ids(findings)
