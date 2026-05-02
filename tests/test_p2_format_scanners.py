import gzip

from sentinel.artifact import scan_file
from sentinel.artifact.compressed_scanner import CompressedWrapperScanner
from sentinel.artifact.extra_format_scanners import CNTKScanner, RKNNScanner
from sentinel.artifact.xgboost_scanner import XGBoostScanner


def _rule_ids(findings):
    return {finding.rule_id for finding in findings}


def test_rknn_scanner_detects_dangerous_metadata(tmp_path):
    path = tmp_path / "model.rknn"
    path.write_bytes(b"RKNN\x00metadata os.system('id')")

    findings = RKNNScanner().scan_file(str(path))

    assert "RKNN-002" in _rule_ids(findings)


def test_cntk_scanner_detects_executable_pattern(tmp_path):
    path = tmp_path / "model.dnn"
    path.write_bytes(b"CNTK\x00__import__('os').system('id')")

    findings = CNTKScanner().scan_file(str(path))

    assert "CNTK-001" in _rule_ids(findings)


def test_xgboost_scanner_covers_bst_extension(tmp_path):
    path = tmp_path / "model.bst"
    path.write_bytes(b"not-binf")

    findings = XGBoostScanner().scan_file(str(path))

    assert "XGBT-001" in _rule_ids(findings)


def test_llamafile_catalog_routes_exe_extension(tmp_path):
    path = tmp_path / "model.exe"
    path.write_bytes(b"MZ")

    findings = scan_file(path)

    assert "LLAMA-050" in _rule_ids(findings)


def test_compressed_wrapper_routes_inner_pickle(tmp_path):
    path = tmp_path / "payload.pkl.gz"
    path.write_bytes(gzip.compress(b"cos\nsystem\n(S'id'\ntR."))

    findings = CompressedWrapperScanner().scan_file(str(path))

    assert findings


def test_lz4_wrapper_fails_closed(tmp_path):
    path = tmp_path / "payload.pkl.lz4"
    path.write_bytes(b"\x04\x22\x4d\x18")

    findings = scan_file(path)

    assert "COMPRESSED-UNSUPPORTED" in _rule_ids(findings)


def test_artifact_catalog_routes_p2_scanners(tmp_path):
    cases = {
        "model.rknn": b"RKNN\x00subprocess",
        "model.dnn": b"CNTK\x00eval(",
        "model.bst": b"bad",
        "model.exe": b"MZ",
        "payload.pkl.gz": gzip.compress(b"cos\nsystem\n(S'id'\ntR."),
    }

    for name, payload in cases.items():
        path = tmp_path / name
        path.write_bytes(payload)

        findings = scan_file(path)

        assert findings, f"{name} was not routed to a P2 scanner"
