import json
import zipfile

from sentinel.artifact import scan_file
from sentinel.artifact.r_serialized_scanner import RSerializedScanner
from sentinel.artifact.rar_scanner import RARScanner
from sentinel.artifact.skops_scanner import SkopsScanner
from sentinel.artifact.torchserve_scanner import Torch7Scanner, TorchServeScanner


def _rule_ids(findings):
    return {finding.rule_id for finding in findings}


def test_r_serialized_scanner_detects_dangerous_r_code(tmp_path):
    path = tmp_path / "model.rds"
    path.write_bytes(b"RDX\nmetadata\nsystem('id')\n")

    findings = RSerializedScanner().scan_file(str(path))

    assert "R-002" in _rule_ids(findings)


def test_skops_scanner_detects_dangerous_schema_type(tmp_path):
    path = tmp_path / "model.skops"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(
            "schema.json",
            json.dumps({"__module__": "builtins", "__class__": "eval"}),
        )

    findings = SkopsScanner().scan_file(str(path))

    assert "SKOPS-003" in _rule_ids(findings)


def test_torchserve_scanner_detects_handler_code(tmp_path):
    path = tmp_path / "model.mar"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("MAR-INF/MANIFEST.json", json.dumps({"model": {"handler": "handler.py"}}))
        zf.writestr("handler.py", "import os\nos.system('id')\n")

    findings = TorchServeScanner().scan_file(str(path))

    assert "MAR-008" in _rule_ids(findings)


def test_torch7_scanner_covers_net_extension(tmp_path):
    path = tmp_path / "legacy.net"
    path.write_bytes(b"torch7\nos.execute('id')\n")

    findings = Torch7Scanner().scan_file(str(path))

    assert "T7-001" in _rule_ids(findings)


def test_rar_scanner_fails_closed(tmp_path):
    path = tmp_path / "payload.rar"
    path.write_bytes(b"Rar!\x1a\x07\x00payload")

    findings = RARScanner().scan_file(str(path))

    assert "RAR-UNSUPPORTED" in _rule_ids(findings)


def test_artifact_catalog_routes_p1_scanners(tmp_path):
    cases = {
        "sample.rds": b"RDX\nsource('evil.R')",
        "sample.skops": None,
        "sample.mar": None,
        "sample.net": b"require('os')\nos.execute('id')",
        "sample.rar": b"Rar!\x1a\x07\x00payload",
    }

    for name, payload in cases.items():
        path = tmp_path / name
        if name.endswith(".skops"):
            with zipfile.ZipFile(path, "w") as zf:
                zf.writestr("schema.json", json.dumps({"__module__": "os", "__class__": "system"}))
        elif name.endswith(".mar"):
            with zipfile.ZipFile(path, "w") as zf:
                zf.writestr("handler.py", "subprocess.run(['id'])")
        else:
            path.write_bytes(payload or b"")

        findings = scan_file(path)

        assert findings, f"{name} was not routed to a P1 scanner"
