import json
import os
import subprocess
import sys


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = f"python{os.pathsep}{env.get('PYTHONPATH', '')}"
    return subprocess.run(
        [sys.executable, "-m", "sentinel.cli.main", *args],
        cwd=os.getcwd(),
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_artifact_scan_lists_scanners_as_json():
    result = _run_cli("artifact", "scan", "--list-scanners", "-f", "json")

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    scanner_ids = {scanner["id"] for scanner in payload["scanners"]}
    assert payload["schema_version"] == "artifact.scanners.v1"
    assert {"pickle", "torchserve", "rar", "compressed"}.issubset(scanner_ids)


def test_artifact_scan_dry_run_supports_scanner_selection(tmp_path):
    artifact = tmp_path / "safe.pkl"
    artifact.write_bytes(b"\x80\x04N.")
    ignored = tmp_path / "note.txt"
    ignored.write_text("not a model", encoding="utf-8")

    result = _run_cli(
        "artifact",
        "scan",
        str(tmp_path),
        "--dry-run",
        "--scanners",
        "pickle",
        "-f",
        "json",
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["summary"]["planned"] == 1
    assert payload["plan"][0]["scanner"] == "pickle"
    assert any(item["reason"] == "unsupported format" for item in payload["skipped"])


def test_artifact_scan_dry_run_honors_max_size(tmp_path):
    artifact = tmp_path / "safe.pkl"
    artifact.write_bytes(b"\x80\x04N.")

    result = _run_cli("artifact", "scan", str(tmp_path), "--dry-run", "--max-size", "1b", "-f", "json")

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["summary"]["planned"] == 0
    assert payload["skipped"][0]["reason"] == "max-size exceeded"


def test_artifact_scan_strict_reports_unsupported_formats(tmp_path):
    artifact = tmp_path / "unknown.weights"
    artifact.write_bytes(b"opaque")

    result = _run_cli("artifact", "scan", str(tmp_path), "--strict", "-f", "json")

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert any(finding["rule_id"] == "ARTIFACT-091" for finding in payload["findings"])


def test_artifact_scan_plaintext_and_summary_exports(tmp_path):
    artifact = tmp_path / "unknown.weights"
    artifact.write_bytes(b"opaque")

    plaintext = _run_cli("artifact", "scan", str(tmp_path), "--strict", "-f", "plaintext")
    summary = _run_cli("artifact", "scan", str(tmp_path), "--strict", "-f", "summary")

    assert plaintext.returncode == 1
    assert "Eresus Sentinel Scan Report" in plaintext.stdout
    assert "ARTIFACT-091" in plaintext.stdout
    assert summary.returncode == 1
    assert "Findings: 1" in summary.stdout
    assert "ARTIFACT-091" in summary.stdout


def test_artifact_metadata_outputs_safe_json(tmp_path):
    artifact = tmp_path / "safe.pkl"
    artifact.write_bytes(b"\x80\x04N.")

    result = _run_cli("artifact", "metadata", str(artifact), "--security-only", "-f", "json")

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "artifact.metadata.v1"
    assert payload["metadata"]["scanner"] == "pickle"
    assert payload["metadata"]["sha256"]
    assert "magic_hex" not in payload["metadata"]


def test_doctor_debug_and_cache_json_commands_are_machine_readable():
    doctor = _run_cli("doctor", "--show-failed", "--json")
    debug = _run_cli("debug", "--json")
    cache = _run_cli("cache", "stats", "--json")

    assert doctor.returncode == 0
    assert json.loads(doctor.stdout)["schema_version"] == "doctor.v1"
    assert debug.returncode == 0
    assert json.loads(debug.stdout)["schema_version"] == "debug.v1"
    assert cache.returncode == 0
    assert json.loads(cache.stdout)["schema_version"] == "cache.v1"
