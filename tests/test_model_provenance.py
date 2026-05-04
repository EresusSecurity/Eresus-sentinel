import json
import os
import subprocess
import sys
import struct

from sentinel.provenance import FingerprintDatabase, ModelProvenanceScanner, compare_models, extract_signals


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


def _write_gpt2_model(root):
    root.mkdir(parents=True, exist_ok=True)
    config = {
        "model_type": "gpt2",
        "n_embd": 768,
        "n_layer": 12,
        "n_head": 12,
        "vocab_size": 50257,
    }
    vocab = {f"tok_{index}": index for index in range(2048)}
    tokenizer = {"model": {"type": "gpt2", "vocab": vocab}, "added_tokens": []}
    (root / "config.json").write_text(json.dumps(config), encoding="utf-8")
    (root / "tokenizer.json").write_text(json.dumps(tokenizer), encoding="utf-8")
    header = {
        "transformer.wte.weight": {"dtype": "F32", "shape": [50257, 768], "data_offsets": [0, 0]},
        "transformer.h.0.ln_1.weight": {"dtype": "F32", "shape": [768], "data_offsets": [0, 0]},
    }
    raw_header = json.dumps(header).encode("utf-8")
    (root / "model.safetensors").write_bytes(struct.pack("<Q", len(raw_header)) + raw_header)


def test_extract_signals_returns_all_eight_signals(tmp_path):
    _write_gpt2_model(tmp_path)

    signals = extract_signals(tmp_path)

    assert set(signals) == {"MFI", "TFV", "VOA", "EAS", "NLF", "LEP", "END", "WVC"}
    assert signals["MFI"].value["architecture"] == "gpt2"
    assert signals["TFV"].value["vocab_size"] == 2048


def test_provenance_scan_matches_seed_reference(tmp_path):
    _write_gpt2_model(tmp_path)

    report = ModelProvenanceScanner().scan(tmp_path, top_k=3, threshold=0.4)

    assert report.matches[0]["family"] == "gpt2"
    assert report.pipeline_score >= 0.4
    assert report.verdict in {"matched", "likely_related", "weak_match"}


def test_compare_models_scores_related_models(tmp_path):
    left = tmp_path / "left"
    right = tmp_path / "right"
    _write_gpt2_model(left)
    _write_gpt2_model(right)

    result = compare_models(left, right)

    assert result["verdict"] == "related"
    assert result["pipeline_score"] >= 0.9


def test_fingerprint_database_integrity_round_trip(tmp_path):
    db_path = tmp_path / "fingerprints.json"
    db = FingerprintDatabase()
    db.write(db_path)

    payload = json.loads(db_path.read_text(encoding="utf-8"))
    loaded = FingerprintDatabase.load(db_path)

    assert loaded.verify_integrity(payload)
    assert loaded.info()["reference_count"] >= 10
    assert payload["manifest"]["schema_version"] == "provenance.db-manifest.v1"
    assert payload["manifest"]["signal_ids"] == ["MFI", "TFV", "VOA", "EAS", "NLF", "LEP", "END", "WVC"]


def test_fingerprint_database_writes_shard_manifest(tmp_path):
    db = FingerprintDatabase()

    manifest = db.write_shards(tmp_path / "shards", shard_size=4)

    shard_dir = tmp_path / "shards"
    assert (shard_dir / "manifest.json").exists()
    assert manifest["schema_version"] == "provenance.db-manifest.v1"
    assert len(manifest["shards"]) >= 3
    for shard in manifest["shards"]:
        payload = json.loads((shard_dir / shard["path"]).read_text(encoding="utf-8"))
        assert payload["hmac_sha256"] == shard["hmac_sha256"]


def test_provenance_top_k_threshold_snapshot(tmp_path):
    _write_gpt2_model(tmp_path)

    report = ModelProvenanceScanner().scan(tmp_path, top_k=2, threshold=0.4)

    payload = report.to_dict()
    assert len(payload["matches"]) == 2
    assert payload["threshold"] == 0.4
    assert payload["summary"]["match_count"] == 2
    assert payload["summary"]["signal_coverage"] >= 6
    assert payload["matches"][0]["score"] >= payload["matches"][1]["score"]


def test_provenance_cli_scan_compare_and_db_info(tmp_path):
    left = tmp_path / "left"
    right = tmp_path / "right"
    _write_gpt2_model(left)
    _write_gpt2_model(right)
    db_path = tmp_path / "db.json"

    download = _run_cli("provenance", "download-fingerprints", "--output-path", str(db_path), "--json")
    scan = _run_cli("provenance", "scan", str(left), "--db", str(db_path), "--json", "--top-k", "2")
    compare = _run_cli("provenance", "compare", str(left), str(right), "--json")
    info = _run_cli("provenance", "db-info", "--db", str(db_path), "--json")

    assert download.returncode == 0
    assert db_path.exists()
    assert json.loads(download.stdout)["integrity_ok"] is True
    assert scan.returncode == 0
    assert json.loads(scan.stdout)["schema_version"] == "provenance.report.v1"
    assert compare.returncode == 0
    assert json.loads(compare.stdout)["verdict"] == "related"
    assert info.returncode == 0
    assert json.loads(info.stdout)["integrity_ok"] is True
