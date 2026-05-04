import json
import os
import subprocess
import sys
import tarfile
import io

from sentinel.aibom.models import AIBOMResult, AIComponent, AIComponentType
from sentinel.aibom.scan_pipeline import ScanPipeline


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


def test_multilanguage_scanner_detects_csharp_model_and_vector_store(tmp_path):
    source = tmp_path / "Program.cs"
    source.write_text(
        """
        using Azure.AI.OpenAI;
        var deployment_name = "gpt-4o-mini";
        var client = new OpenAIClient();
        var vector = new PineconeClient();
        var text = "text-embedding-3-small";
        """,
        encoding="utf-8",
    )

    result = ScanPipeline().run(tmp_path)
    components = result.as_dict()["components"]
    component_types = {component["type"] for component in components}

    assert AIComponentType.ENDPOINT.value in component_types
    assert AIComponentType.MODEL_LLM.value in component_types
    assert AIComponentType.VECTOR_STORE.value in component_types
    assert AIComponentType.MODEL_EMBEDDING.value in component_types


def test_aibom_scan_accepts_container_image_reference_json():
    result = _run_cli("aibom", "scan", "ghcr.io/huggingface/text-generation-inference:latest", "-f", "json")

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["metadata"]["container_image_scan"] is True
    assert payload["components"][0]["type"] == AIComponentType.CONTAINER.value
    assert payload["components"][0]["properties"]["image"].startswith("ghcr.io/huggingface")


def test_aibom_scan_reads_source_files_from_container_layer_tar(tmp_path):
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w") as tf:
        data = b'import OpenAI from "openai"; const model_id = "gpt-4o-mini";'
        info = tarfile.TarInfo(name="app/service.ts")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))

    image_tar = tmp_path / "image.tar"
    with tarfile.open(image_tar, mode="w") as tf:
        layer_bytes = layer.getvalue()
        layer_info = tarfile.TarInfo(name="layer.tar")
        layer_info.size = len(layer_bytes)
        tf.addfile(layer_info, io.BytesIO(layer_bytes))

    result = _run_cli("aibom", "scan", str(image_tar), "--container-extraction-tier", "tarball", "-f", "json")

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["metadata"]["container_image_scan"] is True
    assert payload["metadata"]["extraction_status"] == "tarball-scanned"
    assert payload["metadata"]["archive_members_scanned"] == 1
    names = {component["name"] for component in payload["components"]}
    assert "gpt-4o-mini" in names


def test_aibom_diff_subcommand_alias_outputs_json(tmp_path):
    old = AIBOMResult()
    new = AIBOMResult()
    new.add(AIComponent(type=AIComponentType.MODEL_LLM, name="gpt-4o-mini", path="app.py"))
    old_path = tmp_path / "old.json"
    new_path = tmp_path / "new.json"
    old_path.write_text(json.dumps(old.as_dict()), encoding="utf-8")
    new_path.write_text(json.dumps(new.as_dict()), encoding="utf-8")

    result = _run_cli("aibom", "diff", str(old_path), str(new_path), "-f", "json")

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "aibom.diff.v1"
    assert payload["has_changes"] is True
    assert payload["components"]["added"][0]["name"] == "gpt-4o-mini"


def test_aibom_watch_once_outputs_scan_json(tmp_path):
    (tmp_path / "app.ts").write_text('import OpenAI from "openai"; const model = "gpt-4o";', encoding="utf-8")

    result = _run_cli("aibom", "watch", str(tmp_path), "--once", "-f", "json")

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["metadata"]["watch_mode"] is True
    assert payload["metadata"]["watch_once"] is True
    assert payload["summary"]["component_count"] >= 1


def test_aibom_discover_repos_merges_child_results(tmp_path):
    repo = tmp_path / "service-a"
    repo.mkdir()
    (repo / "app.js").write_text('const OpenAI = require("openai");', encoding="utf-8")

    result = _run_cli("aibom", "--discover-repos", str(tmp_path), "-f", "json")

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["metadata"]["multi_repo"] is True
    assert payload["metadata"]["repo_count"] == 1
    assert payload["components"][0]["properties"]["source_repo"] == "service-a"
