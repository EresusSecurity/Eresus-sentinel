import json
import subprocess
import sys

from sentinel.aibom.diff import diff_bom, format_diff_json
from sentinel.aibom.models import (
    AIBOM_SCHEMA_VERSION,
    AIBOMResult,
    AIComponent,
    AIComponentType,
    RelationshipType,
)
from sentinel.aibom.normalizer import normalize_result
from sentinel.aibom.scan_pipeline import ScanPipeline, ScanPipelineConfig
from sentinel.aibom.scanners.base import BaseAIBOMScanner


def test_aibom_result_schema_round_trips():
    result = AIBOMResult(metadata={"root": "/tmp/project"})
    component = AIComponent(
        type=AIComponentType.MODEL_LLM,
        name="gpt-local",
        version="1",
        path="models/gpt.bin",
        evidence=["fixture"],
    )
    result.add(component)

    payload = result.as_dict()
    loaded = AIBOMResult.from_dict(payload)

    assert payload["schema_version"] == AIBOM_SCHEMA_VERSION
    assert payload["summary"]["component_count"] == 1
    assert loaded.components[0].name == "gpt-local"
    assert loaded.components[0].type == AIComponentType.MODEL_LLM


def test_normalizer_merges_duplicate_components_and_relationships():
    result = AIBOMResult()
    first = AIComponent(type=AIComponentType.AGENT, name="Agent", path="agent.py", evidence=["a"])
    second = AIComponent(type=AIComponentType.AGENT, name="agent", path="agent.py", evidence=["b"])
    target = AIComponent(type=AIComponentType.TOOL, name="tool", path="tool.py")
    result.add(first)
    result.add(second)
    result.add(target)
    result.relate(second, target, RelationshipType.USES)
    result.relate(second, target, RelationshipType.USES)

    normalize_result(result)

    assert len(result.components) == 2
    assert result.components[0].evidence == ["a", "b"]
    assert result.metadata["deduplicated_components"] == 1
    assert len(result.relationships) == 1
    assert result.relationships[0].source_id == first.id


def test_scan_pipeline_applies_dedup_normalizer(tmp_path):
    class DuplicateScanner(BaseAIBOMScanner):
        name = "duplicate"

        def scan(self, root):
            return [
                AIComponent(type=AIComponentType.CONFIG, name="config", path=str(root / "app.py")),
                AIComponent(type=AIComponentType.CONFIG, name="config", path=str(root / "app.py")),
            ]

    result = ScanPipeline(ScanPipelineConfig(scanners=[DuplicateScanner()])).run(tmp_path)

    assert len(result.components) == 1
    assert result.metadata["deduplicated_components"] == 1


def test_aibom_diff_json_reports_modified_component():
    old = AIBOMResult()
    new = AIBOMResult()
    old.add(AIComponent(type=AIComponentType.MODEL_LLM, name="model", version="1", path="m.bin"))
    new.add(AIComponent(type=AIComponentType.MODEL_LLM, name="model", version="2", path="m.bin"))

    payload = format_diff_json(diff_bom(old, new))

    assert payload["schema_version"] == "aibom.diff.v1"
    assert payload["summary"]["modified"] == 1
    assert payload["components"]["modified"][0]["changes"] == ["version: '1' -> '2'"]


def test_aibom_cli_lists_scanners_as_json():
    result = subprocess.run(
        [sys.executable, "-m", "sentinel.cli.main", "aibom", "--list-scanners", "-f", "json"],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "aibom.scanner-registry.v1"
    assert payload["summary"]["scanner_count"] >= 28


def test_aibom_cli_diff_json(tmp_path):
    old = AIBOMResult()
    new = AIBOMResult()
    new.add(AIComponent(type=AIComponentType.AGENT, name="agent", path="agent.py"))
    old_path = tmp_path / "old.json"
    new_path = tmp_path / "new.json"
    old_path.write_text(json.dumps(old.as_dict()), encoding="utf-8")
    new_path.write_text(json.dumps(new.as_dict()), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel.cli.main",
            "aibom",
            "--diff",
            str(old_path),
            str(new_path),
            "-f",
            "json",
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["summary"]["added"] == 1
