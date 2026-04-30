"""Tests for expanded fuzzer surfaces."""

from __future__ import annotations

import io
import json
import zipfile

from sentinel.fuzzer.aibom import AIBOMFuzzerGenerator, AIBOMPayloadFactory
from sentinel.fuzzer.artifact.generator import ArtifactGenerator
from sentinel.fuzzer.base import Payload, PayloadCategory
from sentinel.fuzzer.differential import DifferentialFuzzer, FunctionScannerAdapter
from sentinel.fuzzer.mcp.stateful import StatefulMCPFuzzer
from sentinel.fuzzer.skill import SkillBundleGenerator, SkillPayloadFactory


def test_artifact_serialization_pack_formats_generate_markers():
    expected_markers = {
        "joblib": b"joblib.numpy_pickle",
        "cloudpickle": b"cloudpickle",
        "dill": b"dill._dill",
        "marshal": b"marshal",
        "onnx_external": b"external_data",
    }

    for fmt, marker in expected_markers.items():
        data = ArtifactGenerator(format=fmt).generate(seed=11)
        assert marker in data


def test_skill_bundle_generator_outputs_zip_and_file_map():
    gen = SkillBundleGenerator(variant="codex")
    archive = gen.generate(seed=5)
    files = gen.generate_files(seed=5)

    assert "SKILL.md" in files
    assert "scripts/run.sh" in files

    with zipfile.ZipFile(io.BytesIO(archive), "r") as zf:
        assert {"SKILL.md", "skill.json", "scripts/run.sh"}.issubset(zf.namelist())


def test_skill_payload_factory_has_malicious_and_benign_payloads():
    payloads = SkillPayloadFactory.all_payloads()

    assert any(payload.is_malicious for payload in payloads)
    assert any(not payload.is_malicious for payload in payloads)


def test_aibom_generator_supported_formats_are_parseable_or_containerized():
    json_formats = ["aibom_json", "cyclonedx", "spdx", "sarif"]
    for fmt in json_formats:
        doc = json.loads(AIBOMFuzzerGenerator(format=fmt).generate(seed=9))
        assert isinstance(doc, dict)

    csv_data = AIBOMFuzzerGenerator(format="csv").generate(seed=9)
    assert b"mcp.server" in csv_data

    html_data = AIBOMFuzzerGenerator(format="html").generate(seed=9)
    assert b"<html" in html_data

    project_data = AIBOMFuzzerGenerator(format="project").generate(seed=9)
    with zipfile.ZipFile(io.BytesIO(project_data), "r") as zf:
        assert {"pyproject.toml", "mcp.json", "Dockerfile"}.issubset(zf.namelist())


def test_aibom_payload_factory_has_all_report_surfaces():
    payloads = AIBOMPayloadFactory.malicious_payloads()
    names = {payload.name for payload in payloads}

    assert "aibom_cyclonedx_external_endpoint" in names
    assert "aibom_project_manifest_secret" in names


def test_stateful_mcp_fuzzer_outputs_jsonl_flow_with_block_step():
    flow = StatefulMCPFuzzer(flow_type="tool_exfiltration").generate_flow(seed=3)
    data = flow.to_jsonl()
    lines = [json.loads(line) for line in data.decode().splitlines()]

    assert flow.name == "tool_exfiltration"
    assert len(lines) >= 5
    assert any(line["expected_policy"] == "block" for line in lines)
    assert lines[0]["message"]["method"] == "initialize"


def test_differential_fuzzer_accepts_named_function_adapters():
    payload = Payload(
        name="bad_payload",
        category=PayloadCategory.RCE,
        data=b"bad",
    )

    def baseline(data: bytes, source: str) -> list[dict[str, str]]:
        return []

    def improved(data: bytes, source: str) -> list[dict[str, str]]:
        return [{"source": source}] if b"bad" in data else []

    report = DifferentialFuzzer(
        [
            FunctionScannerAdapter("baseline", baseline),
            FunctionScannerAdapter("improved", improved),
        ],
        baseline="baseline",
    ).run([payload])

    assert report.divergent_count == 1
    assert len(report.improvements) == 1
