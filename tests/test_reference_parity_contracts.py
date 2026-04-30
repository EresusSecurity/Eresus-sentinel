from __future__ import annotations

from sentinel.agent.mcp import mcp_transport_matrix, mcp_transport_summary
from sentinel.agent.skill_eval_manifest import discover_skill_eval_fixtures, skill_eval_manifest
from sentinel.fuzzer.pickle import mutator_catalog, pickle_fuzzer_smoke, protocol_matrix


def test_pickle_fuzzer_protocol_and_mutator_contract():
    protocols = protocol_matrix()
    mutators = mutator_catalog()
    smoke = pickle_fuzzer_smoke()

    assert [spec.protocol for spec in protocols] == [0, 1, 2, 3, 4, 5]
    assert len(mutators) >= 17
    assert smoke["mutator_count"] == len(mutators)
    assert smoke["mutated_non_empty"] > 0


def test_skill_eval_manifest_contract(tmp_path):
    manifest = skill_eval_manifest()
    skill_dir = tmp_path / "backdoor" / "sample"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("---\nname: sample\n---\n", encoding="utf-8")

    fixtures = discover_skill_eval_fixtures(tmp_path)

    assert manifest["category_count"] >= 8
    assert manifest["policy_profile_count"] >= 6
    assert fixtures["backdoor"] == ["backdoor/sample"]


def test_mcp_transport_matrix_contract():
    matrix = mcp_transport_matrix()
    summary = mcp_transport_summary()
    native_names = {spec.name for spec in matrix if spec.status == "native-live"}

    assert {"manifest", "http-jsonrpc", "stdio"}.issubset(native_names)
    assert summary["total"] >= 6
    assert summary["native_live"] >= 3
    assert summary["scans_prompts_resources"] >= 3
