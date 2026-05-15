import json
import inspect
from pathlib import Path

import pytest

from sentinel import sntl


def test_sntl_load_validate_resolve_and_simulate(tmp_path):
    path = tmp_path / "suite.sntl"
    path.write_text(
        """
schema: sentinel.eval.v1
name: sdk-suite
providers:
  - id: local
    type: mock
prompts:
  - id: base
    template: "Review {{input}}"
assertions:
  - id: marker
    type: contains
    expected: result
profiles:
  deep:
    variables:
      - input: alpha
""".lstrip(),
        encoding="utf-8",
    )

    document = sntl.load(path).require()
    bundle = sntl.resolve([path], profile="deep").require()

    assert document.schema == "sentinel.eval.v1"
    assert len(document.fingerprint) == 64
    assert bundle.data["variables"][0]["input"] == "alpha"
    assert bundle.simulate()["matrix"]["cells"] == 1
    assert sntl.explain([path])["schema_version"] == "sentinel.sntl.explain.v1"
    assert sntl.graph([path])["schema_version"] == "sentinel.sntl.graph.v1"


def test_sntl_rejects_invalid_documents():
    document = sntl.loads("schema: sentinel.eval.v1\nname: broken\n")

    assert document.ok is False
    with pytest.raises(sntl.SntlValidationError):
        document.require()


def test_sntl_dump_and_schema_export(tmp_path):
    data = {
        "schema": "sentinel.dataset.v1",
        "name": "cases",
        "records": [{"id": "case-1", "input": "hello"}],
    }
    path = sntl.dump(data, tmp_path / "dataset.sntl")
    schema_path = sntl.write_json_schema("sentinel.dataset.v1", tmp_path / "dataset.schema.json")

    assert sntl.load(path).ok is True
    assert json.loads(schema_path.read_text(encoding="utf-8"))["title"] == "sentinel.dataset.v1"
    assert sntl.fingerprint(data) == sntl.load(path).fingerprint


def test_sntl_duplicate_ids_are_errors():
    document = sntl.loads(
        """
schema: sentinel.assertion.v1
name: pack
assertions:
  - id: duplicate
    type: contains
    expected: ok
  - id: duplicate
    type: regex
    pattern: ok
""".lstrip()
    )

    assert any(issue.path == "assertions[1].id" for issue in document.issues)


def test_sntl_parser_supports_native_features():
    document = sntl.loads(
        """
%sntl 1
schema: sentinel.eval.v1
name: parser-suite
providers:
  - id: local
    type: mock
    capabilities: {streaming: true, json: true}
prompts:
  - id: block
    template: |
      Review {{input}}
      Return a decision.
variables:
  - input: alpha
    tags: [baseline, smoke]
assertions:
  - id: marker
    type: contains
    expected: result:
""".lstrip()
    ).require()

    assert document.data["providers"][0]["capabilities"]["streaming"] is True
    assert document.data["prompts"][0]["template"].startswith("Review")
    assert sntl.query(document.data, "variables[0].tags[1]") == "smoke"


def test_sntl_writer_round_trips_without_yaml():
    data = {
        "schema": "sentinel.runtime.v1",
        "name": "runtime",
        "policies": [{"id": "block-shell", "action": "block", "enabled": True}],
    }

    rendered = sntl.dumps(data)
    parsed = sntl.loads(rendered).require()

    assert "policies:" in rendered
    assert parsed.data == data


def test_sntl_examples_are_valid():
    for path in sorted(Path("examples").glob("*.sntl")) + sorted(Path("examples").glob("*.sentinel")):
        assert sntl.load(path).require().ok is True


def test_sntl_diff_redact_and_set_path():
    left = {"schema": "sentinel.config.v1", "auth": {"api_key": "secret"}, "count": 1}
    right = sntl.set_path(left, "count", 2)

    assert sntl.diff(left, right)[0]["op"] == "replace"
    assert sntl.redact(left)["auth"]["api_key"] == "[redacted]"


def test_sntl_converts_json_toml_yaml_jsonl_csv_and_yara(tmp_path):
    json_doc = sntl.loads_any('{"name":"json-suite","settings":{"enabled":true}}', source_format="json").require()
    toml_doc = sntl.loads_any('name = "toml-suite"\n[settings]\nenabled = true\n', source_format="toml").require()
    yaml_doc = sntl.loads_any("name: yaml-suite\nsettings:\n  enabled: true\n", source_format="yaml").require()
    jsonl_doc = sntl.loads_any('{"input":"alpha"}\n{"input":"beta"}\n', source_format="jsonl").require()
    csv_doc = sntl.loads_any("id,input,enabled\ncase-1,alpha,true\ncase-2,beta,false\n", source_format="csv").require()
    yara_doc = sntl.loads_any(
        """
rule SuspiciousTool : runtime exfiltration {
  meta:
    severity = "high"
    enabled = true
  strings:
    $a = "curl" nocase
    $b = /token=[A-Za-z0-9]+/
  condition:
    any of them
}
""".lstrip(),
        source_format="yara",
    ).require()

    assert json_doc.schema == "sentinel.config.v1"
    assert toml_doc.data["settings"]["enabled"] is True
    assert yaml_doc.data["name"] == "yaml-suite"
    assert jsonl_doc.schema == "sentinel.dataset.v1"
    assert csv_doc.data["records"][1]["enabled"] is False
    assert yara_doc.schema == "sentinel.rulepack.v1"
    assert yara_doc.data["rules"][0]["strings"][1]["kind"] == "regex"
    assert "schema: sentinel.config.v1" in sntl.convert_text('{"name":"json-suite"}', source_format="json")


def test_sntl_conversion_files_tree_and_exports(tmp_path):
    source = tmp_path / "config.json"
    source.write_text(json.dumps({"name": "file-suite", "settings": {"enabled": True}}), encoding="utf-8")
    target = sntl.convert_file(source)
    tree_source = tmp_path / "tree"
    tree_target = tmp_path / "out"
    tree_source.mkdir()
    (tree_source / "records.jsonl").write_text('{"input":"alpha"}\n', encoding="utf-8")

    outputs = sntl.convert_tree(tree_source, tree_target, source_formats=["jsonl"])
    parsed = sntl.load(target).require()

    assert target.suffix == ".sntl"
    assert parsed.data["schema"] == "sentinel.config.v1"
    assert outputs == [tree_target / "records.sntl"]
    assert sntl.load(outputs[0]).require().data["records"][0]["id"] == "record-1"
    assert json.loads(sntl.to_json(parsed.data))["name"] == "file-suite"
    assert "schema = " in sntl.to_toml({"schema": "sentinel.config.v1", "name": "toml"})


def test_sntl_inspect_plan_migrate_roundtrip_and_capabilities(tmp_path):
    source = tmp_path / "imports"
    target = tmp_path / "converted"
    source.mkdir()
    (source / "runtime.toml").write_text('name = "runtime"\n[[policies]]\nid = "p1"\naction = "block"\n', encoding="utf-8")
    (source / "rules.yara").write_text("rule RuntimeRule { condition: true }\n", encoding="utf-8")

    inspection = sntl.inspect_file(source / "runtime.toml", schema="sentinel.runtime.v1")
    plan = sntl.plan_conversion(source, target, source_formats=["toml", "yara"], schema="sentinel.runtime.v1")
    migrated = sntl.migrate_tree(source, target, source_formats=["toml", "yara"])
    roundtrip = sntl.roundtrip_file(source / "runtime.toml", schema="sentinel.runtime.v1")
    comparison = sntl.compare_formats()

    assert inspection.schema == "sentinel.runtime.v1"
    assert plan.items[0].target.endswith(".sntl")
    assert migrated.items[0].valid is True
    assert roundtrip.stable is True
    assert comparison["recommended_authoring_format"] == "sntl"


def test_sntl_patch_applies_diff_in_reverse():
    original = {"schema": "sentinel.config.v1", "count": 1, "name": "base"}
    modified = sntl.set_path(original, "count", 2)
    ops = sntl.diff(original, modified)

    restored = sntl.patch(original, ops)

    assert restored["count"] == 2
    assert restored["name"] == "base"


def test_sntl_patch_supports_remove_operation():
    data = {"a": 1, "b": 2, "c": 3}
    ops = [{"op": "remove", "path": "b"}]

    result = sntl.patch(data, ops)

    assert "b" not in result
    assert result["a"] == 1
    assert result["c"] == 3


def test_sntl_flatten_produces_dot_separated_keys():
    data = {
        "schema": "sentinel.config.v1",
        "auth": {"provider": "local", "timeout": 30},
        "features": ["scan", "redteam"],
    }

    flat = sntl.flatten(data)

    assert flat["auth.provider"] == "local"
    assert flat["auth.timeout"] == 30
    assert flat["features[0]"] == "scan"
    assert flat["features[1]"] == "redteam"


def test_sntl_select_picks_named_keys():
    data = {"id": "rule-1", "severity": "high", "enabled": True, "internal": "x"}

    result = sntl.select(data, ["id", "severity", "enabled"])

    assert result == {"id": "rule-1", "severity": "high", "enabled": True}
    assert "internal" not in result


def test_sntl_select_on_list_projects_each_item():
    data = [
        {"id": "r1", "severity": "high", "noise": 1},
        {"id": "r2", "severity": "low", "noise": 2},
    ]

    result = sntl.select(data, ["id", "severity"])

    assert result == [{"id": "r1", "severity": "high"}, {"id": "r2", "severity": "low"}]


def test_sntl_wildcard_query_recursive_field():
    data = {
        "providers": [
            {"id": "p1", "nested": {"id": "p1-inner"}},
            {"id": "p2"},
        ],
        "id": "root",
    }

    all_ids = sntl.wildcard_query(data, "$**.id")

    assert "root" in all_ids
    assert "p1" in all_ids
    assert "p2" in all_ids
    assert "p1-inner" in all_ids


def test_sntl_wildcard_query_list_star():
    data = {
        "assertions": [
            {"type": "contains"},
            {"type": "regex"},
            {"type": "latency"},
        ]
    }

    types = sntl.wildcard_query(data, "assertions[*].type")

    assert types == ["contains", "regex", "latency"]


def test_sntl_interpolate_replaces_double_brace_variables():
    template = "Review {{input}} and expect {{expected_behavior}}"
    variables = {"input": "summarize the policy", "expected_behavior": "allowed"}

    result = sntl.interpolate(template, variables)

    assert result == "Review summarize the policy and expect allowed"


def test_sntl_interpolate_strict_raises_on_missing_variable():
    import pytest

    template = "Hello {{name}}, your score is {{score}}"

    with pytest.raises(KeyError):
        sntl.interpolate(template, {"name": "Alice"}, strict=True)


def test_sntl_interpolate_document_traverses_nested_structure():
    doc = {
        "name": "{{suite_name}}",
        "prompts": [{"template": "Review {{input}}"}],
        "meta": {"label": "{{label}}"},
    }
    variables = {"suite_name": "smoke", "input": "policy", "label": "CI"}

    result = sntl.interpolate_document(doc, variables)

    assert result["name"] == "smoke"
    assert result["prompts"][0]["template"] == "Review policy"
    assert result["meta"]["label"] == "CI"


def test_sntl_expand_matrix_produces_variable_rows():
    variables = [
        {"input": "alpha", "expected": "allow"},
        {"input": "read private key", "expected": "block"},
    ]

    matrix = sntl.expand_matrix(variables)

    assert len(matrix) == 2
    assert matrix[0]["input"] == "alpha"
    assert matrix[1]["expected"] == "block"


def test_sntl_render_prompt_expands_each_variable_set():
    template = "Input: {{input}}, Behavior: {{expected}}"
    variables = [
        {"input": "alpha", "expected": "allow"},
        {"input": "hack", "expected": "block"},
    ]

    prompts = sntl.render_prompt(template, variables)

    assert prompts[0] == "Input: alpha, Behavior: allow"
    assert prompts[1] == "Input: hack, Behavior: block"


def test_sntl_extract_variables_finds_all_template_vars():
    template = "Review {{input}} and return {{result}} within {{timeout}} ms"

    vars_ = sntl.extract_variables(template)

    assert vars_ == ["input", "result", "timeout"]


def test_sntl_schema_definitions_cover_all_known_schemas():
    from sentinel.sntl.schemas import KNOWN_SCHEMAS, SCHEMA_DEFINITIONS, json_schema

    for schema in ("sentinel.redteam.v1", "sentinel.runtime.v1",
                   "sentinel.rulepack.v1", "sentinel.policy.v1",
                   "sentinel.provider.v1", "sentinel.report.v1"):
        assert schema in SCHEMA_DEFINITIONS, f"{schema} missing from SCHEMA_DEFINITIONS"
        js = json_schema(schema)
        assert js["title"] == schema
        assert js["type"] == "object"


def test_sntl_redteam_schema_validates_example():
    doc = sntl.loads("""
schema: sentinel.redteam.v1
name: test-redteam
attacks:
  - id: injection
    pack: prompt_injection
    goal: detect injection
    assertions:
      - type: refusal
scoring:
  method: deterministic
  fail_on: high
""".lstrip())

    assert doc.ok is True
    assert doc.data["scoring"]["method"] == "deterministic"


def test_sntl_runtime_schema_validates_example():
    doc = sntl.loads("""
schema: sentinel.runtime.v1
name: firewall-runtime
policies:
  - id: block-shell
    action: block
    enabled: true
  - id: flag-pii
    action: flag
    enabled: true
default_action: allow
""".lstrip())

    assert doc.ok is True
    assert doc.data["default_action"] == "allow"


def test_sntl_rulepack_schema_validates_example():
    doc = sntl.loads("""
schema: sentinel.rulepack.v1
name: core-rules
version: 1.0.0
rules:
  - id: RULE-001
    severity: high
    enabled: true
    description: Detects shell injection
  - id: RULE-002
    severity: medium
    enabled: true
""".lstrip())

    assert doc.ok is True
    assert doc.data["rules"][0]["id"] == "RULE-001"


def test_sntl_runtime_does_not_depend_on_yaml_loader():
    import sentinel.sntl.parser as parser
    import sentinel.sntl.writer as writer
    import sentinel.sntl.api as api

    combined = inspect.getsource(parser) + inspect.getsource(writer) + inspect.getsource(api)

    assert "safe_load" not in combined
    assert "import yaml" not in combined
