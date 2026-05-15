import json

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
