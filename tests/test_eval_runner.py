import json

from sentinel.redteam.eval_runner import load_eval_config, run_eval_file


def test_eval_runner_renders_prompt_tests_and_assertions(tmp_path):
    config_path = tmp_path / "eval.yaml"
    config_path.write_text(
        """
id: smoke
name: Smoke Eval
providers:
  - id: echo
    name: echo
prompts:
  - id: greeting
    prompt: "hello {{name}}"
tests:
  - id: alice
    vars:
      name: Alice
    assertions:
      - type: contains
        expected: Alice
""",
        encoding="utf-8",
    )

    result = run_eval_file(config_path)

    assert result.passed
    assert result.summary()["cells"] == 1
    assert result.cells[0].output == "hello Alice"
    assert result.cells[0].assertions[0].status.value == "pass"


def test_eval_runner_loads_jsonl_dataset(tmp_path):
    dataset_path = tmp_path / "rows.jsonl"
    dataset_path.write_text(
        "\n".join(
            [
                json.dumps({"id": "row-1", "prompt": "alpha", "expected": "alpha"}),
                json.dumps({"id": "row-2", "prompt": "beta", "expected": "beta"}),
            ]
        ),
        encoding="utf-8",
    )
    config_path = tmp_path / "eval.json"
    config_path.write_text(
        json.dumps(
            {
                "id": "dataset",
                "providers": [{"id": "echo", "name": "echo"}],
                "datasets": [{"path": str(dataset_path)}],
            }
        ),
        encoding="utf-8",
    )

    config = load_eval_config(config_path)
    result = run_eval_file(config_path)

    assert [case.id for case in config.cases] == ["row-1", "row-2"]
    assert result.passed
    assert result.summary()["assertions"] == 2
