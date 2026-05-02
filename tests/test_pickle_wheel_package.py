from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_standalone_pickle_pyproject_exposes_maturin_package():
    text = (ROOT / "rust" / "sentinel-pickle" / "pyproject.toml").read_text(
        encoding="utf-8"
    )

    assert 'name = "sentinel-picklescan"' in text
    assert 'build-backend = "maturin"' in text
    assert 'module-name = "sentinel_pickle"' in text
    assert "pyo3/abi3-py38" in text


def test_pickle_wheel_workflow_builds_platform_matrix_and_publishes_signed_wheels():
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "pickle-wheels.yml").read_text(
            encoding="utf-8"
        )
    )
    matrix = workflow["jobs"]["build-wheels"]["strategy"]["matrix"]["include"]
    targets = {(entry["os"], entry["target"]) for entry in matrix}

    assert ("ubuntu-latest", "x86_64") in targets
    assert ("ubuntu-latest", "aarch64") in targets
    assert ("macos-13", "x86_64") in targets
    assert ("macos-14", "aarch64") in targets
    assert ("windows-latest", "x64") in targets
    assert workflow["permissions"]["id-token"] == "write"

    publish_steps = workflow["jobs"]["publish"]["steps"]
    uses = {step.get("uses", "") for step in publish_steps}

    assert "sigstore/gh-action-sigstore-python@v3.0.1" in uses
    assert "pypa/gh-action-pypi-publish@release/v1" in uses
