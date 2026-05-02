from pathlib import Path

import yaml

import sentinel


ROOT = Path(__file__).resolve().parents[1]


def _workflow() -> dict:
    return yaml.safe_load((ROOT / "ci" / "github-actions.yml").read_text(encoding="utf-8"))


def _pyproject_version() -> str:
    import re

    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r"(?m)^version\s*=\s*[\"']([^\"']+)[\"']", text)
    assert match
    return match.group(1)


def test_ci_python_matrix_covers_supported_versions():
    matrix = _workflow()["jobs"]["fast-tests"]["strategy"]["matrix"]

    assert matrix["python-version"] == ["3.10", "3.11", "3.12", "3.13", "3.14"]


def test_ci_optional_extras_matrix_is_explicit():
    matrix = _workflow()["jobs"]["optional-extras"]["strategy"]["matrix"]

    assert {"firewall", "api", "hf", "analysis", "archive", "rust"}.issubset(
        set(matrix["extra"])
    )


def test_ci_package_smoke_builds_and_installs_wheel():
    steps = _workflow()["jobs"]["package-smoke"]["steps"]
    run_blocks = "\n".join(str(step.get("run", "")) for step in steps)

    assert "python -m build --sdist --wheel" in run_blocks
    assert "python -m twine check dist/*" in run_blocks
    assert "python -m pip install dist/*.whl" in run_blocks
    assert "sentinel --help" in run_blocks


def test_ci_diff_security_uses_cli_diff_stdin():
    steps = _workflow()["jobs"]["diff-security"]["steps"]
    run_blocks = "\n".join(str(step.get("run", "")) for step in steps)

    assert "git diff origin/${{ github.base_ref }}...HEAD | sentinel diff -" in run_blocks


def test_runtime_version_matches_pyproject_source():
    assert sentinel.__version__ == _pyproject_version()


def test_precommit_manifest_exposes_skill_and_artifact_hooks():
    hooks = yaml.safe_load((ROOT / ".pre-commit-hooks.yaml").read_text(encoding="utf-8"))
    hook_ids = {hook["id"] for hook in hooks}

    assert {"sentinel-scan-skills", "sentinel-scan-artifacts", "sentinel-scan-mcp"}.issubset(
        hook_ids
    )
