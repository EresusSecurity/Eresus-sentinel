# CI and Pre-Commit

Sentinel ships CI templates in `ci/` and pre-commit hooks in
`.pre-commit-hooks.yaml`.

## GitHub Actions

Copy `ci/github-actions.yml` to `.github/workflows/eresus-sentinel.yml`.
The template includes:

- Python 3.10 through 3.14 fast test matrix.
- Optional extras install smoke.
- Wheel and source distribution build smoke.
- PR diff security scan through `sentinel diff -`.

## Pre-Commit

```yaml
repos:
  - repo: https://github.com/eresus-security/sentinel
    rev: v0.1.0
    hooks:
      - id: sentinel-scan-skills
      - id: sentinel-scan-mcp
      - id: sentinel-scan-artifacts
```

Use `--allow-empty` only for hook wrappers that intentionally filter all files.
Direct no-file invocations fail closed.

## Local Release Smoke

```bash
python -m build --sdist --wheel --outdir /tmp/sentinel-dist
python -m twine check /tmp/sentinel-dist/*
python -m venv /tmp/sentinel-wheel
/tmp/sentinel-wheel/bin/python -m pip install /tmp/sentinel-dist/*.whl
/tmp/sentinel-wheel/bin/sentinel --help
```
