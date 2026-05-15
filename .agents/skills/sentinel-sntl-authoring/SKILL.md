---
name: sentinel-sntl-authoring
description: Author, migrate, validate, and review Sentinel .sntl and .sentinel files for eval suites, datasets, assertions, providers, runtime policies, rule packs, red-team plans, plugins, reports, traces, and baselines.
---

# Sentinel SNTL Authoring

Use this skill whenever a task asks to create, edit, migrate, validate, or explain `.sntl` or `.sentinel` files.

## Core Rules

1. Use `.sntl` for human-authored Sentinel configs, eval suites, datasets, assertions, providers, red-team plans, runtime policies, baselines, traces, and reports.
2. Use `.sentinel` for packaged plugin and rule-pack manifests.
3. Keep the first meaningful key `schema` unless the existing file already follows another local order.
4. Prefer deterministic assertions, mock providers, replay inputs, and local-only execution.
5. Do not add shell execution, dynamic imports, network calls, or plugin execution behavior to manifests.
6. Treat YAML, TOML, JSON, YARA, `.sntl`, and `.sentinel` files as untrusted input.
7. Validate every authored or migrated file before finishing.
8. Keep user-facing copy in English.
9. Do not add inline code comments.
10. Do not add external product references.

## Workflow

1. Identify the target schema.
2. Read nearby examples under `examples/` and existing files in the same schema family.
3. If migrating, use `sentinel.sntl` conversion APIs instead of hand-copying fields.
4. Author the smallest valid document first.
5. Add required evidence, lineage, profiles, environments, policies, or assertions.
6. Validate with `sntl.load`, `sntl.load_any`, or the CLI.
7. For eval/runtime/red-team files, simulate or plan the execution.
8. Report the schema, file path, validation command, and any unresolved gaps.

## Schema Choice

Use this quick mapping:

| Need | Schema |
|---|---|
| Shared layered configuration | `sentinel.config.v1` |
| Evaluation suite | `sentinel.eval.v1` |
| Dataset records | `sentinel.dataset.v1` |
| Assertion pack | `sentinel.assertion.v1` |
| Provider contract | `sentinel.provider.v1` |
| Red-team attack plan | `sentinel.redteam.v1` |
| Runtime enforcement policy | `sentinel.runtime.v1` |
| Team or org policy pack | `sentinel.policy.v1` |
| Plugin manifest | `sentinel.plugin.v1` |
| Rule pack | `sentinel.rulepack.v1` |
| Stored run metadata | `sentinel.run.v1` |
| Trace event bundle | `sentinel.trace.v1` |
| Baseline reference | `sentinel.baseline.v1` |
| Report bundle | `sentinel.report.v1` |

For detailed field patterns, read `references/schema-patterns.md`.

For migration from JSON, JSONL, CSV, TOML, YAML, or YARA, read `references/migration-recipes.md`.

## Validation Commands

Use focused validation:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=python python3 -m pytest tests/test_sntl_library.py
```

Inspect one file:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=python python3 -m sentinel.cli.main convert path/to/file.sntl --inspect
```

Check round-trip stability:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=python python3 -m sentinel.cli.main convert path/to/file.sntl --check
```

Simulate a platform config:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=python python3 -m sentinel.cli.main simulate path/to/eval.sntl
```

Run hygiene after broad edits:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=python python3 -m sentinel.cli.main platform hygiene .
```

## Authoring Patterns

Eval suite:

```sntl
schema: sentinel.eval.v1
name: local-firewall-smoke
providers:
  - id: local
    type: mock
prompts:
  - id: base
    template: |
      Review {{input}}
      Return a structured decision.
variables:
  - input: hello
assertions:
  - id: marker
    type: contains
    expected: result
```

Dataset:

```sntl
schema: sentinel.dataset.v1
name: firewall-cases
records:
  - id: case-1
    input: hello
    expected: allow
```

Runtime policy:

```sntl
schema: sentinel.runtime.v1
name: runtime-default
mode: simulate
policies:
  - id: block-secret-exfiltration
    action: block
    enabled: true
    match:
      event: tool_call
      contains_any: [token, secret, password]
```

Rule pack:

```sntl
schema: sentinel.rulepack.v1
name: runtime-rules
rules:
  - id: unsafe-tool-call
    type: runtime
    severity: high
    match:
      tool: shell
      args_contains_any: [curl, token, password]
```

## Migration APIs

Use the public Python API:

```python
from sentinel import sntl

sntl.convert_file("suite.json", "suite.sntl", schema="sentinel.eval.v1")
sntl.convert_file("cases.jsonl", "cases.sntl", schema="sentinel.dataset.v1", name="cases")
sntl.convert_file("runtime.toml", "runtime.sntl", schema="sentinel.runtime.v1")
sntl.convert_file("assertions.yaml", "assertions.sntl", schema="sentinel.assertion.v1")
sntl.convert_file("rules.yara", "rules.sntl")
```

Use CLI migration:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=python python3 -m sentinel.cli.main convert legacy.json --target legacy.sntl --schema sentinel.config.v1
```

Plan a directory migration:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=python python3 -m sentinel.cli.main convert imports --target imports-sntl --recursive --source-formats json jsonl csv toml yaml yara
```

## Completion Checklist

- The document has a known `schema`.
- Required root keys exist.
- IDs are stable and unique.
- Secrets are referenced through env or vault fields, not inline values.
- Mock or local providers are default for tests.
- Runtime and plugin manifests are data-only.
- Migration output validates.
- Round-trip check passes for authored `.sntl` files.
- No external product names or Turkish user-facing copy were added.
