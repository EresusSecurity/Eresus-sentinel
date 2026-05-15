# Migration Recipes

Use `sentinel.sntl` for migrations. Do not hand-copy foreign formats unless the converter cannot represent the source.

## JSON To SNTL

Command:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=python python3 -m sentinel.cli.main convert suite.json --target suite.sntl --from json --schema sentinel.eval.v1
```

Python:

```python
from sentinel import sntl

sntl.convert_file("suite.json", "suite.sntl", source_format="json", schema="sentinel.eval.v1")
```

Use explicit schema when the JSON object does not already contain `schema`.

## JSONL To Dataset

Command:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=python python3 -m sentinel.cli.main convert cases.jsonl --target cases.sntl --schema sentinel.dataset.v1 --name cases
```

Behavior:

| Source | Target |
|---|---|
| Each JSONL line | One `records` entry. |
| Missing `id` | Generated `record-N`. |
| Extra fields | Preserved. |

## CSV To Dataset

Command:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=python python3 -m sentinel.cli.main convert cases.csv --target cases.sntl --schema sentinel.dataset.v1 --name cases
```

Behavior:

| Source | Target |
|---|---|
| Header row | Record keys. |
| `true` and `false` | Booleans. |
| Numeric cells | Numbers when safe. |
| Empty cells | Empty strings. |
| Missing `id` | Generated `row-N`. |

## TOML To Runtime Policy

Command:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=python python3 -m sentinel.cli.main convert runtime.toml --target runtime.sntl --schema sentinel.runtime.v1
```

Python:

```python
from sentinel import sntl

sntl.convert_file("runtime.toml", "runtime.sntl", schema="sentinel.runtime.v1")
```

TOML output cannot represent null values. Prefer `.sntl` or JSON when null must be preserved.

## YAML To SNTL

Command:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=python python3 -m sentinel.cli.main convert assertions.yaml --target assertions.sntl --from yaml --schema sentinel.assertion.v1
```

Supported safe subset:

| Feature | Support |
|---|---|
| Maps | Yes |
| Lists | Yes |
| Scalars | Yes |
| Inline lists | Yes |
| Inline objects | Yes |
| Literal blocks | Yes |
| Folded blocks | Yes |
| Tags | No |
| Anchors | No |
| Aliases | No |

If YAML uses tags, anchors, or aliases, rewrite it into plain data before migration.

## YARA To Rule Pack

Command:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=python python3 -m sentinel.cli.main convert rules.yara --target rules.sntl --from yara
```

Python:

```python
from sentinel import sntl

document = sntl.load_any("rules.yara").require()
rules = document.data["rules"]
```

Preserved fields:

| Source | Target |
|---|---|
| Rule name | `rules[].name` |
| Rule tags | `rules[].tags` |
| Modifiers | `rules[].modifiers` |
| `meta` section | `rules[].meta` |
| `strings` section | `rules[].strings` |
| Condition | `rules[].condition` |
| Source line | `rules[].source.line` |

## Batch Migration

Plan without writing:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=python python3 -m sentinel.cli.main convert imports --target imports-sntl --plan --source-formats json jsonl csv toml yaml yara
```

Write output:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=python python3 -m sentinel.cli.main convert imports --target imports-sntl --recursive --source-formats json jsonl csv toml yaml yara
```

Inspect result:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=python python3 -m sentinel.cli.main convert imports-sntl/suite.sntl --inspect
```

Check round-trip:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=python python3 -m sentinel.cli.main convert imports-sntl/suite.sntl --check
```

## API Checklist

Use these APIs:

| API | Purpose |
|---|---|
| `sntl.detect_format` | Determine source format. |
| `sntl.inspect_file` | Understand schema, keys, counts, and issues. |
| `sntl.plan_conversion` | Preview output paths and validation. |
| `sntl.convert_file` | Convert one file. |
| `sntl.migrate_tree` | Convert a directory. |
| `sntl.roundtrip_file` | Check stability through format conversion. |
| `sntl.compare_formats` | Explain format capabilities. |

## Failure Handling

When a migration fails:

1. Keep the original file untouched.
2. Read the structured `issues`.
3. Fix unsupported syntax or choose an explicit schema.
4. Re-run `--inspect`.
5. Re-run `--check`.

Do not silence validation errors by removing `schema`.
