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

## SARIF To Report

Command:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=python python3 -m sentinel.cli.main convert findings.sarif --target findings-report.sntl --from sarif --schema sentinel.report.v1
```

Python:

```python
from sentinel import sntl

sntl.convert_file("findings.sarif", "findings-report.sntl", source_format="sarif", schema="sentinel.report.v1")
```

Preserved fields:

| Source | Target |
|---|---|
| `runs[].results[].message.text` | `artifacts[].summary` |
| `runs[].results[].ruleId` | `artifacts[].rule_id` |
| `runs[].results[].level` | `artifacts[].severity` |
| `runs[].results[].locations[]` | `artifacts[].location` |
| `runs[].tool.driver.name` | `artifacts[].tool` |
| `runs[].invocations[].startTimeUtc` | `summary.started_at` |

Note: SARIF `level` values map as: `error` → `high`, `warning` → `medium`, `note` → `low`.

## JUnit XML To Report

Command:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=python python3 -m sentinel.cli.main convert results.xml --target results-report.sntl --from junit --schema sentinel.report.v1
```

Python:

```python
from sentinel import sntl

sntl.convert_file("results.xml", "results-report.sntl", source_format="junit", schema="sentinel.report.v1")
```

Preserved fields:

| Source | Target |
|---|---|
| `testsuite[@name]` | `artifacts[].tool` |
| `testcase[@name]` | `artifacts[].summary` |
| `failure` element | counted in `summary.failed` |
| `error` element | counted in `summary.errors` |
| `testsuite[@tests]` | `summary.total` |
| `testsuite[@time]` | `summary.duration_ms` (converted to ms) |

## Parquet To Dataset

Parquet is not natively supported by the converter. Convert to JSONL first:

```python
import pandas as pd
from sentinel import sntl

df = pd.read_parquet("cases.parquet")
jsonl_path = "cases.jsonl"
df.to_json(jsonl_path, orient="records", lines=True)
sntl.convert_file(jsonl_path, "cases.sntl", source_format="jsonl", schema="sentinel.dataset.v1", name="cases")
```

If the Parquet file is large, filter columns before converting:

```python
df = pd.read_parquet("cases.parquet", columns=["id", "input", "expected_output", "tags"])
```

Ensure numeric IDs are cast to strings to avoid round-trip type mismatch:

```python
df["id"] = df["id"].astype(str).apply(lambda v: f"case-{v}")
```

## OpenAPI To Provider Contract

OpenAPI is not natively supported. Extract base URL and auth scheme manually:

```python
import json
from sentinel import sntl

with open("openapi.json") as f:
    spec = json.load(f)

servers = spec.get("servers", [{}])
base_url = servers[0].get("url", "")
security = spec.get("components", {}).get("securitySchemes", {})
has_bearer = any(
    s.get("type") == "http" and s.get("scheme") == "bearer"
    for s in security.values()
)

provider_doc = {
    "schema": "sentinel.provider.v1",
    "providers": [{
        "id": "api-target",
        "type": "http",
        "url": base_url,
        "capabilities": {"json": True, "streaming": False},
        "policy": {"allow_live": False, "max_tokens": 2048},
    }]
}
if has_bearer:
    provider_doc["providers"][0]["auth"] = {
        "type": "bearer",
        "token": "${env:API_TOKEN}",
    }

with open("api-target.sntl", "w") as f:
    import yaml
    yaml.dump(provider_doc, f, default_flow_style=False)
```

Validate after writing:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=python python3 -m sentinel.cli.main convert api-target.sntl --inspect
```

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
2. Read the structured `issues` from `--inspect`.
3. Fix unsupported syntax or choose an explicit schema.
4. Re-run `--inspect`.
5. Re-run `--check`.

Do not silence validation errors by removing `schema`.

### Common Failure Scenarios

| Error | Cause | Fix |
|---|---|---|
| `missing required key: schema` | Source file has no `schema` field | Pass `--schema sentinel.<type>.v1` explicitly |
| `unknown schema: X` | Typo or unsupported schema version | Check the schema table in `SKILL.md` |
| `duplicate id: case-1` | Two records share the same `id` | Renumber with `--dedup-ids` flag or edit source |
| `unsupported yaml tag: !!python/object` | YAML with non-safe tags | Rewrite source using plain YAML before migrating |
| `anchor/alias not supported` | YAML uses `&anchor` or `*alias` | Expand anchors manually and re-run |
| `null value in non-nullable field` | TOML round-trip strips nulls | Use JSON or SNTL source when null must be preserved |
| `round-trip mismatch at: records[2].tags` | List serialization differs by format | Inspect with `--check` and fix the affected record |
| `inline secret detected` | A field value matches a secret pattern | Replace with `${env:VAR_NAME}` |
| `numeric id converted to int` | Integer IDs break string comparisons | Cast all IDs to strings before migrating |
| `SARIF level unknown: open` | Non-standard severity value in SARIF | Map manually before converting |

### Data Loss Warnings by Format

| Source Format | Fields that may be lost |
|---|---|
| YAML | Tags (`!!type`), anchors, aliases |
| TOML | `null` values (TOML has no null) |
| CSV | Nested objects (flattened to string) |
| YARA | Private modifiers, global condition context |
| SARIF | `fixes[]`, `suppressions[]`, `relatedLocations[]` |
| JUnit | `system-out`, `system-err` content |
| Parquet | Column types not representable as JSON scalars |

Always run `--inspect` before and `--check` after to confirm no silent data loss.
