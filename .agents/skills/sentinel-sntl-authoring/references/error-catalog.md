# Error Catalog

Validation error codes returned by `sntl.load`, `sntl.load_any`, `--inspect`, and `--check`.

Each entry shows: error code, cause, and the exact fix.

---

## Schema Errors

### `E001 missing_required_key`

**Cause:** A required key is absent from the document.

**Example:** `missing required key: assertions`

**Fix:** Add the key with a valid value. Check `references/schema-patterns.md` for the required key list for your schema type.

---

### `E002 unknown_schema`

**Cause:** The `schema` field value is not a recognized schema identifier.

**Example:** `unknown schema: sentinel.eval.v2`

**Fix:** Use a supported schema from the table in `SKILL.md`. Current versions are all `v1`.

---

### `E003 missing_schema_key`

**Cause:** The document has no `schema` key at all.

**Fix:** Add `schema: sentinel.<type>.v1` as the first key. Never remove `schema` to silence validation errors.

---

### `E004 type_mismatch`

**Cause:** A field has the wrong type (e.g., a string where a list is expected).

**Example:** `type mismatch at providers: expected list, got string`

**Fix:** Correct the field type. Wrap single values in a list where required.

---

### `E005 duplicate_id`

**Cause:** Two items in the same list share the same `id` value.

**Example:** `duplicate id: case-1 at records[3]`

**Fix:** Use the `--dedup-ids` flag during migration, or manually assign unique IDs. IDs must be unique within their containing list.

---

### `E006 invalid_id_format`

**Cause:** An `id` value contains spaces, uppercase letters, dots, slashes, or other disallowed characters.

**Example:** `invalid id format: "My Case 1"`

**Fix:** Use lowercase kebab-case IDs: `my-case-1`. See ID Naming Conventions in `SKILL.md`.

---

### `E007 numeric_id`

**Cause:** An `id` field was provided as an integer instead of a string.

**Example:** `numeric id at records[2].id: 2`

**Fix:** Quote the value: `id: "case-002"`. Numeric IDs cause round-trip type mismatches.

---

### `E008 empty_required_list`

**Cause:** A list field required to be non-empty contains zero items.

**Example:** `empty required list: assertions`

**Fix:** Add at least one item to the list. For `assertions`, add a deterministic assertion type.

---

## Assertion Errors

### `E010 unknown_assertion_type`

**Cause:** The `type` field on an assertion is not recognized.

**Example:** `unknown assertion type: contains_all`

**Fix:** Use a supported type from `references/assertion-types.md`. Closest match: `all_of` wrapping multiple `contains`.

---

### `E011 assertion_missing_expected`

**Cause:** A `contains` or `not_contains` assertion has no `expected` field.

**Fix:** Add `expected: "your substring"`.

---

### `E012 assertion_missing_pattern`

**Cause:** A `regex` assertion has no `pattern` field.

**Fix:** Add `pattern: "your-regex"`.

---

### `E013 assertion_missing_schema`

**Cause:** A `json_schema` assertion has no `schema` field.

**Fix:** Add a `schema` object with at least `type: object`.

---

### `E014 assertion_missing_path`

**Cause:** A `json_path` assertion has no `path` field.

**Fix:** Add `path: $.your.field`.

---

### `E015 assertion_chain_empty`

**Cause:** A `chain`, `all_of`, or `any_of` assertion has an empty `assertions` list.

**Fix:** Add at least one child assertion to the `assertions` list.

---

### `E016 circular_assertion_reference`

**Cause:** An assertion references itself or creates a cycle through `chain`/`all_of`/`any_of`.

**Fix:** Break the cycle. Assertion composition must be a directed acyclic tree.

---

## Provider Errors

### `E020 live_provider_in_ci`

**Cause:** A provider has `allow_live: true` but the environment is `ci` or `test`.

**Example:** `live provider in ci environment: openai-gpt4o`

**Fix:** Set `allow_live: false` for all providers in `ci` and `test` environments, or use `mock` type.

---

### `E021 inline_secret`

**Cause:** A provider field contains a literal token or key value instead of an env reference.

**Example:** `inline secret detected at providers[1].auth.token`

**Fix:** Replace with `${env:YOUR_VAR_NAME}`. Run `sentinel platform hygiene .` to find all occurrences.

---

### `E022 unknown_provider_type`

**Cause:** The `type` field is not a supported provider adapter.

**Fix:** Use a supported type from `references/provider-adapters.md`.

---

### `E023 missing_provider_url`

**Cause:** An `http`, `mcp` (HTTP transport), or `browser` provider has no `url` field.

**Fix:** Add `url: ${env:PROVIDER_URL}`.

---

### `E024 missing_mcp_command`

**Cause:** An `mcp` provider with `transport: stdio` has no `command` field.

**Fix:** Add `command: [python, -m, your.mcp.server]`.

---

### `E025 env_var_undefined`

**Cause:** A `${env:VAR_NAME}` reference resolves to an empty or undefined variable at validation time.

**Example:** `env var undefined: PROVIDER_TOKEN`

**Fix:** Export the variable in the execution context, or add it to `.env.example` for documentation.

---

## Migration Errors

### `E030 unsupported_yaml_feature`

**Cause:** The YAML source uses tags (`!!type`), anchors (`&name`), or aliases (`*name`).

**Fix:** Rewrite the YAML into plain data (expand anchors, remove tags) before migrating.

---

### `E031 toml_null_field`

**Cause:** A field contains `null`, which TOML cannot represent.

**Fix:** Use JSON or SNTL as the source format when null values must be preserved.

---

### `E032 csv_nested_object`

**Cause:** A CSV cell contains a JSON object or list string that cannot be safely parsed.

**Fix:** Split the nested structure into separate columns, or pre-process the CSV in Python before migration.

---

### `E033 roundtrip_mismatch`

**Cause:** The file content changed after a serialization round-trip (`--check` failed).

**Example:** `round-trip mismatch at: records[2].tags`

**Fix:** Inspect the differing path with `sntl.diff`. Usually caused by list ordering, float precision, or type coercion. Fix the source value or add an explicit type annotation.

---

### `E034 source_format_ambiguous`

**Cause:** The converter cannot determine the source format from the file extension alone.

**Fix:** Pass `--from <format>` explicitly (e.g., `--from json`, `--from yaml`).

---

### `E035 schema_required_for_format`

**Cause:** The source format (JSON, YAML, TOML) does not embed a `schema` field and none was provided.

**Fix:** Pass `--schema sentinel.<type>.v1` to the convert command.

---

## Policy and Runtime Errors

### `E040 extends_unknown_target`

**Cause:** An environment's `extends` references a name that does not exist in the same file.

**Example:** `extends target not found: staging`

**Fix:** Define the target environment in the same `environments` map, or remove the `extends` key.

---

### `E041 extends_cycle`

**Cause:** Two or more environments form a cycle through `extends`.

**Example:** `extends cycle detected: ci -> base -> ci`

**Fix:** Break the cycle. Environment inheritance must be a DAG.

---

### `E042 plugin_executable_content`

**Cause:** A `.sentinel` plugin manifest contains a field that could execute code at load time.

**Example:** `executable content in plugin: hooks[0].exec`

**Fix:** Plugin manifests are data-only. Remove all executable fields. Hook paths must reference static files.

---

### `E043 baseline_locked_regression`

**Cause:** A new run's metrics regressed below a locked baseline's threshold assertion.

**Example:** `baseline regression: pass_rate 0.91 < min 0.95`

**Fix:** Either fix the regression in the product or explicitly update the baseline with `--update-baseline` after review.

---

### `E044 missing_lineage`

**Cause:** A dataset document has no `lineage` block.

**Fix:** Add `lineage` with at least `owner` and `source`. See Evidence and Lineage in `references/schema-patterns.md`.

---

## Hygiene Errors

### `E050 forbidden_brand_string`

**Cause:** A Python source file, doc, or test contains a forbidden external product name.

**Fix:** Replace with internal terminology. Run `pytest tests/test_hygiene.py` to identify all locations.

---

### `E051 turkish_ui_string`

**Cause:** A frontend source file contains Turkish UI copy.

**Fix:** Use English for all user-facing copy. See `tests/test_hygiene.py` for the word list.

---

### `E052 emoji_in_frontend`

**Cause:** A frontend source file contains emoji characters.

**Fix:** Use Lucide icon components instead.

---

## How to Read Structured Issues

When `--inspect` returns issues, each entry has:

```json
{
  "code": "E005",
  "path": "records[3].id",
  "message": "duplicate id: case-1",
  "severity": "error"
}
```

| Field | Description |
|---|---|
| `code` | Error code from this catalog. |
| `path` | JSONPath to the offending value. |
| `message` | Human-readable description. |
| `severity` | `error` (blocks validation) or `warning` (reported, does not block). |

Fix all `error` severity issues before committing. Address `warning` issues before merging to main.
