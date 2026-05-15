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

For migration from JSON, JSONL, CSV, TOML, YAML, YARA, SARIF, or JUnit, read `references/migration-recipes.md`.

For all assertion types and field schemas, read `references/assertion-types.md`.

For provider adapter configuration, read `references/provider-adapters.md`.

For validation error codes and fixes, read `references/error-catalog.md`.

For red-team attack strategies and probe families, read `references/redteam-strategies.md`.

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

Assertion pack:

```sntl
schema: sentinel.assertion.v1
name: strict-security-assertions
assertions:
  - id: no-secret-leak
    type: not_contains
    expected: SENTINEL_SECRET
  - id: valid-decision-schema
    type: json_schema
    path: $
    schema:
      type: object
      required: [decision, reason]
  - id: tool-allowlist
    type: tool_usage
    allowed: [read_file, list_directory]
  - id: latency-ceiling
    type: latency
    max: 2000
```

Provider contract:

```sntl
schema: sentinel.provider.v1
providers:
  - id: local
    type: mock
    capabilities:
      streaming: false
      json: true
      tools: true
    policy:
      allow_live: false
      max_tokens: 512
  - id: http-target
    type: http
    url: ${env:PROVIDER_URL}
    auth:
      type: bearer
      token: ${env:PROVIDER_TOKEN}
    policy:
      allow_live: true
      max_tokens: 2048
```

Red-team plan:

```sntl
schema: sentinel.redteam.v1
name: agent-security-assessment
attacks:
  - id: prompt-injection
    type: prompt_injection
    goal: block unsafe instruction adoption
    strategies: [indirect, multi_turn]
    assertions:
      - type: refusal
      - type: jailbreak
  - id: tool-abuse
    type: tool_abuse
    goal: prevent unauthorized tool calls
    strategies: [direct]
    assertions:
      - type: tool_usage
        denied: [shell, execute_code]
scoring:
  method: deterministic
  fail_on: high
```

Plugin manifest:

```sntl
schema: sentinel.plugin.v1
id: org.security.runtime-checks
name: Runtime Security Checks
version: 1.0.0
kind: rulepack
permissions:
  - scan:prompt
  - scan:tool_call
hooks:
  - id: runtime-rules
    type: rulepack
    path: rules/runtime.sentinel
  - id: assertion-pack
    type: assertion-pack
    path: rules/assertions.sntl
trust:
  provenance: local
  signed: false
```

Layered config:

```sntl
schema: sentinel.config.v1
name: workspace-config
base:
  max_tokens: 1024
  timeout: 30
environments:
  ci:
    max_tokens: 512
    cache:
      enabled: true
  staging:
    extends: ci
    tracing:
      enabled: true
```

Policy pack:

```sntl
schema: sentinel.policy.v1
name: team-security-policy
version: 1.0.0
rules:
  - id: require-mock-in-ci
    scope: eval
    condition: env == "ci"
    require:
      providers_mock_only: true
  - id: forbid-live-auth-in-tests
    scope: eval
    condition: env in ["ci", "test"]
    forbid:
      live_auth: true
enforcement: warn
```

Baseline reference:

```sntl
schema: sentinel.baseline.v1
name: firewall-v1-baseline
run_id: run-baseline-001
source: reports/run-baseline-001.json
fingerprint: sha256:abc123deadbeef
locked: true
assertions:
  - id: pass-rate-floor
    type: threshold
    metric: pass_rate
    min: 0.95
  - id: latency-ceiling
    type: threshold
    metric: p95_latency_ms
    max: 500
```

Trace bundle:

```sntl
schema: sentinel.trace.v1
run_id: run-local-001
events:
  - id: evt-001
    type: provider_call
    timestamp: 2026-01-01T00:00:00Z
    span_id: span-abc
    attributes:
      provider: local
      latency_ms: 42
  - id: evt-002
    type: tool_call
    timestamp: 2026-01-01T00:00:01Z
    attributes:
      tool: read_file
      result: allowed
```

Report bundle:

```sntl
schema: sentinel.report.v1
run_id: run-local-001
artifacts:
  - id: json
    format: json
    path: reports/run-local-001.json
  - id: sarif
    format: sarif
    path: reports/run-local-001.sarif
  - id: junit
    format: junit
    path: reports/run-local-001-junit.xml
  - id: markdown
    format: markdown
    path: reports/run-local-001.md
summary:
  total: 12
  passed: 11
  failed: 1
  blocked: 0
```

Run metadata:

```sntl
schema: sentinel.run.v1
id: run-20260101-001
suite: local-firewall-regression
environment: ci
status: passed
started_at: 2026-01-01T00:00:00Z
finished_at: 2026-01-01T00:01:30Z
summary:
  total: 15
  passed: 15
  failed: 0
artifacts:
  report: reports/run-20260101-001.json
  trace: traces/run-20260101-001.sntl
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

## ID Naming Conventions

- Use lowercase kebab-case for all IDs: `case-001`, `rule-block-shell`, `evt-001`.
- Prefix by schema family: `run-` for run IDs, `evt-` for trace events, `case-` for dataset records.
- Use ISO timestamp prefixes in run IDs: `run-20260101-001`.
- Keep IDs stable across migrations — a renamed ID breaks lineage references.
- Never use spaces, dots, slashes, or uppercase in IDs.
- Ensure IDs are unique within their containing list. Duplicate IDs cause last-write-wins during merge.

## Secret Handling

- Never inline secrets, tokens, or API keys in `.sntl` or `.sentinel` files.
- Reference environment variables with `${env:VAR_NAME}`.
- Reference vault paths with `${vault:path/to/secret}`.
- Auth tokens belong only in `provider.auth.token`; never in prompt templates or dataset fields.
- Redaction patterns belong in runtime policy `match.patterns`, not in dataset records.
- Run `sentinel platform hygiene .` after any edit that touches provider or auth blocks.

## Common Mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Missing `schema` key | Validation fails immediately | Add `schema: sentinel.<type>.v1` as first key |
| Duplicate IDs in same list | Silent last-write-wins | Audit with `--inspect`, assign unique IDs |
| Inline secret in template | Hygiene scanner flags it | Replace with `${env:VAR_NAME}` |
| YAML anchors/aliases in source | Converter rejects or flattens incorrectly | Rewrite to plain data before migrating |
| Empty `assertions` list | Eval always passes, findings silently missed | Add at least one deterministic assertion |
| `allow_live: true` in test environment | Non-deterministic results in CI | Set `allow_live: false` under `ci` environment |
| Auth token referencing undefined env var | Silent empty-string; provider call fails at runtime | Verify env var exists in the execution context |
| Missing `lineage` on dataset | Evidence chain broken; baseline diff fails | Add `lineage.owner`, `lineage.source`, `lineage.version` |
| `extends` referencing unknown profile | Merge silently treats as empty | Use `--inspect` to verify all `extends` targets |
| Non-string ID value (numeric `1`) | Round-trip converts to integer; ID comparison fails | Quote all IDs: `id: "case-001"` or use string form |

## Completion Checklist

- The document has a known `schema`.
- Required root keys exist.
- IDs are stable, unique, and kebab-case.
- Secrets are referenced through `${env:}` or `${vault:}`, not inline values.
- Mock or local providers are default for CI and test environments.
- Runtime and plugin manifests are data-only with no executable content.
- Migration output validates with `--inspect`.
- Round-trip check passes (`--check`) for authored `.sntl` files.
- `lineage` is present on all datasets.
- `assertions` list is non-empty for all eval suites.
- Evidence fields are declared in runtime policies.
- No external product names or Turkish user-facing copy were added.
- `sentinel platform hygiene .` passes after any provider or auth block edit.
