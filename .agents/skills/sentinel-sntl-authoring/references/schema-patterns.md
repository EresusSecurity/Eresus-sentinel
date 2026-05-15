# Schema Patterns

Use these patterns when authoring Sentinel `.sntl` documents.

## Eval Suite

Required keys:

| Key | Purpose |
|---|---|
| `schema` | Must be `sentinel.eval.v1`. |
| `name` | Stable suite name. |
| `providers` | Provider contracts or IDs. |
| `prompts` | Prompt templates. |
| `assertions` | Deterministic pass/fail checks. |

Recommended keys:

| Key | Purpose |
|---|---|
| `variables` | Inline matrix variables. |
| `datasets` | External dataset references. |
| `profiles` | Depth, speed, or risk profiles. |
| `environments` | CI, local, staging, or airgap values. |
| `reporting` | Export formats and evidence policy. |
| `lineage` | Source, owner, and change metadata. |

Template:

```sntl
schema: sentinel.eval.v1
name: suite-name
providers:
  - id: local
    type: mock
prompts:
  - id: base
    template: |
      Review {{input}}
      Return a structured decision.
variables:
  - input: sample
assertions:
  - id: contains-result
    type: contains
    expected: result
profiles:
  fast:
    variables:
      - input: smoke
  deep:
    datasets:
      - datasets/regression.sntl
```

## Dataset

Required keys:

| Key | Purpose |
|---|---|
| `schema` | Must be `sentinel.dataset.v1`. |
| `name` | Stable dataset name. |
| `records` | List of records. |

Recommended keys:

| Key | Purpose |
|---|---|
| `lineage` | Source, generation method, owner, and fingerprint. |
| `transforms` | Deterministic transforms. |
| `slices` | Named subsets. |
| `sharding` | Worker distribution hints. |

Template:

```sntl
schema: sentinel.dataset.v1
name: dataset-name
lineage:
  owner: security
  source: local
records:
  - id: case-1
    input: hello
    expected: allow
slices:
  smoke:
    include: [case-1]
```

## Assertion Pack

Required keys:

| Key | Purpose |
|---|---|
| `schema` | Must be `sentinel.assertion.v1`. |
| `name` | Stable pack name. |
| `assertions` | List of assertions. |

Deterministic assertion types to prefer:

| Type | Use |
|---|---|
| `contains` | Required marker text. |
| `not_contains` | Forbidden marker text. |
| `regex` | Pattern shape. |
| `json_schema` | Structured output contract. |
| `json_path` | Required nested value. |
| `yaml` | YAML parseability or shape. |
| `xml` | XML parseability or shape. |
| `markdown` | Markdown structure. |
| `latency` | Runtime ceiling. |
| `cost` | Cost ceiling. |
| `tokens` | Token ceiling. |
| `refusal` | Refusal behavior. |
| `jailbreak` | Jailbreak markers. |
| `policy` | Runtime policy decision. |
| `tool_usage` | Tool allowlist or denylist. |
| `mcp_call` | MCP call validation. |
| `trace_span` | Trace evidence. |
| `code_safety` | Unsafe generated code markers. |

Template:

```sntl
schema: sentinel.assertion.v1
name: strict-output
assertions:
  - id: valid-json
    type: json_schema
    path: $
    schema:
      type: object
      required: [decision]
  - id: no-secret
    type: not_contains
    expected: SENTINEL_SECRET
```

## Provider Contract

Required keys:

| Key | Purpose |
|---|---|
| `schema` | Must be `sentinel.provider.v1`. |
| `providers` | List of provider entries. |

Template:

```sntl
schema: sentinel.provider.v1
providers:
  - id: local
    type: mock
    capabilities:
      streaming: true
      json: true
      tools: false
    policy:
      allow_live: false
      max_tokens: 512
```

## Runtime Policy

Required keys:

| Key | Purpose |
|---|---|
| `schema` | Must be `sentinel.runtime.v1`. |
| `name` | Stable policy name. |
| `policies` | List of runtime decisions. |

Template:

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
    evidence:
      fields: [tool, args, destination]
```

## Red-Team Plan

Required keys:

| Key | Purpose |
|---|---|
| `schema` | Must be `sentinel.redteam.v1`. |
| `name` | Stable plan name. |
| `attacks` | List of attack entries. |

Template:

```sntl
schema: sentinel.redteam.v1
name: agent-runtime-redteam
attacks:
  - id: indirect-injection
    type: prompt_injection
    goal: block unsafe instruction adoption
    strategies: [indirect, multi_turn]
    assertions:
      - id: refusal-shape
        type: refusal
```

## Rule Pack

Required keys:

| Key | Purpose |
|---|---|
| `schema` | Must be `sentinel.rulepack.v1`. |
| `name` | Stable pack name. |
| `rules` | List of rules. |

Template:

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
    remediation: Use a scoped connector with explicit egress policy.
```

## Plugin Manifest

Required keys:

| Key | Purpose |
|---|---|
| `schema` | Must be `sentinel.plugin.v1`. |
| `id` | Stable plugin ID. |
| `name` | Human-readable plugin name. |
| `version` | Semantic version. |
| `kind` | Plugin class. |

Template:

```sntl
schema: sentinel.plugin.v1
id: local-rulepack
name: Local Rule Pack
version: 0.1.0
kind: rulepack
permissions:
  - read_workspace
hooks:
  - id: rules
    type: rulepack
    path: rules/runtime.sentinel
trust:
  signed: false
  source: local
```

## Trace Bundle

Template:

```sntl
schema: sentinel.trace.v1
run_id: run-local
events:
  - id: event-1
    type: provider_call
    timestamp: 2026-01-01T00:00:00Z
    attributes:
      provider: local
```

## Report Bundle

Required keys:

| Key | Purpose |
|---|---|
| `schema` | Must be `sentinel.report.v1`. |
| `run_id` | Reference to the run that produced this report. |
| `artifacts` | List of export artifacts. |

Recommended keys:

| Key | Purpose |
|---|---|
| `summary` | Aggregate pass/fail/blocked counts. |
| `lineage` | Source run, owner, and export date. |

Template:

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
  - id: csv
    format: csv
    path: reports/run-local-001.csv
  - id: html
    format: html
    path: reports/run-local-001.html
summary:
  total: 15
  passed: 14
  failed: 1
  blocked: 0
  warnings: 2
lineage:
  owner: security-engineering
  exported_at: 2026-01-01T00:02:00Z
```

## Config

Required keys:

| Key | Purpose |
|---|---|
| `schema` | Must be `sentinel.config.v1`. |
| `name` | Stable config name. |

Recommended keys:

| Key | Purpose |
|---|---|
| `base` | Shared default values applied before environment overrides. |
| `environments` | Named environment overrides with optional `extends`. |

Template:

```sntl
schema: sentinel.config.v1
name: workspace-config
base:
  max_tokens: 1024
  timeout: 30
  tracing:
    enabled: false
environments:
  ci:
    max_tokens: 512
    cache:
      enabled: true
    tracing:
      enabled: true
  local:
    extends: ci
    max_tokens: 1024
  staging:
    extends: ci
    tracing:
      enabled: true
      evidence: snapshot
```

Merge order: `base` → environment block → caller overrides.

## Baseline Reference

Required keys:

| Key | Purpose |
|---|---|
| `schema` | Must be `sentinel.baseline.v1`. |
| `name` | Stable baseline name. |
| `run_id` | Run ID this baseline captures. |
| `source` | Path or URI to the report artifact used. |

Recommended keys:

| Key | Purpose |
|---|---|
| `fingerprint` | SHA-256 of the source artifact for tamper detection. |
| `locked` | When `true`, diffs that regress past this baseline fail the build. |
| `assertions` | Threshold assertions that define acceptable regression bounds. |

Template:

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
  - id: no-new-highs
    type: threshold
    metric: new_high_severity
    max: 0
lineage:
  owner: security-engineering
  locked_by: alice
  locked_at: 2026-01-01T00:00:00Z
```

## Run Metadata

Required keys:

| Key | Purpose |
|---|---|
| `schema` | Must be `sentinel.run.v1`. |
| `id` | Stable run ID, unique across the workspace. |
| `suite` | Name of the eval suite that was executed. |
| `status` | `passed`, `failed`, `errored`, or `aborted`. |

Recommended keys:

| Key | Purpose |
|---|---|
| `environment` | Environment name from the suite's `environments` map. |
| `started_at` | ISO 8601 start time. |
| `finished_at` | ISO 8601 finish time. |
| `summary` | Aggregate counts. |
| `artifacts` | Paths to report and trace outputs. |

Template:

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
  blocked: 0
  duration_ms: 90000
artifacts:
  report: reports/run-20260101-001.json
  trace: traces/run-20260101-001.sntl
  sarif: reports/run-20260101-001.sarif
```

## Policy Pack

Required keys:

| Key | Purpose |
|---|---|
| `schema` | Must be `sentinel.policy.v1`. |
| `name` | Stable policy pack name. |
| `version` | Semantic version. |
| `rules` | List of policy rules. |

Recommended keys:

| Key | Purpose |
|---|---|
| `enforcement` | `error` (default), `warn`, or `off`. |
| `scope` | `eval`, `runtime`, or `all`. |

Template:

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
  - id: require-assertions
    scope: eval
    require:
      assertions_non_empty: true
  - id: require-lineage-on-datasets
    scope: dataset
    require:
      lineage_present: true
enforcement: warn
```

## Assertion Chains

Assertions can be composed with `chain`, `all_of`, and `any_of`.

Sequential chain (all must pass in order):

```sntl
assertions:
  - id: full-security-check
    type: chain
    assertions:
      - type: contains
        expected: "result:"
      - type: not_contains
        expected: ERROR
      - type: code_safety
      - type: jailbreak
```

Logical AND (all must pass, evaluated independently):

```sntl
assertions:
  - id: strict-compliance
    type: all_of
    assertions:
      - type: refusal
      - type: policy
        decision: block
      - type: trace_span
        event: tool_call
        result: denied
```

Logical OR (at least one must pass):

```sntl
assertions:
  - id: any-valid-format
    type: any_of
    assertions:
      - type: json_schema
        path: $
        schema:
          type: object
      - type: contains
        expected: "decision:"
```

Nested composition:

```sntl
assertions:
  - id: security-and-format
    type: all_of
    assertions:
      - type: any_of
        assertions:
          - type: refusal
          - type: jailbreak
      - type: latency
        max: 2000
      - type: not_contains
        expected: SENTINEL_SECRET
```

## Evidence and Lineage

Full `lineage` block for a dataset:

```sntl
lineage:
  owner: security-engineering
  source: sentinel-curated
  version: 3
  fingerprint: sha256:abc123deadbeef
  generated_by: sentinel.redteam.v1
  reviewed_by: [alice, bob]
  change_note: Added MCP injection cases
  created_at: 2026-01-01T00:00:00Z
  updated_at: 2026-06-01T00:00:00Z
```

Evidence field in runtime policy (captures what was observed on block/allow):

```sntl
policies:
  - id: block-shell
    action: block
    match:
      event: tool_call
      tool: shell
    evidence:
      fields: [tool, args, caller, timestamp]
      snapshot: true
      retention: 30d
```

Trace evidence reference in assertion:

```sntl
assertions:
  - id: tool-call-recorded
    type: trace_span
    event: tool_call
    required_fields: [tool, result, latency_ms]
    result: denied
```

## Scoring (Red-Team Plans)

Full scoring block:

```sntl
scoring:
  method: deterministic
  fail_on: high
  weights:
    prompt_injection: 1.5
    tool_abuse: 2.0
    data_exfiltration: 2.0
    jailbreak: 1.0
  thresholds:
    pass: 0.90
    warn: 0.80
  report_on_warn: true
```

Scoring methods:

| Method | Description |
|---|---|
| `deterministic` | Pass/fail based on assertion results only. Preferred. |
| `llm_graded` | AI judge scores each response. Requires judge provider. |
| `hybrid` | Deterministic first; LLM judge on failures only. |

Severity levels for `fail_on`:

| Level | Behavior |
|---|---|
| `critical` | Only critical findings halt the build. |
| `high` | Critical and high findings halt the build. |
| `medium` | Critical, high, and medium findings halt the build. |
| `any` | Any finding halts the build. |

## Environment Overrides

Environments are merged on top of the base config. Use `extends` to inherit from another environment.

Eval suite environments:

```sntl
environments:
  local:
    providers:
      - id: local-mock
        type: mock
  ci:
    extends: local
    cache:
      enabled: true
    reporting:
      formats: [json, sarif, junit]
  staging:
    extends: ci
    providers:
      - id: staging-http
        type: http
        url: ${env:STAGING_URL}
        policy:
          allow_live: true
```

Rules:
- `extends` must reference a sibling environment name defined in the same file.
- Keys in the child block override the parent's keys at that depth.
- Lists are replaced, not appended. Provide the full list in the child if you need additions.
- `extends` chains are resolved once at load time; cycles cause a validation error.
