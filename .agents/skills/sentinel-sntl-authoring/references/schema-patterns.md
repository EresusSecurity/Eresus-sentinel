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

Template:

```sntl
schema: sentinel.report.v1
run_id: run-local
artifacts:
  - id: json
    format: json
    path: reports/run-local.json
  - id: sarif
    format: sarif
    path: reports/run-local.sarif
```
