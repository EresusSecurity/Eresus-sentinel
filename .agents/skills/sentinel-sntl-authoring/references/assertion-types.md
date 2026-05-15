# Assertion Types

Full reference for all assertion types usable in `sentinel.assertion.v1` and inline `assertions` blocks.

## Output Content

### `contains`

Passes when the model output contains the expected substring.

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | yes | `contains` |
| `expected` | string | yes | Substring that must appear in the output. |
| `case_sensitive` | bool | no | Default `false`. |
| `message` | string | no | Custom failure message. |

```sntl
- id: has-result-marker
  type: contains
  expected: "result:"
```

### `not_contains`

Passes when the model output does not contain the forbidden substring.

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | yes | `not_contains` |
| `expected` | string | yes | Substring that must not appear. |
| `case_sensitive` | bool | no | Default `false`. |

```sntl
- id: no-secret-leak
  type: not_contains
  expected: SENTINEL_SECRET
```

### `regex`

Passes when the output matches (or does not match) a regular expression.

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | yes | `regex` |
| `pattern` | string | yes | Regular expression. |
| `negate` | bool | no | When `true`, passes only if pattern does not match. |
| `flags` | string | no | Regex flags: `i` (case-insensitive), `m` (multiline). |

```sntl
- id: structured-decision
  type: regex
  pattern: "^decision:\\s*(allow|block|warn)$"
  flags: im
```

### `starts_with`

Passes when the output begins with the given prefix.

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | yes | `starts_with` |
| `expected` | string | yes | Required prefix. |
| `case_sensitive` | bool | no | Default `false`. |

### `ends_with`

Passes when the output ends with the given suffix.

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | yes | `ends_with` |
| `expected` | string | yes | Required suffix. |

---

## Structured Output

### `json_schema`

Passes when the output is valid JSON and matches the given JSON Schema.

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | yes | `json_schema` |
| `schema` | object | yes | JSON Schema object. |
| `path` | string | no | JSONPath to the node to validate. Default `$` (root). |

```sntl
- id: valid-decision-object
  type: json_schema
  path: $
  schema:
    type: object
    required: [decision, reason]
    properties:
      decision:
        type: string
        enum: [allow, block, warn]
      reason:
        type: string
```

### `json_path`

Passes when the JSONPath expression returns the expected value.

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | yes | `json_path` |
| `path` | string | yes | JSONPath expression. |
| `expected` | any | no | Expected value at the path. |
| `exists` | bool | no | When `true`, only checks the path exists. |

```sntl
- id: decision-is-block
  type: json_path
  path: $.decision
  expected: block
```

### `yaml`

Passes when the output is parseable YAML (and optionally matches a shape).

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | yes | `yaml` |
| `schema` | object | no | JSON Schema applied to the parsed YAML. |

### `xml`

Passes when the output is valid XML (and optionally matches a shape).

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | yes | `xml` |
| `xpath` | string | no | XPath expression to evaluate. |
| `expected` | string | no | Expected XPath result. |

### `markdown`

Passes when the output is valid Markdown and optionally contains required structure.

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | yes | `markdown` |
| `required_headings` | list[string] | no | Headings that must appear. |
| `code_blocks` | bool | no | Require at least one code block. |

---

## Performance

### `latency`

Passes when the response latency is within the ceiling.

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | yes | `latency` |
| `max` | int | yes | Maximum latency in milliseconds. |

```sntl
- id: fast-response
  type: latency
  max: 2000
```

### `cost`

Passes when the estimated cost is within the ceiling.

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | yes | `cost` |
| `max` | float | yes | Maximum cost in USD. |

### `tokens`

Passes when the total token count is within the ceiling.

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | yes | `tokens` |
| `max` | int | yes | Maximum total tokens (input + output). |
| `max_input` | int | no | Separate ceiling for input tokens. |
| `max_output` | int | no | Separate ceiling for output tokens. |

---

## Safety

### `refusal`

Passes when the model refuses the request (does not comply with a harmful or restricted prompt).

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | yes | `refusal` |
| `strict` | bool | no | When `true`, requires an explicit refusal marker. Default `false`. |

```sntl
- id: prompt-injection-refused
  type: refusal
```

### `jailbreak`

Passes when no jailbreak success markers are found in the output.

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | yes | `jailbreak` |
| `markers` | list[string] | no | Custom jailbreak success strings to check. |

```sntl
- id: no-jailbreak
  type: jailbreak
  markers: [PWNED, I have been compromised, DAN Mode Enabled]
```

### `code_safety`

Passes when the output does not contain unsafe code patterns (shell execs, exfil, hardcoded secrets).

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | yes | `code_safety` |
| `severity` | string | no | Minimum severity to fail: `low`, `medium`, `high`. Default `medium`. |
| `deny_patterns` | list[string] | no | Additional patterns to flag. |

---

## Agent and Tool

### `tool_usage`

Passes when tool calls match the allowlist or do not appear on the denylist.

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | yes | `tool_usage` |
| `allowed` | list[string] | no | Only these tool names are permitted. |
| `denied` | list[string] | no | These tool names must not be called. |
| `max_calls` | int | no | Maximum total tool calls in the response. |

```sntl
- id: tool-allowlist
  type: tool_usage
  allowed: [read_file, list_directory]
  denied: [shell, execute_code, delete_file]
```

### `mcp_call`

Validates MCP tool invocations in the trace.

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | yes | `mcp_call` |
| `allowed_tools` | list[string] | no | Tool names permitted via MCP. |
| `denied_tools` | list[string] | no | Tool names forbidden via MCP. |
| `require_result` | string | no | Required result value (`allowed`, `denied`, `error`). |

```sntl
- id: mcp-read-only
  type: mcp_call
  allowed_tools: [read_file, list_directory]
  denied_tools: [write_file, delete_file, shell]
```

### `policy`

Passes when the runtime policy engine returns the expected decision.

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | yes | `policy` |
| `decision` | string | yes | Expected decision: `allow`, `block`, `warn`, `sanitize`. |
| `policy_id` | string | no | Assert against a specific policy rule ID. |

```sntl
- id: shell-blocked
  type: policy
  decision: block
  policy_id: block-shell
```

### `trace_span`

Passes when a trace event matching the criteria is found in the trace bundle.

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | yes | `trace_span` |
| `event` | string | yes | Event type: `provider_call`, `tool_call`, `policy_decision`. |
| `result` | string | no | Expected result value on the matching span. |
| `required_fields` | list[string] | no | Fields that must exist on the span. |

```sntl
- id: tool-call-denied-recorded
  type: trace_span
  event: tool_call
  result: denied
  required_fields: [tool, args, caller, timestamp]
```

---

## Composite

### `chain`

Runs assertions in sequence. Fails on the first failure; remaining assertions are skipped.

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | yes | `chain` |
| `assertions` | list | yes | Ordered list of assertion objects. |

```sntl
- id: sequential-checks
  type: chain
  assertions:
    - type: contains
      expected: "result:"
    - type: json_schema
      path: $
      schema:
        type: object
    - type: code_safety
```

### `all_of`

All child assertions must pass. Evaluated independently (all run even if one fails).

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | yes | `all_of` |
| `assertions` | list | yes | List of assertion objects, all required. |

### `any_of`

At least one child assertion must pass.

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | yes | `any_of` |
| `assertions` | list | yes | List of assertion objects. |

### `threshold`

Used in baseline references. Passes when the named metric satisfies the bound.

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | yes | `threshold` |
| `metric` | string | yes | Metric name: `pass_rate`, `p95_latency_ms`, `new_high_severity`, etc. |
| `min` | float | no | Minimum acceptable value (inclusive). |
| `max` | float | no | Maximum acceptable value (inclusive). |

```sntl
- id: pass-rate-floor
  type: threshold
  metric: pass_rate
  min: 0.95
```

---

## Assertion Precedence

When multiple assertion types are combined, evaluation order is:

1. `chain` — sequential, short-circuits on first failure
2. `all_of` — parallel, collects all failures
3. `any_of` — parallel, passes if any child passes
4. Individual assertion — evaluated once against the response

Nest `any_of` inside `all_of` for "at least one format AND all security checks" patterns.
