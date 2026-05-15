# Provider Adapters

Full reference for all provider types usable in `sentinel.provider.v1` and inline `providers` blocks.

## Capability Matrix

| Type | Live calls | Streaming | Tools | JSON mode | Local-only |
|---|---|---|---|---|---|
| `mock` | no | optional | optional | yes | yes |
| `http` | yes | optional | no | yes | no |
| `mcp` | yes | optional | yes | yes | no |
| `local` | yes | no | no | yes | yes |
| `browser` | yes | no | no | no | no |
| `script` | optional | no | no | optional | optional |
| `openai` | yes | yes | yes | yes | no |
| `anthropic` | yes | yes | yes | yes | no |

Always use `mock` or `local` as the default for CI and test environments.

---

## `mock`

Deterministic echo provider for offline testing. Returns a configurable static response.

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | Stable provider ID. |
| `type` | string | yes | `mock` |
| `model` | string | no | Model name used in trace output. Default `mock`. |
| `response` | string | no | Static response to return. Default empty. |
| `response_template` | string | no | Response with `{{variable}}` substitution. |
| `capabilities.streaming` | bool | no | Simulate streaming chunks. Default `false`. |
| `capabilities.json` | bool | no | Return response wrapped as JSON. Default `false`. |
| `capabilities.tools` | bool | no | Accept tool call requests. Default `false`. |
| `policy.allow_live` | bool | no | Must be `false`. |
| `policy.max_tokens` | int | no | Token ceiling for validation. |

```sntl
- id: local-mock
  type: mock
  model: deterministic-echo
  response_template: "result: {{expected_behavior}}"
  capabilities:
    streaming: false
    json: true
    tools: false
  policy:
    allow_live: false
    max_tokens: 512
```

---

## `http`

Generic HTTP REST provider. Sends prompts as POST requests to an arbitrary endpoint.

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | Stable provider ID. |
| `type` | string | yes | `http` |
| `url` | string | yes | Base URL. Use `${env:VAR}` for runtime injection. |
| `method` | string | no | HTTP method. Default `POST`. |
| `headers` | object | no | Extra request headers. |
| `auth.type` | string | no | `bearer`, `basic`, `api_key`, or `none`. |
| `auth.token` | string | no | Token value. Use `${env:VAR}`. |
| `auth.header` | string | no | Header name for `api_key` auth. Default `X-API-Key`. |
| `auth.username` | string | no | Username for `basic` auth. |
| `auth.password` | string | no | Password for `basic` auth. Use `${env:VAR}`. |
| `request_template` | object | no | JSON template for the request body. |
| `response_path` | string | no | JSONPath to extract the response text. |
| `timeout` | int | no | Timeout in seconds. Default `30`. |
| `capabilities.streaming` | bool | no | Use SSE streaming. Default `false`. |
| `capabilities.json` | bool | no | Expect JSON response. Default `true`. |
| `policy.allow_live` | bool | no | Must be `true` for this provider type to execute. |
| `policy.max_tokens` | int | no | Token ceiling. |

```sntl
- id: http-target
  type: http
  url: ${env:PROVIDER_URL}
  auth:
    type: bearer
    token: ${env:PROVIDER_TOKEN}
  request_template:
    model: gpt-4o
    messages:
      - role: user
        content: "{{prompt}}"
  response_path: $.choices[0].message.content
  timeout: 30
  policy:
    allow_live: true
    max_tokens: 2048
```

---

## `mcp`

Model Context Protocol provider. Communicates with an MCP server via stdio or HTTP transport.

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | Stable provider ID. |
| `type` | string | yes | `mcp` |
| `transport` | string | yes | `stdio` or `http`. |
| `command` | list[string] | if stdio | Command and args to spawn the server. |
| `url` | string | if http | MCP server URL. |
| `tools` | list[string] | no | Tool allowlist. If omitted, all tools are permitted. |
| `capabilities.tools` | bool | no | Default `true`. |
| `policy.allow_live` | bool | no | Must be `true` to execute. |
| `policy.tool_allowlist` | list[string] | no | Runtime enforcement of allowed tools. |

```sntl
- id: mcp-local
  type: mcp
  transport: stdio
  command: [python, -m, sentinel.mcp.server, --read-only]
  tools: [read_file, list_directory, search]
  capabilities:
    tools: true
  policy:
    allow_live: false
    tool_allowlist: [read_file, list_directory]
```

```sntl
- id: mcp-remote
  type: mcp
  transport: http
  url: ${env:MCP_SERVER_URL}
  policy:
    allow_live: true
    tool_allowlist: [read_file, search]
```

---

## `local`

Local model provider via CLI subprocess (e.g., llama.cpp, Ollama).

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | Stable provider ID. |
| `type` | string | yes | `local` |
| `command` | list[string] | yes | Command and args to invoke the model. |
| `model` | string | no | Model name or path. |
| `format` | string | no | Response format: `text` or `json`. Default `text`. |
| `timeout` | int | no | Timeout in seconds. Default `60`. |
| `policy.allow_live` | bool | no | Set `true` to execute. |
| `policy.max_tokens` | int | no | Token ceiling passed as a CLI flag if supported. |

```sntl
- id: ollama-local
  type: local
  command: [ollama, run, llama3]
  model: llama3
  format: text
  timeout: 120
  policy:
    allow_live: true
    max_tokens: 1024
```

---

## `browser`

Browser-based provider using Playwright for UI automation of web chat interfaces.

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | Stable provider ID. |
| `type` | string | yes | `browser` |
| `url` | string | yes | URL of the chat interface. |
| `selectors.input` | string | yes | CSS selector for the prompt input field. |
| `selectors.submit` | string | yes | CSS selector for the submit button. |
| `selectors.output` | string | yes | CSS selector for the response output element. |
| `auth` | object | no | Browser-based auth config (session cookie or pre-auth script). |
| `timeout` | int | no | Page load timeout in seconds. Default `30`. |
| `policy.allow_live` | bool | no | Must be `true` to execute. |

```sntl
- id: browser-chat
  type: browser
  url: ${env:CHAT_URL}
  selectors:
    input: "textarea[data-testid=chat-input]"
    submit: "button[data-testid=send-button]"
    output: "div[data-testid=response]"
  timeout: 45
  policy:
    allow_live: true
```

---

## `script`

Custom evaluation script provider. Runs an arbitrary script that receives the prompt on stdin and writes the response to stdout.

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | Stable provider ID. |
| `type` | string | yes | `script` |
| `command` | list[string] | yes | Script command and args. |
| `format` | string | no | Response format: `text` or `json`. Default `text`. |
| `env` | object | no | Extra environment variables to pass. Use `${env:VAR}` for values. |
| `timeout` | int | no | Timeout in seconds. Default `30`. |
| `policy.allow_live` | bool | no | Set `true` to execute. |

```sntl
- id: custom-eval-script
  type: script
  command: [python, scripts/eval_harness.py, --model, gpt-4o]
  format: json
  env:
    OPENAI_API_KEY: ${env:OPENAI_API_KEY}
  timeout: 60
  policy:
    allow_live: true
```

---

## `openai`

OpenAI-compatible provider (OpenAI, Azure OpenAI, or any OpenAI-compatible endpoint).

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | Stable provider ID. |
| `type` | string | yes | `openai` |
| `model` | string | yes | Model name, e.g. `gpt-4o`, `gpt-4o-mini`. |
| `base_url` | string | no | Override base URL for Azure or compatible endpoints. |
| `auth.token` | string | yes | API key. Use `${env:OPENAI_API_KEY}`. |
| `parameters.temperature` | float | no | Sampling temperature. |
| `parameters.max_tokens` | int | no | Max output tokens. |
| `parameters.top_p` | float | no | Nucleus sampling. |
| `capabilities.streaming` | bool | no | Enable streaming. Default `false`. |
| `capabilities.tools` | bool | no | Enable function calling. Default `false`. |
| `policy.allow_live` | bool | no | Must be `true` to execute. |

```sntl
- id: openai-gpt4o
  type: openai
  model: gpt-4o
  auth:
    token: ${env:OPENAI_API_KEY}
  parameters:
    temperature: 0
    max_tokens: 1024
  capabilities:
    streaming: false
    tools: true
  policy:
    allow_live: true
    max_tokens: 1024
```

---

## `anthropic`

Anthropic Claude provider.

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | Stable provider ID. |
| `type` | string | yes | `anthropic` |
| `model` | string | yes | Model name, e.g. `claude-opus-4-5`, `claude-sonnet-4-5`. |
| `auth.token` | string | yes | API key. Use `${env:ANTHROPIC_API_KEY}`. |
| `parameters.max_tokens` | int | no | Max output tokens. Required by Anthropic API. |
| `parameters.temperature` | float | no | Sampling temperature. |
| `capabilities.streaming` | bool | no | Enable streaming. Default `false`. |
| `capabilities.tools` | bool | no | Enable tool use. Default `false`. |
| `policy.allow_live` | bool | no | Must be `true` to execute. |

```sntl
- id: claude-sonnet
  type: anthropic
  model: claude-sonnet-4-5
  auth:
    token: ${env:ANTHROPIC_API_KEY}
  parameters:
    max_tokens: 1024
    temperature: 0
  capabilities:
    streaming: false
    tools: true
  policy:
    allow_live: true
    max_tokens: 1024
```

---

## Policy Fields (All Providers)

| Field | Type | Default | Description |
|---|---|---|---|
| `allow_live` | bool | `false` | Allow live API calls. Set `false` for all CI providers. |
| `max_tokens` | int | — | Hard ceiling on tokens. Fails the run if exceeded. |
| `rate_limit` | int | — | Max requests per minute. |
| `retry.max_attempts` | int | `3` | Retry attempts on transient errors. |
| `retry.backoff_seconds` | float | `1.0` | Initial backoff between retries. |
| `cache.enabled` | bool | `false` | Cache responses by prompt hash. |
| `cache.ttl_seconds` | int | `86400` | Cache TTL. |
| `tool_allowlist` | list[string] | — | Enforced at runtime; calls to unlisted tools are denied. |
