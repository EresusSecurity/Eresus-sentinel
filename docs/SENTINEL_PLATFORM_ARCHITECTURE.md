# Sentinel Platform Architecture

Sentinel needs a platform backend, not only a dashboard. This file tracks the durable systems that move Sentinel from scanner collection to AI security operating system.

## Product Surfaces

| Surface | Target capability | First Sentinel implementation |
|---------|-------------------|-------------------------------|
| Eval matrix | Compare prompts, targets, models, datasets, assertions, latency, and cost in one table | Normalize existing scan outputs into a shared result table |
| Red-team plans | Application context, target adapter, security packs, strategies, report export, replay | Keep the new wizard backed by a registry instead of hard-coded UI arrays |
| Provider adapters | HTTP, MCP, local model, browser workflow, custom script, hosted model | Define a strict adapter contract with timeouts, allowlists, and evidence capture |
| Plugin registry | Python plugins, manifest packs, YARA rules, YAML/TOML policies, Sentinel manifests | Add manifest parsing and validation under `python/sentinel/plugins` |
| Secure MCP server | Local tools for scanner discovery, manifest validation, safe path-limited scans | Add stdio JSON-RPC server under `python/sentinel/mcp` |
| Skills and agent guidance | Agent workflows stay repo-native and deterministic-first | Add `.agents/skills` and root `AGENTS.md` |
| Reporting | JSON, SARIF, Markdown, HTML, CSV, JUnit snapshots | Keep schema contract tests before expanding report views |
| CI/CD | Repeatable commands with stable exit codes and no secrets in logs | Add fixture-driven tests for each backend surface |

## 30-Day Backend Work

| Priority | Deliverable | Acceptance |
|----------|-------------|------------|
| P0 | Manifest plugin registry | YAML, TOML, JSON, YARA, and `.sentinel` files validate without executing code |
| P0 | Secure MCP stdio server | Tool list and calls are allowlisted, path-limited, size-limited, and shell-free |
| P0 | Signup flow | Disabled unless explicitly allowed, with strong password validation and no role self-assignment |
| P1 | Registry-backed red-team UI | Security packs and strategies come from API data instead of component constants |
| P1 | Eval result table backend | Existing scan domains emit a shared result shape |
| P1 | Plugin authoring docs | Single contract for YAML, TOML, YARA, Python, and `.sentinel` packs |
| P2 | Adapter contract | HTTP and MCP target adapters share timeout, retry, auth, evidence, and error rules |

## Secure Defaults

- Plugin manifests are data, never executable code.
- YARA files are parsed as rules and metadata unless an optional compiler is explicitly installed and enabled.
- MCP tools expose read-only scanner operations first.
- Signup is off by default and never accepts client-supplied roles.
- All scan evidence is bounded, redacted, and serialized through the common finding contract.
- AI or judge adapters stay optional and must be explicitly configured.

## Directory Plan

| Directory | Purpose |
|-----------|---------|
| `.agents/skills` | Agent Skills for deterministic Sentinel workflows |
| `python/sentinel/plugins` | Manifest registry, loaders, validation, pack discovery |
| `python/sentinel/mcp` | Secure MCP stdio server and tool surface |
| `rules/packs` | Built-in manifest and YARA examples |
| `docs` | Authoring guides and backend contracts |
| `tests` | Fixture-driven contract tests for each surface |
