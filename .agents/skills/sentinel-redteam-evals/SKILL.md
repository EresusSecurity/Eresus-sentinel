---
name: sentinel-redteam-evals
description: Create Sentinel red-team plans, deterministic eval suites, assertion registries, replay fixtures, and report contracts.
---

# Sentinel Red-Team Evals

Use this skill when adding or improving red-team, firewall, eval, assertion, or replay coverage.

## Workflow

1. Identify the target: prompt firewall, HTTP endpoint, MCP server, agent workflow, RAG pipeline, or local model.
2. Define inputs, expected safe behavior, failure modes, and evidence fields.
3. Prefer deterministic assertions: exact match, contains, regex, JSON schema, latency, cost, refusal shape, rule id, and severity.
4. Use model-graded checks only when deterministic assertions cannot answer the question.
5. Store long test inputs in fixture files.
6. Add replay fixtures for any finding that should never regress.
7. Validate output through the shared `Finding` and scan result contracts.

## Plan Shape

- `target`: endpoint, provider, manifest, or local path.
- `purpose`: what the application is allowed to do.
- `security_packs`: selected risk families.
- `strategies`: delivery and mutation strategy names.
- `assertions`: deterministic pass/fail checks.
- `evidence`: prompt, output, rule id, severity, latency, remediation.

## Output Contract

When done, report:

- What behavior is being tested.
- Files changed.
- Commands to run.
- Required environment variables.
- Any fixture or replay gaps left.
