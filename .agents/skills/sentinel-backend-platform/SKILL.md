---
name: sentinel-backend-platform
description: Build or modify Sentinel backend platform features: plugin manifests, scanner registries, MCP tools, provider adapters, report contracts, and secure API surfaces.
---

# Sentinel Backend Platform

Use this skill for backend work that expands Sentinel beyond a single scanner page.

## Inputs

- Target surface: plugin registry, MCP server, adapter, report, API, CLI, or auth.
- Desired contract: command, route, schema, file format, or tool call.
- Security boundary: workspace root, auth role, token scope, network destination, or local-only execution.

## Workflow

1. Find the existing module boundary before adding files.
2. Add a contract test first or in the same change.
3. Treat all user files as untrusted input.
4. Keep manifest formats data-only.
5. Reject path traversal, symlinks escaping roots, oversized files, and unknown schema versions.
6. Return structured errors and keep exit codes stable.
7. Keep AI or network-backed behavior behind explicit configuration.

## Secure Defaults

- No shell execution from manifests.
- No dynamic import from YAML, TOML, JSON, YARA, or `.sentinel` files.
- No arbitrary outbound network access from MCP tools.
- No secrets in logs, reports, or frontend bundles.
- No client-supplied role assignment during signup.
- No unauthenticated state-changing dashboard endpoints.

## Output Contract

When done, report:

- Backend surfaces changed.
- Security controls added.
- Tests run.
- Remaining backend gaps.
