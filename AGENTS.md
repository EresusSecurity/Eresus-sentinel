# Sentinel Agent Guide

This repository is a deterministic-first AI security platform. Keep scanners, reports, adapters, plugins, MCP tools, and UI changes aligned with that product promise.

## Working Rules

- Prefer deterministic checks over model-graded behavior.
- Keep AI and judge adapters optional.
- Do not hard-code external product names into product UI.
- Keep user-facing UI copy in English.
- Use Lucide icons for frontend controls.
- Do not add inline code comments unless a maintainer explicitly asks for them.
- Do not store secrets in browser storage beyond the existing short-lived dashboard token behavior.
- Do not add plugin behavior that executes manifest content.
- Treat YAML, TOML, JSON, YARA, and `.sentinel` files as untrusted input.
- Validate filesystem paths against an explicit workspace root before reading files from tools or APIs.

## Backend Priorities

- Shared `Finding` and `ScanResult` contracts.
- Safe plugin and rule pack registry.
- Secure MCP stdio server with allowlisted read-only tools.
- Red-team security pack and strategy registry.
- Provider adapter contract for HTTP, MCP, local models, browser workflows, and custom scripts.
- Export snapshots for JSON, SARIF, Markdown, HTML, CSV, and JUnit.

## Frontend Priorities

- White workbench UI.
- Dense operator surfaces over marketing layout.
- Feature controls backed by APIs instead of hard-coded demo constants where possible.
- Authentication screens must be functional, clear, and secure by default.
- Avoid product copy that explains implementation details to end users.

## Verification

- Run focused Python tests for backend changes.
- Run `npm run lint` and `npm run build` for frontend changes.
- Use the browser to verify dashboard and auth flows after significant UI edits.
