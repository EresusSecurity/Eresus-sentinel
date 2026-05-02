# CLI Reference

Sentinel CLI commands follow the contract in [CLI_CONTRACT.md](CLI_CONTRACT.md):
`0` means clean, `1` means findings or a failed gate, and `2` means usage or
internal error. Machine output should use `-f json` or `-f sarif`.

## Core Commands

| Command | Purpose | Machine Output |
|---|---|---|
| `sentinel scan PATH` | Multi-domain local scan | JSON, SARIF, CSV, Markdown, HTML, JUnit |
| `sentinel artifact PATH` | Model artifact scan | JSON, SARIF |
| `sentinel firewall TEXT` | Prompt/response firewall check | JSON, SARIF |
| `sentinel sast PATH` | Static code scan | JSON, SARIF |
| `sentinel secrets-scan PATH` | Secret and entropy scan | JSON, SARIF |
| `sentinel supply-chain PATH` | Dependency and provenance audit | JSON, SARIF |
| `sentinel aibom PATH` | AI-BOM inventory | JSON |
| `sentinel agent PATH` | Agent, skill, MCP, and A2A checks | JSON, SARIF |
| `sentinel redteam --target TARGET` | Red team probes | JSON, SARIF |
| `sentinel evaluate CONFIG` | Config-driven eval assertions | JSON |
| `sentinel diff [TARGET]` | Git diff and PR patch scan | JSON, SARIF |
| `sentinel notebook PATH` | Notebook security scan | JSON, SARIF |

## Operational Commands

| Command | Purpose |
|---|---|
| `sentinel doctor --json` | Environment and scanner health |
| `sentinel debug --json` | Runtime diagnostics |
| `sentinel cache stats` | Scan cache status |
| `sentinel rules list -f json` | Loaded rule inventory |
| `sentinel rules test RULE_ID -f json` | Rule smoke test |
| `sentinel finding explain RULE_ID -f json` | Rule/finding explanation |
| `sentinel scanners` | Scanner registry |
| `sentinel dashboard` | Local Web UI |
| `sentinel serve` | API server |
| `sentinel proxy` | MCP proxy |

## Smoke Examples

```bash
sentinel doctor --json | python -m json.tool
sentinel rules list -f json | python -m json.tool
sentinel scan ./project --profile fast -f json
sentinel artifact ./models --list-scanners
git diff main...HEAD | sentinel diff - -f sarif > sentinel.sarif
```
