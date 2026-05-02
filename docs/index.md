# Eresus Sentinel

**Alpha-stage, deterministic-first AI security toolkit for local audits, MCP/agent checks, model artifact scanning, and prompt firewall testing.**

Sentinel provides deterministic, YAML-driven security scanning across the AI stack — from model artifacts and prompt firewalls to supply chain auditing and red team automation. AI/judge integrations are optional enrichment, not required for findings.

## Security Domains

| Domain | Module | Coverage |
|--------|--------|----------|
| 🔬 **Artifact** | `artifact/` | 24 scanners — Pickle, Torch, Keras, ONNX, GGUF, Safetensors, TFLite, Archives |
| 🛡️ **Input Firewall** | `firewall/input/` | 22 guardrails — Injection, secrets, PII, encoding attacks, invisible text, toxicity |
| 🔒 **Output Firewall** | `firewall/output/` | 24 guardrails — Bias, compliance, copyright, watermark, format enforcement |
| 🔍 **SAST** | `sast/` | Static analysis + 120+ secret patterns + entropy + git history scanning |
| 🤖 **Agent/MCP** | `agent/` | Trust maps, permissions, MCP schema validation, live MCP discovery |
| 📦 **Supply Chain** | `supply_chain/` | Dependency scanning, typosquatting, OSV.dev, provenance |
| ⚔️ **Red Team / Eval** | `redteam/` | 48 probes + 13 detectors + 14 generators + YAML playbook/eval engine |
| 🔗 **MCP Proxy** | `mcp_proxy.py` | Live intercepting proxy (stdio/HTTP) with OPA policy enforcement |
| 📓 **Notebook** | `notebook_scanner/` | Jupyter security scanning (14 plugins) |
| 📝 **Diff** | `diff_scanner/` | Git diff/PR ML anti-pattern detection |

## Quick Start

```bash
pip install -e ".[dev]"
sentinel doctor
sentinel scan ./my-project --plan --profile fast
sentinel scan ./my-project/
```

See the [Quick Start guide](QUICKSTART.md) for more details.

## Project Docs

- [CLI Contract](CLI_CONTRACT.md)
- [CLI Reference](CLI_REFERENCE.md)
- [Roadmap](ROADMAP.md)
- [Rule Authoring Guide](RULE_AUTHORING.md)
- [Scanner Authoring Guide](SCANNER_AUTHORING.md)
- [MCP Proxy Deployment](MCP_PROXY_DEPLOYMENT.md)
- [CI and Pre-Commit](CI_PRECOMMIT.md)
- [False Positive Handling](FALSE_POSITIVES.md)
- [Troubleshooting](TROUBLESHOOTING.md)
- [FAQ](FAQ.md)
- [Turkish Quick Start](TR_QUICKSTART.md)
