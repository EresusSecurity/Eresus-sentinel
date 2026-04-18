<p align="center">
  <img src="https://img.shields.io/badge/version-0.1.0-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/license-Proprietary-red?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/status-Alpha-orange?style=flat-square" alt="Status">
</p>

# Eresus Sentinel

**Production-grade security platform for AI/LLM ecosystems.**

Sentinel provides deterministic, YAML-driven security scanning across the entire AI stack — from model artifacts and prompt firewalls to supply chain auditing and red team automation. Zero AI required to produce findings; AI is an optional enrichment layer.

---

## Security Domains

| Domain | Module | Coverage |
|--------|--------|----------|
| 🔬 **Artifact** | `artifact/` | 24 scanners — Pickle, Torch, Keras, ONNX, GGUF, Safetensors, TFLite, Archives |
| 🛡️ **Input Firewall** | `firewall/input/` | 22 guardrails — Injection, secrets, PII, encoding attacks, invisible text, toxicity |
| 🔒 **Output Firewall** | `firewall/output/` | 24 guardrails — Bias, compliance, copyright, watermark, format enforcement |
| 🔍 **SAST** | `sast/` | Static analysis + 120+ secret patterns + entropy + git history scanning |
| 🤖 **Agent/MCP** | `agent/` | Trust maps, permissions, MCP schema validation, threat taxonomy |
| 📦 **Supply Chain** | `supply_chain/` | Dependency scanning, typosquatting, OSV.dev, provenance |
| ⚔️ **Red Team** | `redteam/` | 48 probes + 13 detectors + 14 generators + YAML playbook engine |
| 🔗 **MCP Proxy** | `mcp_proxy.py` | Live intercepting proxy (stdio/HTTP) with OPA policy enforcement |
| 📓 **Notebook** | `notebook_scanner/` | Jupyter security scanning (14 plugins) |
| 📝 **Diff** | `diff_scanner/` | Git diff/PR ML anti-pattern detection |

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Verify installation
sentinel doctor

# Scan a project
sentinel scan ./my-project/

# Firewall a prompt
sentinel firewall "user input text"

# Scan model artifacts
sentinel artifact ./models/

# Red team assessment
sentinel redteam --target openai/gpt-4o

# Interactive shell
sentinel shell
```

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    Eresus Sentinel CLI                        │
│               (Python · Click + Rich terminal)               │
├──────────┬──────────┬──────────┬──────────┬──────────────────┤
│ Artifact │ Firewall │   SAST   │ Agent/   │  Supply Chain    │
│ Scanner  │ (I/O)    │ Analyzer │ MCP      │  Auditor         │
├──────────┴──────────┴──────────┴──────────┴──────────────────┤
│                    YAML Rule Engine                           │
│              (rules/ — zero hardcoded regex)                  │
├──────────────────────────────────────────────────────────────┤
│               Finding Universal Data Model                    │
│          (7 domain factories + dedup fingerprints)            │
├──────────────────────────────────────────────────────────────┤
│  MCP Proxy  │  Playbook Engine  │  OPA Policy  │  Telemetry  │
├──────────────────────────────────────────────────────────────┤
│           AI-Assisted Layer (optional, pluggable)             │
│        OpenAI / Anthropic / Local GGUF / Generic REST        │
└──────────────────────────────────────────────────────────────┘
```

### Key Design Principles

- **Deterministic-first** — All scanning is regex/AST/opcode-based. No AI dependency for findings.
- **YAML-driven rules** — All patterns in `rules/*.yaml`. Zero hardcoded regex in code.
- **Plugin auto-discovery** — Drop a scanner class, it's automatically registered.
- **Lazy loading** — Modules load on-demand for fast CLI startup.
- **SARIF v2.1.0 output** — Native GitHub Security tab integration.

## CLI Commands

| Command | Description |
|---------|-------------|
| `sentinel scan <path>` | Full security scan across all domains |
| `sentinel firewall <text>` | Input/output firewall scan |
| `sentinel artifact <path>` | Model artifact scanning |
| `sentinel sast <path>` | Static analysis (secrets, code patterns) |
| `sentinel agent <path>` | Agent/MCP security validation |
| `sentinel supply-chain <path>` | Dependency + provenance audit |
| `sentinel redteam --target <model>` | Automated red team assessment |
| `sentinel hf-guard <repo>` | Pre-download HuggingFace security check |
| `sentinel evaluate` | Scanner effectiveness benchmarks |
| `sentinel benchmark` | Latency benchmarks (p50/p95/p99) |
| `sentinel doctor` | System health check |
| `sentinel scanners` | List all registered scanners |
| `sentinel shell` | Interactive REPL |
| `sentinel fuzz <action>` | Pickle fuzzer (generate/mutate/validate) |

## Python SDK

```python
from sentinel import Sentinel

s = Sentinel()

# Scan input
result = s.scan_input("user prompt here")
print(result.findings)

# Scan output
result = s.scan_output("prompt", "llm response")

# Full conversation scan
result = s.scan_conversation("prompt", "response")

# Export to SARIF
s.export_sarif(result.findings, "report.sarif")
```

## REST API

```bash
# Start API server
sentinel serve --host 0.0.0.0 --port 8000

# Scan endpoint
curl -X POST http://localhost:8000/v1/scan/input \
  -H "Content-Type: application/json" \
  -d '{"text": "user prompt"}'
```

## MCP Proxy

Intercept and inspect all MCP protocol traffic in real-time:

```bash
# Stdio mode — wrap any MCP server
sentinel proxy --mode stdio -- npx my-mcp-server

# HTTP mode — reverse proxy
sentinel proxy --mode http --upstream http://localhost:3000 --port 8080
```

## Configuration

Engine is configured via `sentinel.toml`:

```toml
[general]
rules_dir = "rules"
min_severity = "LOW"
workers = 4

[scanners]
artifact = true
input_firewall = true
output_firewall = true
sast = true
agent_mcp = true
supply_chain = true
red_team = false  # Opt-in only

[ai]
enabled = false
backend = "openai"
model = "gpt-4o"
```

## Docker

```bash
# Standard
docker build -t eresus-sentinel .
docker run -v ./models:/data eresus-sentinel scan /data

# GPU-accelerated (CUDA)
docker build -f Dockerfile.cuda -t eresus-sentinel:cuda .

# Docker Compose (API + worker)
docker compose up
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Sentinel Security Scan
  run: |
    pip install eresus-sentinel
    sentinel scan ./src --format sarif --output sentinel.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: sentinel.sarif
```

## Documentation

| Document | Description |
|----------|-------------|
| [Quick Start](docs/QUICKSTART.md) | Getting started guide |
| [Architecture](docs/ARCHITECTURE.md) | System design and data flow |
| [Rules Reference](docs/RULES.md) | YAML rule format specification |
| [Contributing](CONTRIBUTING.md) | Development setup and PR process |
| [Security Policy](SECURITY.md) | Vulnerability reporting |
| [Changelog](CHANGELOG.md) | Release history |

## Requirements

- Python 3.10+
- Dependencies: `pyyaml`, `rich`, `click`
- Optional: `fastapi`, `uvicorn`, `torch`, `huggingface_hub`, `aiohttp`

## License

Proprietary — © 2024-2026 Eresus Security. See [LICENSE](LICENSE).

---

<p align="center">
  <strong>Eresus Security</strong> · <a href="https://eresussec.com">eresussec.com</a>
</p>
