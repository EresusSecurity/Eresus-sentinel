<p align="center">
  <img src="https://img.shields.io/badge/version-0.1.0-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/license-Proprietary-red?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/status-Alpha-orange?style=flat-square" alt="Status">
</p>

# Eresus Sentinel

**Alpha-stage, deterministic-first AI security toolkit for local audits, MCP/agent checks, model artifact scanning, and prompt firewall testing.**

Sentinel provides deterministic, YAML-driven security scanning across the AI stack — from model artifacts and prompt firewalls to supply chain auditing and red team automation. Zero AI is required to produce findings; AI/judge adapters are optional enrichment layers.

<p align="center">
  <img src="demo.gif" alt="Eresus Sentinel Demo" width="700">
</p>

---

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
| 🚦 **Runtime Gateway** | `runtime_gateway.py` | Provider-neutral LLM gateway contract with monitor/enforce modes |
| 📓 **Notebook** | `notebook_scanner/` | Jupyter security scanning (14 plugins) |
| 📝 **Diff** | `diff_scanner/` | Git diff/PR ML anti-pattern detection |

## Domain Maturity

| Domain | Maturity |
|--------|----------|
| Pickle/artifact no-load scanning | Beta |
| Prompt firewall deterministic checks | Beta |
| SAST/secrets/notebook/diff | Beta |
| MCP manifest/live scanning | Beta |
| MCP proxy runtime enforcement | Experimental |
| Dashboard/API | Experimental |
| HF/supply-chain live integrations | Experimental |
| Runtime gateway provider adapters | Experimental |
| AI/judge enrichment | Optional experimental |

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Verify installation
sentinel doctor
sentinel doctor --json

# Preview the scanner plan, then scan a project
sentinel scan ./my-project --plan --profile fast
sentinel scan ./my-project/

# Firewall a prompt
sentinel firewall "user input text"

# Scan model artifacts
sentinel artifact ./models/

# Red team assessment
sentinel redteam --target openai/gpt-4o

# Config-driven eval
sentinel evaluate eval.yaml

# Live/manifest MCP scan
sentinel mcp scan ./mcp-manifest.json

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
│  MCP Proxy  │  Eval Runner  │  Runtime Gateway  │ Telemetry │
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

The most common commands are:

```bash
sentinel scan ./project --profile fast -f json
sentinel artifact ./models -f sarif
sentinel firewall "user input text" -f json
sentinel mcp scan ./mcp-manifest.json
git diff main...HEAD | sentinel diff - -f sarif
```

See [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md) for the full command table
and [docs/CLI_CONTRACT.md](docs/CLI_CONTRACT.md) for exit codes and output
shape.

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

## Config-Driven Eval

```yaml
# eval.yaml
providers:
  - id: local-echo
    name: echo
prompts:
  - id: greeting
    prompt: "hello {{name}}"
tests:
  - id: alice
    vars: { name: Alice }
    assertions:
      - type: contains
        expected: Alice
```

```bash
sentinel evaluate eval.yaml --fail-on-threshold 0.95
sentinel evaluate eval.yaml -f json -o eval-report.json
```

## MCP Live Scanner

Scan offline manifests or live MCP JSON-RPC endpoints:

```bash
sentinel mcp scan ./mcp-manifest.json
sentinel mcp scan --url http://localhost:3000/mcp
sentinel mcp scan --stdio-command npx my-mcp-server
```

The scanner discovers tools, prompts, resources, server instructions, auth metadata, and readiness signals.

## Runtime Gateway

```python
from sentinel.runtime_gateway import SentinelGateway, EchoProviderAdapter

gateway = SentinelGateway(provider=EchoProviderAdapter())
decision = gateway.complete("user prompt")
if decision.blocked:
    print(decision.response.text)
```

## REST API

```bash
# Start Web UI dashboard
export SENTINEL_PASSWORD=change-me
sentinel dashboard
# Open http://127.0.0.1:8080

# If running from source and the UI is missing:
# Node.js 20.19+ is required by Vite/React Router.
cd frontend && npm install && npm run build

# Start API server
sentinel serve --host 0.0.0.0 --port 8080

# Scan endpoint
curl -X POST http://localhost:8080/scan/input \
  -H "Content-Type: application/json" \
  -d '{"text": "user prompt"}'
```

## MCP Proxy

Intercept and inspect all MCP protocol traffic in real-time:

```bash
# Stdio mode — wrap any MCP server
sentinel proxy --transport stdio --mode enforce --server-cmd npx my-mcp-server

# HTTP mode — reverse proxy
sentinel proxy --transport http --mode enforce --upstream http://localhost:3000 --port 8080
```

## Configuration

Engine is configured via `sentinel.toml`:

```toml
[engine]
mode = "deterministic"    # "ai-assisted" | "full"
min_severity = "MEDIUM"
action_policy = "balanced" # "advisory" | "strict"

[scanners.artifact]
enabled = true

[scanners.firewall.input]
enabled = true

[scanners.firewall.output]
enabled = true

[scanners.sast]
enabled = true

[scanners.redteam]
enabled = false  # Opt-in only

[ai]
enabled = false
backend = "ollama"
model = "llama3.2"
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

- [Quick Start](docs/QUICKSTART.md)
- [Turkish Quick Start](docs/TR_QUICKSTART.md)
- [CLI Reference](docs/CLI_REFERENCE.md)
- [Rule Authoring](docs/RULE_AUTHORING.md)
- [Scanner Authoring](docs/SCANNER_AUTHORING.md)
- [MCP Proxy Deployment](docs/MCP_PROXY_DEPLOYMENT.md)
- [CI and Pre-Commit](docs/CI_PRECOMMIT.md)
- [False Positive Handling](docs/FALSE_POSITIVES.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [FAQ](docs/FAQ.md)
- [Community Notes](docs/COMMUNITY.md)
- [Good First Issues](docs/GOOD_FIRST_ISSUES.md)

## Authentication & Security

For production deployments:

```bash
# Enable API authentication
export SENTINEL_AUTH_TYPE=bearer
export SENTINEL_AUTH_TOKEN=your-secret-token

# Restrict CORS
export SENTINEL_CORS_ORIGINS=https://yourdomain.com

# Enable audit logging
export SENTINEL_AUDIT_LOG=/var/log/sentinel/audit.jsonl

# Rate limiting (configured via SENTINEL_RATE_LIMIT)
export SENTINEL_RATE_LIMIT=100/minute
```

See [Security Policy](SECURITY.md) for full hardening guide.

## Requirements

- Python 3.10+
- Core dependencies: `pyyaml`, `rich`
- API server: `pip install eresus-sentinel[api]` (adds `fastapi`, `uvicorn`)
- Web dashboard: `pip install eresus-sentinel[web]`
- ML scanning: `pip install eresus-sentinel[ml]` (adds `torch`, `transformers`)
- Rust pickle backend: `cd rust/sentinel-pickle && maturin develop --release`
- All extras: `pip install eresus-sentinel[all]`

## Alpha Disclaimer

> **This is alpha software.** APIs, CLI flags, finding schemas, and rule IDs may change between releases without deprecation notice. Do not depend on output stability in production CI pipelines yet.

## License

Proprietary — © 2026 Eresus Security. See [LICENSE](LICENSE).

---

<p align="center">
  <strong>Eresus Security</strong> · <a href="https://eresussec.com">eresussec.com</a>
</p>
