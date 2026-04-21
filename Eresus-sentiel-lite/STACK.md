# Eresus Sentinel — Tech Stack

## Core Architecture

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **CLI & Orchestration** | Python 3.10+ (rich, click) | CLI interface, scan orchestration, SARIF/HTML/Markdown export |
| **Security Modules** | Python 3.10+ | Model analysis, artifact inspection, firewall, SAST, red teaming |
| **API Server** | FastAPI + Uvicorn | REST API with k8s probes, batch scanning |
| **Configuration** | TOML | Engine config (`sentinel.toml`) |
| **Rules & Patterns** | YAML | All detection patterns externalized — no hardcoded regex in code |

## Python Dependencies

### Core (Required)
| Package | Purpose |
|---------|---------|
| `pyyaml` | YAML rule file loading |
| `toml` | Configuration parsing |

### Artifact Scanning
| Package | Purpose |
|---------|---------|
| `safetensors` | Safetensors header validation |
| `onnx` | ONNX model graph analysis (optional fallback available) |

### Firewall
| Package | Purpose |
|---------|---------|
| `transformers` | ML-based prompt injection (AI-assisted mode only) |
| `torch` | ML model runtime (AI-assisted mode only) |
| `presidio-analyzer` | NER-based PII detection (optional) |
| `detect-secrets` | Secret detection backend (optional) |
| `jsonschema` | Output format validation |

### Red Teaming
| Package | Purpose |
|---------|---------|
| `requests` / `httpx` | LLM target adapters (Ollama, OpenAI) |

### HuggingFace
| Package | Purpose |
|---------|---------|
| `huggingface_hub` | Remote repo scanning API |

## API & Observability

| Package | Purpose |
|---------|---------|
| `fastapi` | REST API framework |
| `uvicorn` | ASGI server |
| `pydantic` | Data validation |
| `slowapi` | Rate limiting |
| `structlog` | Structured logging |
| `opentelemetry-*` | Distributed tracing & metrics |

## Architecture Principles

### 1. Deterministic-First
- Core detection is pure regex, AST, opcode analysis, rule engines, schema validation
- No AI required for any core finding
- All patterns externalized to YAML in `rules/` directory

### 2. AI as Optional Enrichment
When enabled (`[ai] enabled = true`), AI adds:
- Semantic prompt injection analysis
- Behavioral backdoor comparison
- Red team response interpretation
- False positive reduction
- Finding enrichment and prioritization

### 3. AI Backend is Pluggable
Supported backends:
- **Ollama** — Local models (default, air-gapped friendly)
- **OpenAI** — GPT-4o, GPT-4 compatible endpoints
- **Anthropic** — Claude models
- **Generic REST** — Any OpenAI-compatible API

### 4. Offline / No-AI Mode
- `mode = "deterministic"` — zero network calls, zero AI
- Perfect for: air-gapped environments, CI pipelines, cost-sensitive scans

## File Format Coverage

| Format | Scanner | Attack Vectors |
|--------|---------|----------------|
| `.pkl` / `.pickle` | PickleScanner | `__reduce__` RCE, dangerous GLOBAL opcodes |
| `.pt` / `.pth` / `.bin` | TorchScanner | Embedded pickle in ZIP, magic number abuse |
| `.safetensors` | SafetensorsValidator | Header DoS, metadata injection |
| `.gguf` | GGUFAnalyzer | Metadata prompt injection, n_kv overflow |
| `.keras` | KerasScanner | Lambda layer bytecode, CVE-2025-1550, config injection |
| `.h5` / `.hdf5` | KerasScanner | Legacy HDF5 Lambda exploits |
| `.onnx` | ONNXScanner | Custom ops, external data SSRF, control flow |
| `.nemo` / `.mar` | ArchiveSlipDetector | Path traversal, symlink escape |
| `.tar.gz` / `.zip` | ArchiveSlipDetector | ZipSlip, TarSlip, decompression bombs |
| HF Repos | HuggingFaceScanner | auto_map, trust_remote_code, missing safetensors |

## Rule Files

| File | Contents |
|------|----------|
| `rules/artifact_blocklist.yaml` | 200+ dangerous pickle globals + allowlist |
| `rules/secret_patterns.yaml` | 120+ credential/token patterns |
| `rules/injection_patterns.yaml` | 100+ prompt injection patterns (8 categories) |
| `rules/sast_rules.yaml` | 30+ SAST rules for AI/ML code |

## Security Domains

1. **Artifact Scanning** — Model file integrity and backdoor detection
2. **Input Firewall** — Prompt injection, invisible text, encoding attacks, secrets
3. **Output Firewall** — PII leakage, malicious URLs, format enforcement
4. **SAST** — Static analysis for LLM application source code
5. **Red Team** — Automated adversarial testing (probe → generate → detect)
6. **Supply Chain** — HuggingFace repo audit, SHA verification
7. **Agent/MCP Security** — Tool schema validation, trust boundaries, behavioral analysis, YARA scanning
