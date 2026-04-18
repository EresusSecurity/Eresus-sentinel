# Eresus Sentinel — Architecture

## Overview

Eresus Sentinel is a **deterministic-first**, **Python-native** security engine for AI/LLM ecosystems. It operates as a CLI tool with optional API/daemon mode, designed for offline-first scanning with pluggable AI assistance.

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

## Design Principles

### 1. Deterministic-First
All scanning is regex/AST/opcode/schema-based. No AI is required to produce findings. AI is an optional enrichment layer.

### 2. YAML-Driven Rules
All detection patterns live in `rules/*.yaml`. Zero hardcoded regex in Python code. This enables:
- Easy pattern updates without code changes
- Community contributions via YAML PRs
- Environment-specific rule overrides

### 3. Pure Python Architecture
- Built on modern Python 3.10+
- Heavily utilizes asynchronous processing (`asyncio`) for network-bound tasks
- CLI interface powered by `click` and `rich`
- Robust plugin discovery system for scanners, redteam generators, and reporting backends

### 4. Ten Security Domains

| Domain | Module | What it scans |
|--------|--------|---------------|
| **Artifact** | `artifact/` | Pickle, Torch, Keras, ONNX, GGUF, Safetensors, TFLite, Archives |
| **Input Firewall** | `firewall/input/` | Prompt injection, secrets, invisible text, encoding attacks |
| **Output Firewall** | `firewall/output/` | URLs, PII, format enforcement |
| **SAST** | `sast/` | LLM application source code (unsafe eval, pickle, API keys, entropy) |
| **Agent/MCP** | `agent/` | MCP tool schemas, trust boundaries, permissions |
| **Supply Chain** | `supply_chain/` | Model provenance, SHA256 integrity, dependencies |
| **Red Team** | `redteam/` | Probe-based attack simulation (opt-in only) |
| **MCP Proxy** | `mcp_proxy.py` | Real-time interception and OPA policy enforcement of MCP protocols |
| **Notebook** | `notebook_scanner/` | Jupyter security scanning (.ipynb) |
| **Diff Scanner** | `diff_scanner/` | Git diff / PR anti-pattern detection |

## Directory Structure

```
eresus-sentinel/
├── pyproject.toml                   # Python package configuration
├── sentinel.toml                   # Engine configuration
│
├── python/sentinel/
│   ├── finding.py                   # Finding dataclass (7 factories)
│   ├── rules.py                     # Central YAML loader
│   ├── cli_dispatch.py              # Subcommand dispatching
│   ├── cli.py                       # Main CLI entrypoint
│   ├── sdk.py                       # Python SDK interface
│   ├── server.py                    # FastAPI REST endpoint
│   ├── mcp_proxy.py                 # MCP transparent proxy
│   ├── opa_engine.py                # OPA integration layer
│   ├── telemetry.py                 # OpenTelemetry integration
│   │
│   ├── artifact/                    # 24 model artifact scanners
│   ├── firewall/
│   │   ├── base.py                  # Base scanner interfaces
│   │   ├── input/                   # 22 input scanners (injection, secrets, etc.)
│   │   └── output/                  # 24 output scanners (PII, URL, format, etc.)
│   ├── redteam/                     # 48 probes, 13 detectors, playbook engine
│   ├── notebook_scanner/            # Jupyter notebook security
│   ├── sast/                        # Source code analysis & secrets
│   ├── diff_scanner/                # PR and diff analysis
│   ├── agent/                       # Agent security (MCP schemas, Threat Taxonomy)
│   └── supply_chain/                # ML dependency & provenance checks
│
├── rules/                           # YAML rule database
│   ├── secret_patterns.yaml         # 120+ credential patterns
│   ├── injection_patterns.yaml      # 100+ injection patterns
│   ├── sast_rules.yaml              # 30+ SAST rules
│   ├── artifact_blocklist.yaml      # 200+ dangerous globals
│   ├── mcp_rules.yaml               # 13 capability categories
│   ├── supply_chain_rules.yaml      # 35+ extensions, 16 vulns
│   ├── scanner_rules.yaml           # TF/TS/TFLite/LlamaFile patterns
│   └── diff_patterns.yaml           # 20 ML diff anti-patterns
│
├── payloads/                        # Red team payloads
│   ├── agentic_probes.yaml          # Agent exploitation payloads
│   └── tool_abuse.yaml              # Tool abuse payloads
│
├── ci/                              # CI/CD integration templates
├── tests/                           # Pytest suite
└── docs/
    ├── ARCHITECTURE.md              # This file
    ├── RULES.md                     # Rule format reference
    └── QUICKSTART.md                # Getting started
```

## Data Flow

```
Input (file/dir/prompt/config)
       │
       ▼
   ┌──────────┐
   │   CLI    │  (Parse args, load config sentinel.toml)
   └────┬─────┘
        │
        ▼
   ┌──────────┐
   │ Pipeline │  (Dispatch to relevant domains via SDK)
   └────┬─────┘
        │
   ┌────┼────────────────┐
   │    │    ┌──────────┐ │
   │    ├───>│ Artifact │ │
   │    │    └──────────┘ │
   │    │    ┌──────────┐ │  Python Modules
   │    ├───>│ Firewall │ │  (Sync/Async processing)
   │    │    └──────────┘ │
   │    │    ┌──────────┐ │
   │    ├───>│   SAST   │ │
   │    │    └──────────┘ │
   │    │    ┌──────────┐ │
   │    ├───>│  Agent   │ │
   │    │    └──────────┘ │
   │    │    ┌──────────┐ │
   │    └───>│ Supply   │ │
   │         │ Chain    │ │
   │         └──────────┘ │
   └─────────────┬────────┘
                 │
                 ▼
          ┌────────────┐
          │  Findings  │  (Standardized internal DTO)
          └──────┬─────┘
                 │
                 ▼
          ┌────────────┐
          │  Reporter  │  (Rust: JSON/SARIF/Table)
          └────────────┘
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
backend = "openai"  # "anthropic", "local", "generic_rest"
model = "gpt-4o"

[reporting]
format = "json"  # "sarif", "table", "html"
include_evidence = true
```
