# Eresus Sentinel — Documentation

**Docs:** [Overview](overview.md) · [Quick Start](quickstart.md) · [How It Works](how-it-works.md) · [Detection](detection.md) · [Deception Engine](deception.md) · [Deployment](deployment.md) · [Configuration](configuration.md) · [API Reference](api.md) · [Threat Hunting](threat-hunting.md) · [Format Support](format-support.md)

---

## What is Eresus Sentinel?

Eresus Sentinel is a **deterministic-first security platform for AI/LLM ecosystems**. It provides ten security domains:

| Domain | Description |
|--------|-------------|
| **Artifact Scanning** | Security scanning across 30+ model formats: Pickle, HDF5, GGUF, SafeTensors, ONNX, Keras, TFLite, CoreML, Skops, NeMo and more |
| **Input Firewall** | Prompt injection, jailbreak, and malicious input detection |
| **Output Firewall** | Sensitive data leakage and harmful output filtering |
| **Deception Engine** | Mislead attackers with fabricated-but-plausible responses |
| **SAST** | Static application security testing |
| **Red Team** | Automated attack simulation |
| **MCP Proxy** | Model Context Protocol security scanning |
| **Supply Chain** | Model provenance verification and embedding anomaly detection |
| **Notebook** | Jupyter notebook security analysis |
| **Diff Scanning** | Code change security analysis |

## Core Philosophy

1. **Deterministic-First** — All core detection is regex/AST/opcode-based. AI enrichment is optional and never gates security decisions.
2. **YAML-Driven Rules** — All patterns externalized to `rules/*.yaml`. No hardcoded regex in Python scanners.
3. **Plugin Auto-Discovery** — Drop a scanner class in the right module; `_plugins.py` discovers it automatically.
4. **Universal Finding DTO** — Every domain returns `Finding` objects with consistent severity, confidence, and evidence fields.

## All Documentation

| Page | Contents |
|------|----------|
| [Overview](overview.md) | Platform architecture and core philosophy |
| [Quick Start](quickstart.md) | Install, configure, and run your first scan |
| [How It Works](how-it-works.md) | Request pipeline, decision model, worked examples |
| [Detection](detection.md) | 9 threat categories, jailbreak patterns, custom rules |
| [Deception Engine](deception.md) | Templates, generative mode, output scanner |
| [Deployment](deployment.md) | Production setup: nginx, Redis, TLS, Docker |
| [Configuration](configuration.md) | Full environment variable reference |
| [API Reference](api.md) | Endpoints, request/response format |
| [Threat Hunting](threat-hunting.md) | Deception log, attribution, session inspection |
| [Format Support](format-support.md) | Supported model formats and comparison |
