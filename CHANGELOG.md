# Changelog

All notable changes to Eresus Sentinel will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-04-16

### Initial Release

Eresus Sentinel — Production-grade AI/LLM Security Platform.

#### Artifact Scanning (28 scanners)
- Pickle deserialization RCE detection (`__reduce__`, dangerous globals, opcode analysis)
- PyTorch `.pt`/`.pth` embedded pickle + ZIP inspection
- SafeTensors header validation and metadata injection detection
- GGUF metadata prompt injection and n_kv overflow detection
- ONNX custom ops, external data SSRF, control flow analysis
- Keras Lambda layer bytecode, CVE-2025-1550, config injection
- TensorFlow SavedModel scanner
- TorchScript scanner
- TFLite FlatBuffer scanner
- NumPy `.npy`/`.npz` scanner
- XGBoost model scanner
- TorchMobile `.ptl` scanner
- LlamaFile scanner
- HuggingFace repo scanner (auto_map, trust_remote_code)
- Archive slip detector (ZIP/TAR path traversal, symlink, bombs)
- Integrity verification engine (SHA-256)

#### Input Firewall (17+ scanners)
- Prompt injection detection (heuristic + ML-based DeBERTa)
- Invisible text scanner (zero-width characters)
- Encoding attack scanner (base64, hex, unicode escapes)
- Secret detection (API keys, tokens, credentials)
- Layered defense orchestrator (4-layer Rebuff pattern)
- Canary injection system (4 strategies)
- Vector similarity scanner (TF-IDF)
- Toxicity scanner (6 categories)
- Language detection and enforcement
- Ban substrings / competitors
- Gibberish detection (entropy/stats)
- Token limit scanner (DoS defense)
- Code detection and blocking (6 languages)
- Regex pattern scanner
- Sentiment analysis (hostility detection)

#### Output Firewall (12+ scanners)
- Sensitive data / PII leakage detection
- Malicious URL scanner
- Format enforcement
- Bias detection (6 categories)
- No-refusal scanner (12 patterns)
- Relevance scorer (Jaccard + n-gram)
- Toxicity output scanner
- Gibberish output scanner
- URL reachability scanner (DNS)
- Reading time limiter
- JSON validation and injection detection
- Language consistency scanner

#### Red Team Engine
- 39 attack probes across 13 categories
- 12 advanced detectors
- 12 target adapters (generators)
- 5 attack strategies (crescendo, encoding chain, multi-turn, ASCII art, prefix injection)
- 6 automated graders (PII, toxicity, prompt leak, refusal, compliance, data exfil)
- Coding agent security fuzzer (8 attack categories)
- 7 injection plugins (SQL, Shell, SSRF, SSTI, XSS, Path Traversal, Special Tokens)
- Harmful content testing (16 categories, 60+ probes)
- Compliance mapper (NIST AI RMF + EU AI Act + ISO 42001)
- YAML-driven playbook engine with SARIF/HTML reports

#### Fuzzer Platform (5 backends)
- Pickle fuzzer: 45 opcodes, 17 mutators, 56 payloads, PVM simulation
- MCP fuzzer: JSON-RPC 2.0, 6 mutators, 24 payloads
- LLM fuzzer: 7 attack categories, 6 mutators, 24 payloads
- RAG fuzzer: 7 document attacks, 4 mutators, 15 payloads
- Artifact fuzzer: GGUF/ONNX/SafeTensors/PyTorch/ZIP
- Coverage-guided + differential + parallel fuzzing
- SARIF/JUnit/HTML reporting + Slack/Discord notifications

#### Agent/MCP Security (11 modules)
- MCP protocol validator
- Trust boundary mapping
- Permission analysis
- Taint tracker (7 labels, 9 sink types)
- Behavioral analyzer (11 categories)
- Skill/plugin security scanner
- YARA pattern analyzer (12 built-in rules)
- Threat taxonomy (OWASP LLM Top 10 + Agentic AI Top 10 + MITRE ATLAS)
- Outbound request validator
- Static analysis with dataflow tracking
- Multi-format report generator (JSON/SARIF/Markdown/HTML)

#### Supply Chain Security
- Model provenance verification
- Dependency auditing
- HuggingFace model scanning
- Adversarial embedding detection (5 detectors)
- Live dependency scanner (OSV.dev, typosquatting, confusion)

#### Enterprise Features
- MCP intercepting proxy (stdio/HTTP, behavioral + OPA inspection)
- Enterprise secrets scanner (120+ patterns, entropy, git history)
- Sandbox module (executor, honeypot, syscall filter)
- SAST analyzer with complexity analysis and taint tracking
- OPA policy engine integration
- OpenTelemetry instrumentation
- Secure PII redaction vault (Fernet encryption)
- LLM cost tracking and budget enforcement
- HuggingFace pre-download security guard

#### Infrastructure
- Python SDK (one-liner integration)
- FastAPI REST API (batch scan, k8s probes)
- LangChain/OpenAI/Generic LLM middleware
- CLI with 15+ subcommands
- YAML-driven policy engine with auto-discovery
- JSONL audit logger
- Prometheus metrics collector
- Plugin auto-discovery system
- Scanner evaluator framework (precision/recall/F1)
- Multi-stage Docker image (non-root, CUDA variant)
- Docker Compose stack with Prometheus
- CI/CD templates (GitHub Actions, GitLab CI, pre-commit)
- 13 YAML rule files with 500+ detection patterns
- 4 payload databases with 160+ attack payloads
