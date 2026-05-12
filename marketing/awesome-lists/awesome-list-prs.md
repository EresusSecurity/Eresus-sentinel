# Awesome List PR Submissions — Eresus Sentinel
# Each section = one PR to one repo
# PR title and body are ready to paste

---

## 1. awesome-mlsec
**Repo:** https://github.com/dhavalkapil/awesome-mlsec (or current maintained fork)

**PR Title:** Add Eresus Sentinel — static ML model artifact scanner

**Line to add in README (under Model Security / Scanning Tools):**
```
- [Eresus Sentinel](https://github.com/EresusSecurity/Eresus-sentinel) - Deterministic static scanner for 24 ML model formats (Pickle, PyTorch, GGUF, ONNX, SafeTensors, Keras, TFLite, CNTK, JAX, RKNN and more). No model loading required. SARIF output.
```

**PR Body:**
```
## What is this?

Eresus Sentinel is an open-source static analyzer for ML model artifact files.
It scans 24 model formats (Pickle, PyTorch, GGUF, ONNX, SafeTensors, Keras,
TFLite, TorchScript, LlamaFile, CNTK, JAX, RKNN, XGBoost, LightGBM, CoreML,
PaddlePaddle, MXNet, and more) for malicious payloads without loading them.

## Why it belongs here

- Addresses the ML model supply chain attack surface
- Deterministic analysis (no ML model to detect ML threats)
- Active project, MIT-licensed Python package on PyPI
- Maps findings to OWASP LLM Top 10 and MITRE ATLAS

pip install eresus-sentinel
```

---

## 2. awesome-llm-security
**Repo:** https://github.com/corca-ai/awesome-llm-security

**PR Title:** Add Eresus Sentinel — LLM firewall + model artifact scanner + MCP proxy

**Lines to add (3 separate sections):**

Under **Input/Output Guardrails:**
```
- [Eresus Sentinel Firewall](https://github.com/EresusSecurity/Eresus-sentinel) - 22 input + 24 output guardrails. Prompt injection, PII leakage, encoding attacks (Unicode bidi, homoglyph, zero-width), invisible text, toxicity. Deterministic, no ML required.
```

Under **Model Supply Chain / Artifact Security:**
```
- [Eresus Sentinel Artifact Scanner](https://github.com/EresusSecurity/Eresus-sentinel) - Static analysis for 24 ML model formats. Detects malicious Pickle opcodes, GGUF metadata injection, Keras Lambda layer exploits. No model loading.
```

Under **Agent Security:**
```
- [Eresus Sentinel MCP Proxy](https://github.com/EresusSecurity/Eresus-sentinel) - Real-time intercepting proxy for Model Context Protocol traffic. OPA policy enforcement. Blocks tool poisoning and permission escalation in agent workflows.
```

**PR Body:**
```
Adding Eresus Sentinel across three relevant sections:

1. Firewall: deterministic prompt injection + PII + encoding attack detection
2. Artifact scanner: first open-source tool covering 24 ML model formats statically
3. MCP proxy: first open tool for real-time MCP agent traffic inspection + OPA enforcement

Active project, pip install eresus-sentinel, Apache-2.0 / ESL-1.1 licensed.
```

---

## 3. awesome-mcp (Model Context Protocol)
**Repo:** https://github.com/punkpeye/awesome-mcp-servers (or equivalent)

**PR Title:** Add Eresus Sentinel — MCP security proxy with OPA policy enforcement

**Line to add (under Security / Monitoring):**
```
- [Eresus Sentinel MCP Proxy](https://github.com/EresusSecurity/Eresus-sentinel) - Intercepting security proxy for MCP traffic. Inspects all JSON-RPC 2.0 messages, enforces OPA (Rego) policies, blocks tool poisoning and permission escalation. Real-time. Python.
```

**PR Body:**
```
Eresus Sentinel includes an MCP intercepting proxy that sits between an AI agent
and its MCP servers. It inspects all JSON-RPC 2.0 traffic in real time, enforces
Rego policies via OPA, and blocks suspicious patterns before they reach the model.

This is the first open-source tool specifically built for MCP security monitoring.
Relevant as MCP adoption grows and security requirements follow.
```

---

## 4. awesome-devsecops
**Repo:** https://github.com/TaptuIT/awesome-devsecops

**PR Title:** Add Eresus Sentinel — AI/ML SAST + secrets scanner with SARIF output

**Line to add (under SAST / Static Analysis Tools):**
```
- [Eresus Sentinel](https://github.com/EresusSecurity/Eresus-sentinel) - SAST for AI/ML codebases. 120+ secret patterns, entropy analysis, git history scanning, Jupyter notebook inspection. SARIF v2.1.0 output for GitHub Security tab. Also scans ML model artifacts.
```

**PR Body:**
```
Eresus Sentinel adds SAST coverage specifically for AI/ML application code:

- 120+ hardcoded secret patterns (API keys, tokens, credentials)
- Shannon entropy analysis for high-entropy string detection
- Full git history scanning (finds secrets even after `git rm`)
- Jupyter notebook cell-by-cell inspection
- YAML-driven rule format
- SARIF v2.1.0 output → GitHub Security tab integration

pip install eresus-sentinel
sentinel sast ./src --sarif > results.sarif
```

---

## 5. awesome-ai-tools
**Repo:** https://github.com/mahseema/awesome-ai-tools

**PR Title:** Add Eresus Sentinel — AI security toolkit (model scanning, firewall, agent security)

**Line to add (under Security / Developer Tools):**
```
- [Eresus Sentinel](https://github.com/EresusSecurity/Eresus-sentinel) - Open-source AI security toolkit. Scans 24 ML model formats, runs LLM prompt/output firewall, intercepts MCP agent traffic, and performs SAST on AI application code. pip install eresus-sentinel.
```

**PR Body:**
```
Adding Eresus Sentinel as a comprehensive AI security toolkit.

It covers the full AI application stack:
- Model artifacts (24 formats, static analysis, no loading)
- Prompt firewall (22 input + 24 output guardrails)
- Agent security (MCP proxy + OPA enforcement)
- SAST (secrets, taint analysis, complexity)
- Red team (48 attack probes, OWASP LLM Top 10)

Open source, Python, `pip install eresus-sentinel`.
```
