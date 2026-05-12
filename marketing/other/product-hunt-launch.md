# Product Hunt Launch Copy
# Product: Eresus Sentinel
# Category: Developer Tools / Security

---

## Tagline (60 chars max)

Scan your entire AI stack for threats — before production.

---

## Description (260 chars for PH tagline field)

Deterministic AI security toolkit: scan 24 model formats without loading them,
block prompt injection at the pipeline layer, intercept MCP agent traffic, and
run red team probes — all with SARIF output and zero AI dependency for findings.

---

## Full Description

Eresus Sentinel is a deterministic AI security toolkit that covers every
layer of the modern AI stack — from model files to agent traffic.

🔬 Model artifacts
Scan Pickle, PyTorch, GGUF, ONNX, SafeTensors and 19 more formats
without loading them. Catches RCE payloads, metadata injection, and
archive slip attacks before they touch your runtime.

🛡️ Prompt firewall
22 input guardrails + 24 output checks. Prompt injection, PII leakage,
encoding attacks, invisible text — caught deterministically, no ML needed.

🤖 MCP / Agent security
Intercept and inspect all MCP protocol traffic in real time. OPA policy
enforcement. Block tool poisoning and permission escalation at the proxy layer.

🔍 SAST + Secrets
120+ secret patterns, entropy analysis, git history scanning, and Jupyter
notebook cell inspection. SARIF output goes straight to GitHub Security tab.

⚔️ Red team
48 attack probes, 13 detectors, YAML playbooks. Maps findings to OWASP LLM
Top 10, EU AI Act, and MITRE ATLAS.

Zero AI required to produce findings.
Everything runs locally.
One pip install.

---

## First Comment (post immediately after launch)

Hey PH! Ibrahim here, founder of Eresus Security.

The problem we kept hitting: ML teams download model files, call torch.load(),
and ship. Nobody checks what's inside those files before loading them.
Pickle deserialization is arbitrary code execution. One malicious upload
to HuggingFace and you have RCE in every team that pulled that model.

We built Sentinel to gate the entire AI pipeline — model files, prompts,
agent traffic, secrets, supply chain — deterministically, without needing
an AI model to find AI threats.

The MCP proxy is probably the most novel part — it's the first open tool
that intercepts and enforces policy on agent-to-MCP-server traffic in real time.

Happy to answer questions about any of the detection approaches, the YAML
rule format, or the Rust pickle backend. What's your biggest AI security headache?

---

## Maker Profile Bio

Building Eresus Sentinel — deterministic security for the AI stack.
ML model scanning, prompt firewalls, MCP agent security.
github.com/EresusSecurity/Eresus-sentinel
