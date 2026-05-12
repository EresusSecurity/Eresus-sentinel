# Directory Listings — Eresus Sentinel
# Copy-paste ready for each platform's submission form

---

## AlternativeTO
**URL:** https://alternativeto.net/software/add/
**Alternatives to:** Rebuff, LLM Guard, Guardrails AI, ProtectAI ModelScan

**Product Name:** Eresus Sentinel
**Website URL:** https://github.com/EresusSecurity/Eresus-sentinel
**Short Description (160 chars):**
Deterministic AI security toolkit: scan 24 ML model formats, block prompt injection, intercept MCP agent traffic. No AI required to find AI threats.

**Full Description:**
Eresus Sentinel is an open-source, deterministic AI security toolkit that covers
the full modern AI stack — from model files to agent traffic.

Model Artifact Scanner: Scans 24 formats (Pickle, PyTorch, GGUF, ONNX,
SafeTensors, Keras, TFLite, CNTK, JAX, RKNN, XGBoost, LightGBM and more)
without loading them. Detects RCE payloads, metadata injection, and archive slip
attacks at the binary/opcode/AST level.

Prompt Firewall: 22 input guardrails and 24 output checks for prompt injection,
PII leakage, encoding attacks, invisible text, and toxicity.

MCP Proxy: Real-time intercepting proxy for Model Context Protocol traffic with
OPA policy enforcement. Blocks tool poisoning and permission escalation in AI
agent workflows.

SAST: 120+ secret patterns, entropy analysis, git history scanning, and Jupyter
notebook inspection. SARIF output for GitHub Security tab.

Red Team: 48 attack probes mapped to OWASP LLM Top 10, EU AI Act, and MITRE ATLAS.

**Category:** Security Software, Developer Tools, AI Tools
**License:** Open Source
**Platform:** Linux, macOS, Windows (Python)
**Tags:** ai-security, llm-security, model-scanning, prompt-injection, mcp-security, sast, devsecops

---

## Toolify.ai
**URL:** https://www.toolify.ai/submit
**Category:** AI Security Tools

**Tool Name:** Eresus Sentinel
**Tool URL:** https://github.com/EresusSecurity/Eresus-sentinel
**Tagline:** Scan your entire AI stack for threats — before production
**Description (300 chars):**
Deterministic AI security: scan 24 ML model formats without loading them, block
prompt injection, intercept MCP agent traffic with OPA policy enforcement.
SARIF output. Zero AI required to find AI threats.

**Use Cases:**
- ML model supply chain security
- LLM application security testing
- AI agent security monitoring
- DevSecOps for AI teams

**Pricing:** Free / Open Source
**Tags:** security, llm, model-scanning, prompt-injection, mcp, sast, devsecops, open-source

---

## There's An AI For That (TAAFT)
**URL:** https://theresanaiforthat.com/submit/
**Category:** Security

**AI Name:** Eresus Sentinel
**Website:** https://github.com/EresusSecurity/Eresus-sentinel
**What does it do? (1 sentence):**
Deterministic static scanner for ML model files and LLM applications — catches malicious payloads, prompt injection, and secrets before they hit production.

**Description:**
Eresus Sentinel is an open-source AI security toolkit. It scans 24 ML model
formats (Pickle, PyTorch, GGUF, ONNX, SafeTensors) for malicious code without
loading them, runs an LLM prompt/output firewall, intercepts MCP agent traffic,
and performs SAST on AI application code. pip install eresus-sentinel.

**Pricing:** Free
**Tags:** security, developer-tools, llm, open-source

---

## Futurepedia
**URL:** https://www.futurepedia.io/submit-tool
**Category:** Developer Tools → Security

**Tool Name:** Eresus Sentinel
**Tool URL:** https://github.com/EresusSecurity/Eresus-sentinel
**Short Description:**
Open-source security toolkit for AI/ML applications. Scans model files for malicious code, blocks prompt injection, monitors MCP agent traffic.

**Full Description:**
Eresus Sentinel protects your entire AI stack:

🔬 Model Scanner — 24 formats analyzed statically (no loading)
🛡️ Prompt Firewall — 22+24 guardrails against injection, PII, encoding attacks
🤖 MCP Proxy — real-time agent traffic inspection with OPA policies
🔍 SAST — 120+ secret patterns, entropy analysis, git history scanning
⚔️ Red Team — 48 probes, OWASP LLM Top 10, MITRE ATLAS mapping

Everything is deterministic. SARIF output. One pip install.

**Pricing:** Free, Open Source
**Categories:** Security, Developer Tools, AI Infrastructure
**Website Screenshot tip:** Use terminal showing `sentinel scan model.pkl` with findings output

---

## SaaSHub
**URL:** https://www.saashub.com/submit
**Category:** Security Software

**Software Name:** Eresus Sentinel
**Software Website:** https://github.com/EresusSecurity/Eresus-sentinel
**Short Pitch:**
Deterministic AI security toolkit for ML teams: model file scanning, LLM firewall, MCP agent proxy, SAST.

**Description:**
Eresus Sentinel is an open-source security toolkit purpose-built for AI/ML
applications. It covers model artifact scanning (24 formats), prompt injection
defense, MCP agent traffic monitoring, static analysis for secrets, and red team
probing. All findings are deterministic — no AI used to detect AI threats.

**Alternatives:** ProtectAI ModelScan, Rebuff, Guardrails AI, LLM Guard
**Pricing:** Free / Open Source
**License:** Open Source

---

## GitHub Actions Marketplace
**File:** action.yml (already exists in repo root)

**Listing details for marketplace.github.com:**

**Name:** Sentinel Security Scan
**Description:**
Scan ML model artifacts, detect prompt injection patterns, analyze secrets,
and run SAST on AI application code. SARIF output for GitHub Security tab.

**Categories:** Security, Code Quality
**Keywords:** security, ml-security, model-scanning, prompt-injection, sast, sarif, ai-security

**Example workflow (add to README and marketplace description):**
```yaml
- name: Sentinel Security Scan
  uses: EresusSecurity/Eresus-sentinel@v0.1.0
  with:
    path: '.'
    sarif: true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: sentinel-results.sarif
```

**Submit at:** https://github.com/marketplace/new
(Requires action.yml in repo root — already present ✅)
