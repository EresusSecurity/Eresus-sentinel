# Show HN Post — Hacker News
# Title: Show HN: Eresus Sentinel – Scan ML model files for malicious code without loading them
# Post timing: Monday or Tuesday 09:00–11:00 EST
# URL to submit: https://github.com/EresusSecurity/Eresus-sentinel

---

Show HN: Eresus Sentinel – Scan ML model files for malicious code without loading them

We built a deterministic AI security toolkit that covers the full AI stack.

The core problem: teams download models from HuggingFace and call torch.load()
without any inspection. Pickle deserialisation is arbitrary code execution.
A malicious model looks identical to a legitimate one until it runs its payload.

What it does:

- Scans 24 model formats (Pickle, PyTorch, GGUF, ONNX, SafeTensors, Keras,
  TFLite, JAX, CNTK, RKNN) via opcode/AST/binary analysis, nothing loaded
- Input/output firewall with 22+24 guardrails (prompt injection, PII,
  encoding attacks, invisible text, toxicity)
- MCP proxy for intercepting and enforcing OPA policy on all agent traffic
- SAST with 120+ secret patterns, entropy analysis, full git history scanning
- Red team engine with 48 probes mapped to OWASP LLM Top 10 + MITRE ATLAS
- SARIF v2.1.0 output for native GitHub Security tab integration
- YAML-driven rules, zero hardcoded regex in Python code

Everything is deterministic. No AI required to produce findings.
AI adapters (OpenAI/Anthropic/local GGUF) are optional enrichment only.

Stack: Python + Rust (Pickle backend via PyO3/maturin), YAML rule engine,
FastAPI dashboard, Click + Rich CLI.

Currently alpha. We would love feedback on:
- The MCP proxy design (most scanning tools do not cover the agent layer yet)
- The YAML rule format for custom pattern authoring
- Any model formats we are missing

github.com/EresusSecurity/Eresus-sentinel
