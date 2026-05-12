# Reddit Posts — Eresus Sentinel
# Post timing: Tuesday–Thursday 12:00–15:00 EST
# Do NOT cross-post same text across subreddits — each is rewritten for tone

---

## r/MachineLearning — Discussion post

**Title:** We built a static scanner for ML model files (Pickle, PyTorch, GGUF, ONNX) — no model loading required

**Body:**
We've been quietly building Eresus Sentinel, and I want to share the approach
with people who'll actually care about the technical details.

**The problem:** `torch.load()` is arbitrary code execution. Pickle is literally
a stack-based bytecode VM. When someone uploads a malicious model to HuggingFace
and you pull it down, the payload runs at load time — before any eval, before any
inference. Your sandbox doesn't help if you've already executed the attacker's
`__reduce__` chain.

**What we built:** A scanner that disassembles model files at the opcode / binary
/ AST level without loading them into any interpreter. Covers 24 formats:

- Pickle → opcode disassembly, detects `REDUCE`/`GLOBAL` with dangerous imports
- PyTorch `.pt/.pth/.bin` → ZIP extraction + pickle analysis of each tensor
- GGUF → metadata string scanning for prompt injection
- Keras `.h5` → Lambda layer extraction + config injection
- SafeTensors → header-only validation (the whole point of the format)
- ONNX → custom op detection, external data reference checks
- + 18 more (TFLite, TorchScript, LlamaFile, CNTK, JAX, RKNN...)

Everything is deterministic. No ML model to detect ML threats. SARIF v2.1.0 output
drops straight into GitHub Security tab.

GitHub: https://github.com/EresusSecurity/Eresus-sentinel
pip install eresus-sentinel

Happy to go deep on the Pickle opcode analysis or the GGUF metadata approach.

---

## r/netsec — Link post

**Title:** Eresus Sentinel — open-source static analysis for ML model files + LLM prompt injection firewall

**Body:**
Putting this here because the attack surface is real and underappreciated.

**ML model files as a delivery vector:**
Pickle deserialization = RCE. PyTorch `.bin` files are Pickle under a ZIP.
A researcher last year showed you can embed a reverse shell in a HuggingFace
model that fires on `torch.load()`. Our scanner finds these without executing anything.

**LLM firewall:**
22 input guardrails + 24 output checks. Catches:
- Prompt injection (direct + indirect)
- Encoding attacks (Unicode bidi, homoglyph, zero-width)
- PII in outputs (regex + Luhn for card numbers)
- Invisible text injection

**MCP proxy:**
Intercepts Model Context Protocol traffic at the transport layer. OPA policy
enforcement. Blocks tool poisoning and permission escalation in agent workflows.

Findings map to OWASP LLM Top 10, EU AI Act, and MITRE ATLAS.

https://github.com/EresusSecurity/Eresus-sentinel

---

## r/LocalLLaMA — Discussion post

**Title:** Anyone checking GGUF files before loading them? We added a metadata scanner

**Body:**
Quick security note for anyone running local models: GGUF metadata fields
are essentially free-text that gets passed to the runtime, model cards,
and sometimes displayed in UI elements. Some loaders expose metadata strings
to downstream systems without sanitization.

We added GGUF metadata scanning to Eresus Sentinel — it checks for:
- Prompt injection payloads embedded in model metadata
- Suspicious template strings in tokenizer config
- Abnormally large metadata blobs (>1MB = flag)
- Numeric overflow in tensor dimension headers

```bash
pip install eresus-sentinel
sentinel scan model.gguf
```

Also scans `.llamafile` (the executable envelope + embedded GGUF inside).

Not saying every GGUF you download is malicious — just that nobody was checking.
Repo: https://github.com/EresusSecurity/Eresus-sentinel

---

## r/cybersecurity — Discussion post

**Title:** MCP (Model Context Protocol) is becoming a real attack surface — here's what we're doing about it

**Body:**
Model Context Protocol has quietly become the standard plumbing for AI agents
connecting to tools (filesystems, databases, APIs). Almost nobody is security-testing it.

The attack classes we've documented:

**Tool poisoning:** Malicious MCP server returns tool descriptions with hidden
instructions. Agent executes them as legitimate tool calls.

**Permission escalation:** Agent chains tool calls to gain capabilities beyond
its original scope.

**Prompt injection via tool output:** Data returned by a tool contains injected
instructions that redirect the agent's behavior.

We built a real-time MCP intercepting proxy:
- Sits between your agent and MCP servers
- Inspects all JSON-RPC 2.0 messages
- Enforces OPA (Rego) policy per tool and per call
- Blocks suspicious patterns before they reach the model

It's part of Eresus Sentinel, open source:
https://github.com/EresusSecurity/Eresus-sentinel

We're mapping everything to MITRE ATLAS. Happy to discuss the threat model.

---

## r/Python — Show & Tell post

**Title:** Show & Tell: sentinel — scan ML model files for malicious code, no loading required

**Body:**
Built this after getting frustrated that nobody was checking what's inside
model files before `torch.load()`.

```bash
pip install eresus-sentinel

# Scan a single model
sentinel scan model.pkl

# Scan a HuggingFace repo
sentinel scan --hf EleutherAI/gpt-neox-20b

# Use in Python
from sentinel.artifact import scan_file
findings = scan_file("model.pkl")
for f in findings:
    print(f.rule_id, f.severity, f.title)
```

**What it checks:**
- Pickle opcodes (`REDUCE`/`GLOBAL` = code execution)
- PyTorch ZIP extraction → per-tensor pickle analysis
- GGUF metadata injection
- SafeTensors header validation
- 20 more formats

**Also in the package:**
- LLM input/output firewall (prompt injection, PII, encoding attacks)
- SAST scanner with 120+ secret patterns + entropy analysis
- Git history scanning for leaked secrets

SARIF output works with GitHub's Security tab natively.

Repo: https://github.com/EresusSecurity/Eresus-sentinel
Feedback welcome — especially on false positive rates.

---

## r/devops — Discussion post

**Title:** SARIF + GitHub Security tab integration for ML model scanning — anyone doing this in CI?

**Body:**
Our team added ML model artifact scanning to CI/CD and I'm curious if others
have done the same.

We use the SARIF output from Eresus Sentinel:

```yaml
# .github/workflows/security.yml
- name: Scan model artifacts
  run: |
    pip install eresus-sentinel
    sentinel scan models/ --sarif > results.sarif

- name: Upload to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

This gives you:
- Findings in the Security tab with file/line attribution
- PR annotations when a new model introduces a risk
- Historical tracking of finding trends

The GitHub Action version is in the marketplace if you don't want to write the YAML.
Repo: https://github.com/EresusSecurity/Eresus-sentinel

Anyone else gating model deploys on scan results?
