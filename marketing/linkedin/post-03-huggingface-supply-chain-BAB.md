# LinkedIn Post 03 — HuggingFace Supply Chain | Framework: BAB
# Hook type: Personal transformation
# GIF: demos/hf-scan.gif
# Topic pillar: Model Artifact Security

---

**I scanned 100 HuggingFace models last month.**

12 had patterns I would not want in a production pipeline.

Before, the default workflow was: find model, download, load.

No inspection. No policy gate. No security step.

It is the ML equivalent of running email attachments.

trust_remote_code=True is the new "open this macro to view the document".

After, with a pre-download scanner running in CI:

You see the model's structure before it touches your runtime.

auto_map flags surface. Embedded execution hooks are caught.

Malicious configs are blocked before deserialisation begins.

The bridge is simpler than you think.

Scan the manifest. Check the metadata. Inspect the config.

3 seconds per model. Full audit trail. SARIF output.

You do not need to load a model to know if it is safe.

Read the structure. Analyse the opcodes. Check the header.

The information is there. You just need a scanner that reads it.

Your model supply chain deserves the same gate as your package registry.

Repost if you use HuggingFace models in your ML workflow. ♻️
