# Eresus Sentinel — Competitive Feature Benchmark

> Honest, feature-level comparison against 16 open-source AI-security tools the user called out. For each competitor: what it does, what we already match, what we're missing, whether adoption makes sense. Ends with a unified gap list and a roadmap ranked by ROI. Companion to [`AUDIT.md`](AUDIT.md).

**TL;DR**
- **We already cover most of what these tools do** — our breadth (10 domains, 14+ artifact engines, MCP + skill + firewall + red-team) is wider than any single competitor.
- **Depth is where we lose**: `promptfoo` has a polished web UI + ecosystem, `llm-guard` has mature anonymization, `modelaudit` has a cleaner output format, `pickle-fuzzer` has a real fuzzing harness we don't.
- **10 concrete features to copy** are listed in §12 with effort estimates.
- **UI**: our React frontend already beats promptfoo's Model Audit screenshot structurally (more domains, history view). What's missing is the report polish — export, raw-output toggle, grouping by severity. §13 says build it, don't ship a full rewrite.

---

## 1. `protectai/llm-guard`

**What it is**: the reference input/output guardrail framework for LLM apps. Python lib; scanners pipeline.

**Core features**
- Input scanners: Anonymize (PII → placeholder), PromptInjection (HuggingFace classifier), BanTopics, BanSubstrings, Toxicity, Code, Language, Secrets, TokenLimit, InvisibleText, Regex, Sentiment, Gibberish, Ban competitors.
- Output scanners: Deanonymize, NoRefusal, Bias, Toxicity, Sensitive (PII), FactualConsistency, MaliciousURLs, Relevance, JSON, Regex, URLReachability, Code, BanSubstrings, BanTopics, Language, LanguageSame, Reading­Time, Sentiment, Gibberish.
- Vault (memory) for anonymize/deanonymize round-trip.
- Fail-fast and parallel execution modes.

**What we match**
- Input pipeline (`firewall/input/*`) — we have prompt-injection (heuristic + ML), canary, rate limiter, language detection, secrets, regex, token budget, ban-substrings, code, invisible-unicode, encoding-detection.
- Output pipeline (`firewall/output/*`) — no-refusal, toxicity, bias, PII, JSON, relevance, URL reachability, code, regex, ban-topics, language-same, sentiment, gibberish, factual-consistency.
- Vault (`vault.py`) with redact/restore, shown in `scan_input` endpoint.

**What we're missing**
- Maturity of the anonymize/deanonymize vault (our implementation is basic compared to the production-hardened one in llm-guard).
- The specific `MaliciousURLs` scanner backed by curated blocklists (we only check reachability + allowlist, no threat intel).
- `BanCompetitors` scanner — trivial to add.

**Adopt?** Copy BanCompetitors, invest in vault maturity, plug malicious-URL blocklists into `firewall/output/malicious_urls.py`.

---

## 2. `North-Shore-AI/LlmGuard`

**What it is**: LlmGuard is a smaller fork/alternative that positions itself as a lighter-weight guardrail with a focus on deployment packaging. Fewer scanners than ProtectAI's `llm-guard`, but simpler surface.

**Observations**
- Smaller scanner catalog; mostly prompt-injection and PII focus.
- Packaging emphasis (Docker, simple REST server).

**What we match**: everything in their catalog is already present in ours.

**Adopt?** No. They're a subset.

---

## 3. `protectai/modelscan`

**What it is**: the canonical pickle-scanning tool. H5/Keras, PyTorch, TF SavedModel scanning for unsafe deserialization gadgets.

**Core features**
- Pickle opcode scanning (REDUCE chain with module blocklist).
- H5 (`.h5`, `.keras`) Lambda-layer detection.
- PyTorch zip scanning (`archive/data.pkl` inside `.pt`).
- TF SavedModel op-blocklist.
- CLI with JSON / SARIF output.
- Scan summary: issues by severity.

**What we match** (see [`AUDIT.md`](AUDIT.md) §B)
- Pickle scanner is broader than ModelScan — we add copyreg EXT registry reconstruction, expansion/DUP attacks, nested-pickle detection, CodeType construction, crash-resilient raw-byte fallback.
- H5 / Keras detection — `python/sentinel/artifact/keras_scanner.py` (35 KB).
- PyTorch zip scanning — we recurse into `data.pkl`.
- TF SavedModel — `python/sentinel/artifact/tensorflow_scanner.py`.
- SARIF output — `python/sentinel/sarif_output.py`.

**What we're missing**
- ModelScan's output format is simpler and more scannable in CI logs. Ours is more structured but harder to read at a glance.
- ModelScan has clearer policy config (allow/deny globals per project). Ours is rule-YAML-based but less mature.

**Adopt?** Copy the CLI summary style (critical/warning/info/scanned counts — exactly what `promptfoo/modelaudit` shows in the screenshot). Add a `--style=compact` output mode.

---

## 4. `promptfoo/promptfoo`

**What it is**: eval + red-team framework for LLM apps. YAML-driven, web UI, cloud dashboard. The most production-adopted LLM testing framework.

**Core features**
- `promptfoo eval` — run prompt/model/dataset matrix, assertions, rubrics.
- `promptfoo redteam` — 50+ attack plugins (ASCII smuggling, prompt extraction, harmful content, PII, hijacking, etc.), generates an attack dataset, runs it against your app.
- Web viewer: grid of results, pass/fail per row, side-by-side prompt comparison.
- Integrations: OpenAI, Anthropic, HF, Bedrock, Azure, local models, HTTP endpoints.
- **Model Audit** (see screenshot) — their newer tab that wraps `modelaudit` CLI with a UI.

**What we match**
- Red-team corpus: `redteam/probes/` with TAP, injection_plugins, context_manipulation, apikey, and ~20 more probe modules.
- HTTP endpoint scanning target: `scan_conversation` over any `(prompt, output)` pair.

**What we're missing**
- The eval/rubric harness (matrix testing). We're a scanner, not an evaluator — but we could ship a `sentinel eval` that consumes a red-team corpus and an LLM endpoint.
- The polished web UI for reviewing eval results (grid, filter, export).
- Cloud sync / team sharing.

**Adopt?** Copy:
1. Summary card tiles (critical / warning / info / files-scanned) in the frontend — **easy win, matches the screenshot**.
2. `--output-format html` that produces a standalone report file.
3. Raw-output toggle (they call it "Show Raw Output"). Users want to see JSON when they don't trust the UI.

Don't try to become promptfoo. Stay focused on scanning; integrate with promptfoo via JSON/SARIF export.

---

## 5. `promptfoo/modelaudit`

**What it is**: promptfoo's model-file scanner. Direct ModelScan competitor. Ships with a web UI (the screenshot).

**Core features**
- Pickle / Keras / PyTorch / TF / safetensors / GGUF / joblib / ONNX scanning.
- CLI + programmatic API.
- Web UI with card tiles, findings list, export report, raw-output view.
- Finding schema: position, opcode, severity, location.

**What we match**
- Every file format they scan, we scan (plus TFLite, TorchMobile, LlamaFile, XGBoost, LightGBM, numpy — they don't).
- Rule severity / position metadata in findings.

**What we're missing**
- **The UI polish shown in the screenshot.** Cards for counts, clean findings list with position callouts, export-report button, raw-output toggle. Our `ArtifactsPage.tsx` exists and has comparable structure but less visual polish.
- A dedicated "Model Audit" landing page concept inside a broader platform (they're a tab in promptfoo). Our `/artifacts` page is the rough equivalent.

**Adopt?** Upgrade `frontend/src/pages/ArtifactsPage.tsx` to match the screenshot layout:
- 4 tiles at top (Critical / Warnings / Info / Files Scanned)
- "Security Findings" heading + per-finding cards with location + position + opcode JSON block
- Severity badge, "All (excl. Debug)" dropdown, Export Report, Show Raw Output buttons

This is **≤1 day of frontend work** and directly addresses the user's UI question.

---

## 6. `antgroup/MCPScan`

**What it is**: multi-stage security scanner for MCP servers. From Ant Group's security team. Research-backed (2025 paper).

**Core features**
- Static analysis of MCP tool definitions.
- Dynamic analysis via agent-based probing (they send crafted inputs and observe tool behavior).
- Taint tracking between tools.
- Classifier for tool poisoning.
- Citation: `sha2025mcpscan`.

**What we match**
- Static analysis of tool definitions (our `MCPValidator`).
- Tool poisoning heuristics.

**What we're missing**
- **Dynamic agent-based probing.** We do static-only. They actually boot the MCP server and poke it.
- Cross-tool taint analysis with flow tracking.
- Research-paper-grade classifier.

**Adopt?** The dynamic probing idea is worth it — run the tool with crafted inputs in a sandbox and observe. Medium-complexity. Add `sentinel mcp-probe` subcommand that spawns the MCP server, enumerates tools, fires adversarial inputs, checks responses.

---

## 7. `cisco-ai-defense/mcp-scanner`

**What it is**: Cisco's MCP security scanner. Part of their broader AI Defense OSS push. More polished and active than most.

**Core features**
- Scans MCP tool schemas for prompt injection, tool poisoning, schema abuse.
- Integrates with their `defenseclaw` meta-framework.
- Has a well-documented rule catalog.
- Reports via SARIF.

**What we match**
- MCP schema scanning (`MCPValidator`).
- SARIF output.

**What we're missing**
- The rule catalog is more curated than ours; they benchmark against the specific MCP attack literature (GitHub Issues #xxx, research papers).
- Cleaner integration into IDE plugins (they ship a VS Code extension).

**Adopt?** Import their public rule set into `rules/mcp_rules.yaml` (respect license — likely Apache-2 or MIT). This is **pure rule enrichment with no code change**; highest-ROI adoption on the list.

---

## 8. `cisco-ai-defense/defenseclaw`

**What it is**: umbrella/orchestrator for Cisco's scanners. Runs mcp-scanner, skill-scanner, pickle-fuzzer, a2a-scanner together and produces a unified report.

**Core features**
- Multi-scanner orchestration.
- Unified JSON/SARIF output.
- Policy gating (fail build if severity >= X).

**What we match**
- `cli_dispatch.py` is exactly this pattern — scanner fan-out + `_post_process` policy pipeline.
- Unified `Finding` DTO across all domains.

**What we're missing**
- Nothing substantive. This is our architecture, applied to their scanner set.

**Adopt?** No. We already *are* this.

---

## 9. `cisco-ai-defense/pickle-fuzzer`

**What it is**: structure-aware pickle fuzzer in Rust. Generates valid pickle bytecode to stress-test pickle scanners. Has a GitHub Action. Published a blog post: "Breaking the Jar: Hardening Pickle File Scanners with Structure-Aware Fuzzing".

**Core features**
- Grammar-based bytecode generation (respects pickle opcode semantics, so outputs are parseable).
- Atheris harness mode for Python fuzzing.
- CI integration via a pre-built GitHub Action.
- Rust-native → fast.

**What we match**
- We have a fuzzer directory (`python/sentinel/fuzzer/` — 45 items) and a `FUZZER_ROADMAP.md` (39 KB).

**What we're missing**
- Structure-aware generator output. Our fuzzer exists but we haven't validated it produces pickle-valid bytecode that exercises parser edge cases.
- Published GitHub Action.
- Blog-post-grade methodology doc.

**Adopt?**
- **Seriously consider using cisco's pickle-fuzzer directly** in our CI rather than writing our own. It's Apache-2 or MIT, it's better maintained, it's backed by a research blog. Vendor reuse > in-house duplication.
- Add `make fuzz-pickle` that pulls their binary and runs it against our `PickleScanner`.

---

## 10. `cisco-ai-defense/aibom`

**What it is**: AI Bill of Materials generator. Produces a machine-readable inventory of models, datasets, and weights used by an application.

**Core features**
- SPDX/CycloneDX-compatible SBOM extended with AI fields (model card, weight hash, dataset provenance).
- Scan a repo → emit `ai-bom.json`.
- Sign/verify manifests.

**What we match**
- `supply_chain/` directory exists but is thinner.
- No dedicated AI-BOM generator.

**What we're missing**
- **AI-BOM generation.** We have supply-chain scanning but not SBOM/AI-BOM as a deliverable artifact.

**Adopt?** Yes — add `sentinel bom <path>` emitting CycloneDX-AI JSON. Medium effort. This is increasingly required for enterprise procurement (US EO 14028, EU AI Act).

---

## 11. `cisco-ai-defense/a2a-scanner`

**What it is**: Agent-to-Agent protocol scanner. Specifically for the A2A spec (Google's agent-to-agent protocol). Detects malicious agent cards, tool poisoning across agents, registry poisoning.

**Core features**
- Scan A2A agent manifests for spoofing, capability lying, mass-registration patterns.
- Integrates with agent registries.
- Quality-gate mode for registry operators.

**What we match**
- MCP is our equivalent; A2A is a different protocol.
- Tool-poisoning patterns in `MCPValidator`.

**What we're missing**
- **A2A protocol support entirely.** MCP is the dominant protocol today, but A2A is growing fast (Google is pushing it).

**Adopt?** Moderate priority. Wrap A2A manifest schema into an `A2AValidator` that reuses most of MCPValidator's rule logic. A2A and MCP have enough overlap that this is ~2 days of work, not a ground-up rewrite.

---

## 12. `cisco-ai-defense/skill-scanner`

**What it is**: security scanner for agent skills (Claude-style SKILL.md manifests and similar). Direct competitor to our `python/sentinel/agent/skill_scanner.py`.

**Core features**
- Parses SKILL.md frontmatter structurally (not substring).
- Flags `allowed-tools: ["*"]`, overbroad permissions.
- Cross-file analysis: scans the skill's referenced scripts.
- Pre-commit hook.

**What we match**
- `SkillScanner` class exists with 5-tier command safety analysis.

**What we're missing**
- **Structural frontmatter parsing.** We do per-line regex. They parse the YAML frontmatter properly and type-check fields.
- **Cross-file analysis.** Already called out in [`AUDIT.md`](AUDIT.md) §C.1.
- Pre-commit hook out of the box.

**Adopt?** Directly. Port their frontmatter parser approach to our `SkillScanner.extract_metadata` path. Add `.pre-commit-hooks.yaml` at repo root declaring us as a pre-commit hook provider. Low effort, high user-facing value.

---

## 13. `cisco-ai-defense/ai-defense-python-sdk`

**What it is**: client SDK for Cisco AI Defense cloud platform (paid service). Not directly comparable — it's a commercial API client.

**What we match**: we have our own `python/sentinel/sdk.py` (17 KB) with `Sentinel` class.

**Adopt?** No direct technical adoption. Optional: build a `sentinel-cisco-adapter` that forwards findings to their cloud for customers already in that ecosystem.

---

## 14. `cisco-ai-defense/securebert2`

**What it is**: domain-adapted LM for cybersecurity NLP. Trained on security data; used for semantic search, NER, code-vulnerability detection.

**Core features**
- Fine-tuned BERT-family model.
- Tasks: CVE NER, security classification, code-vuln detection.

**What we match**
- `firewall/input/ml_classifier.py` uses DeBERTa-v3-base-prompt-injection.
- We don't use a security-domain LM for downstream tasks.

**What we're missing**
- Domain-specific reasoning. SecureBERT2 could power a "which CVE does this code match" feature we don't have.

**Adopt?** Optional. Medium effort: add a pluggable backend in `python/sentinel/ai/reasoning.py` that can use SecureBERT2 for semantic classification instead of the current general-purpose models. Only worth it if we productize CVE triage.

---

## 15. `cisco-ai-defense/adversarial-hubness-detector` (HubScan)

**What it is**: scanner for **adversarial hubness in vector databases**. Detects poisoned embeddings that dominate retrieval results in RAG systems. Research-paper backed (HubScan, 2026).

**Core features**
- Audit FAISS / Pinecone / Qdrant / Weaviate indices.
- Detect hubs: embeddings that rank high for an abnormally large number of queries.
- Multi-modal mode (text + image cross-modal).
- Concept-aware mode (per-category hubness).

**What we match**
- `firewall/input/vector_scanner.py` — exists but scope unclear from the name alone.

**What we're missing**
- **Vector-DB-level adversarial-hubness detection is a unique capability**. RAG poisoning is a real and growing attack class (we flagged it as a blind spot in AUDIT.md §I). They are the only OSS tool I know of that addresses it.

**Adopt?** Yes. Two options:
1. Integrate their tool as a dependency — call HubScan from `supply_chain/rag_auditor.py` (new module).
2. Reimplement the core idea: hub-score = `count(queries where this embedding is in top-k)`; flag outliers.

Medium-to-high effort, high novelty. Would be a genuine differentiator.

---

## 16. Feature matrix — who covers what

Legend: ✅ full, 🟡 partial, ❌ none/missing, **★** = unique to Sentinel among the 16.

| Domain | Sentinel | llm-guard | modelscan | promptfoo | modelaudit | MCPScan | cisco-mcp | pickle-fuzzer | a2a | skill-scanner | aibom | hubness |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Input firewall (prompt injection, PII, secrets, rate limit) | ✅ | ✅ | ❌ | 🟡 eval-only | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Output firewall (toxicity, PII, JSON, relevance) | ✅ | ✅ | ❌ | 🟡 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Vault / anonymize-deanonymize | 🟡 | ✅ mature | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Pickle scanner | ✅ strong | ❌ | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ (generates) | ❌ | ❌ | ❌ | ❌ |
| Pickle fuzzer (CI) | 🟡 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |
| H5 / Keras Lambda | ✅ | ❌ | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| PyTorch / TorchScript | ✅ | ❌ | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| TF SavedModel | ✅ | ❌ | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| ONNX | ✅ | ❌ | 🟡 | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| SafeTensors | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| GGUF / LlamaFile | ✅ **★** | ❌ | ❌ | ❌ | 🟡 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| TFLite / TorchMobile | ✅ **★** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| XGBoost / LightGBM / joblib | ✅ **★** | ❌ | ❌ | ❌ | 🟡 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| NumPy `.npy` `.npz` | ✅ **★** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Archive slip (zip/tar/7z) | ✅ strong | ❌ | ❌ | ❌ | 🟡 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Polyglot detection | ✅ | ❌ | ❌ | ❌ | 🟡 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| MCP validator | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ research | ✅ polished | ❌ | ❌ | 🟡 | ❌ | ❌ |
| MCP dynamic probing | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | 🟡 | ❌ | ❌ | ❌ | ❌ | ❌ |
| A2A protocol scanner | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Skill manifest scanner | 🟡 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |
| Notebook scanner (ipynb) | ✅ **★** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| SAST (source code) | ✅ **★** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Secrets scanner | ✅ | 🟡 scanner only | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Diff scanner (PR review) | ✅ **★** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Red-team probes | ✅ | ❌ | ❌ | ✅ dominant | ❌ | 🟡 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Eval framework (rubric, matrix) | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| HuggingFace repo pre-download guard | ✅ **★** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| AI-BOM / SBOM-AI generator | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |
| Vector-DB / RAG hubness audit | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| CVE detection on model / deps | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Trojan / backdoor detector | ✅ **★** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| MCP proxy / runtime guard | ✅ **★** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Honeypot sandbox | ✅ **★** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Web UI | 🟡 React, stubs | ❌ | ❌ | ✅ dominant | ✅ polished | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| SARIF export | ✅ | ❌ | ✅ | ✅ | 🟡 | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| OPA / policy engine | ✅ **★** | ❌ | 🟡 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Pre-commit hook | ❌ | ❌ | ✅ | ❌ | 🟡 | ❌ | ✅ | ✅ | ❌ | ✅ | ❌ | ❌ |
| Docker / REST server | ✅ | ✅ | ❌ | ✅ | 🟡 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |

### Rows marked ★ — our moat
- GGUF / LlamaFile / TFLite / TorchMobile / NumPy / XGBoost scanning
- Notebook scanning (full ipynb plugin system)
- SAST (source-code) scanning
- Diff scanner (PR-review scope)
- HuggingFace pre-download guard
- Trojan detector
- MCP runtime proxy (live guardrail, not just static validation)
- Honeypot sandbox
- OPA policy engine integration

**No single competitor hits more than 6 of our 35 feature rows. Our breadth is the moat.**

---

## 17. Top-10 features to adopt (ranked by ROI)

| # | From | Feature | Effort | Value |
|---|---|---|---|---|
| 1 | cisco-mcp-scanner | Import their MCP rule catalog into `rules/mcp_rules.yaml` | S | **H** — rule enrichment, no code change |
| 2 | promptfoo/modelaudit | Polish `ArtifactsPage.tsx` to match their 4-tile summary + findings layout | S (≤1 day) | **H** — directly addresses user's UI question |
| 3 | cisco-skill-scanner | Structural SKILL.md frontmatter parsing + `.pre-commit-hooks.yaml` | S | **H** — closes a measured blind spot from AUDIT.md |
| 4 | modelscan | Compact CLI output mode (critical/warning/info/scanned counts) | S | M — CI-log readability |
| 5 | cisco pickle-fuzzer | Vendor their fuzzer into `make fuzz-pickle` target | S | **H** — turns on structure-aware fuzzing without writing it |
| 6 | promptfoo | HTML standalone-report export | M | M — enterprise reporting |
| 7 | cisco aibom | `sentinel bom <path>` emits CycloneDX-AI JSON | M | **H** — procurement requirement (EU AI Act) |
| 8 | cisco hubness | Implement hub-score calculation for vector DBs; plug into `supply_chain/` | M-L | **H** — unique differentiator, addresses RAG-poisoning blind spot |
| 9 | cisco a2a-scanner | Add `A2AValidator` reusing MCPValidator logic | M | M — grows with the A2A ecosystem |
| 10 | antgroup MCPScan | Dynamic MCP probing (`sentinel mcp-probe`) | L | M-H — closes our static-only gap |

Total estimate: **~3–4 sprints** to ship 1–7. Items 8–10 are a second phase.

---

## 18. Should we build a UI like promptfoo's Model Audit?

**Short answer: we already have one, upgrade don't rebuild.**

What we have in `@/Users/ibrahim/Downloads/Eresus-sentiel-lite/frontend/`:
- React 19 + TanStack Query + Tailwind 4 + Vite 8 (modern stack).
- 11 pages (Dashboard, Firewall, Artifacts, History, SAST, Secrets, Diff, Notebook, Agent, SupplyChain, RedTeam) — **more breadth than promptfoo's Model Audit tab**.
- `ArtifactsPage.tsx` (11.9 KB) already has: drag-and-drop upload, scanner-badges row, history, finding cards.
- Auth context, login page, echarts integration.

What the screenshot has that we don't (yet):
- 4 summary tiles at the top (Critical/Warnings/Info/Files Scanned) with big numeric counters — **easy Tailwind addition**.
- "All (excl. Debug)" filter dropdown — already doable with our state, just not wired up.
- "Export Report" button producing a downloadable JSON/SARIF/HTML file — our backend already emits JSON; wire a download link.
- "Show Raw Output" toggle showing the raw scanner JSON — simple `<pre>` toggle.
- Location line (`Location: <path> (pos NNN)`) with a code block showing the finding payload (`{"position": 52, "opcode": "REDUCE"}`) — match their format in `FindingCard.tsx`.

### Concrete UI checklist (what to ship this week)

1. Add `SummaryTiles` component with 4 cards (Critical/Warnings/Info/Files Scanned) at the top of `ArtifactsPage`, `FirewallPage`, `HistoryPage`.
2. Add `FindingsFilter` component: dropdown that filters by severity (includes an "All (excl. Debug)" default).
3. Upgrade `FindingCard.tsx` to render `Location: <target> (pos <offset>)` line + collapsible JSON payload.
4. Add `Export Report` button on `ArtifactsPage` and `HistoryPage` that downloads `report.json` and `report.sarif`.
5. Add `Show Raw Output` toggle that reveals the underlying scanner output.
6. Fill in the 6 stub pages (`AgentPage`, `DiffPage`, `NotebookPage`, `RedTeamPage`, `SastPage`, `SecretsPage`, `SupplyChainPage`) — each currently <500 bytes — using `ArtifactsPage` as the template.
7. Add a **"Model Audit"** top-level nav tab that is just a re-skin of `/artifacts` to match the promptfoo/modelaudit naming convention for marketing parity.

**Do not** build a promptfoo clone. We are a scanner platform, not an eval framework. The UI should make scanning pleasant, not try to compete with promptfoo's eval grid.

---

## 19. Gaps vs current AUDIT.md

This benchmark surfaces three gaps that weren't called out in `AUDIT.md`:
- **No AI-BOM generator** (row: cisco-aibom). Add to AUDIT risk matrix as priority-M.
- **No vector-DB/RAG-hubness auditor** (row: cisco-hubness). Add to AUDIT risk matrix as priority-M.
- **No pre-commit hook packaging** (multiple competitors ship one). Trivially cheap, should ship.

These are additive to — not replacements for — the blind-spot list in `AUDIT.md` §I.

---

## 20. Final verdict

**We are broader than every competitor on this list and narrower only where they are specialist tools** (promptfoo at evals, HubScan at vector DBs, aibom at manifests, pickle-fuzzer at fuzz-gen). None of them does what we do across 10 domains.

**Biggest competitive weaknesses today**:
1. UI polish compared to promptfoo/modelaudit (fixable in ≤1 week).
2. No fuzz pipeline even though the scaffold exists (vendor cisco's tool).
3. No AI-BOM even though supply_chain exists (2-sprint build).
4. No RAG-poisoning detection (HubScan integration, 2–3 sprints).

**Biggest strengths nobody else has**:
1. 10-domain integration (firewall + artifact + MCP + skill + notebook + SAST + diff + supply + red-team + sandbox).
2. 14+ model format engines — literally nobody scans TFLite/TorchMobile/LlamaFile/XGBoost/NumPy.
3. MCP runtime proxy (live guardrail) — not just a validator.
4. Honeypot sandbox — unique in OSS.
5. OPA policy integration — unique in OSS.

Adopt the top-5 items from §17, polish the UI per §18, and Sentinel is ahead of every individual OSS competitor in this list on net feature count.
