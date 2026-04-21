# Eresus Sentinel — Deep Competitive Security Audit

> Read-only review. Brutal, production-focused, adversarial-minded. Numbers in section G come from running `scripts/benchmark_fpfn.py` against `tests/adversarial_corpus/`; this document does not fabricate metrics.

---

## A. Executive Verdict

**Advanced research prototype with some production-grade sub-components. NOT enterprise production-ready as a whole.**

Pickle scanner and archive-slip detector are genuinely strong — on par with or slightly ahead of `fickling`/`ModelScan` on specific dimensions (copyreg EXT tracking, fickling-parity structural checks, multi-step symlink chain analysis). The rest of the stack — REST server, MCP/agent validator, heuristic prompt-injection layer, cross-file story — is substantially weaker than README/AGENTS.md imply. Several product claims are not actually implemented.

### Top 5 critical problems

0. **Artifact scanning is broken in the current tree.** `@/Users/ibrahim/Downloads/Eresus-sentiel-lite/python/sentinel/cli_dispatch.py:154` imports `NumPyScanner` but the class is `NumpyScanner` (see `@/Users/ibrahim/Downloads/Eresus-sentiel-lite/python/sentinel/artifact/numpy_scanner.py:117`). Every `Sentinel.scan_artifact()` call, every `/scan/artifact` hit, every CLI artifact scan raises `ImportError` at dispatch entry and returns zero findings. Discovered by running `scripts/benchmark_fpfn.py` against the adversarial corpus. Single-character fix, but critical deployment-blocking regression.

1. **Server auth is unimplemented.** `AGENTS.md` advertises `SENTINEL_AUTH_TYPE` / `SENTINEL_AUTH_TOKEN`. `python/sentinel/server.py` never reads them, registers no auth middleware, enforces nothing. Every endpoint public. Combined with default `SENTINEL_CORS_ORIGINS="*"` + `allow_credentials=True` (`@/Users/ibrahim/Downloads/Eresus-sentiel-lite/python/sentinel/server.py:104-110`) this is documentation-reality drift and a CRITICAL attack surface (server accepts hostile artifacts → feeds them into in-process parsers).
2. **MCP detection is substring matching on flattened `json.dumps(tool).lower()`** (`@/Users/ibrahim/Downloads/Eresus-sentiel-lite/python/sentinel/agent/mcp_validator.py:127-147`). Every capability check is defeated by synonyms, homoglyphs, or split payloads. Negated descriptions produce FPs; benign wrappers produce FNs.
3. **Heuristic injection is English-only** (`@/Users/ibrahim/Downloads/Eresus-sentiel-lite/python/sentinel/firewall/input/heuristic.py:30-52`). 11 verbs × 20 objects, all English. `_normalize()` strips punctuation but does **not** NFKC/confusable-fold. Turkish / Arabic / Chinese / Cyrillic-homoglyph / base64-wrapped overrides walk past.
4. **Parser isolation is advisory, not enforced.** `scan_safety.run_with_timeout` exists but `_scan_single_artifact` in `cli_dispatch.py:144-213` calls scanners directly in-process. Hostile `.onnx`/`.keras`/`.pb`/`.tflite` triggering OOM or native-parser bug compromises the scanner host. No seccomp, no namespace isolation, no egress block.
5. **Zip/tar bomb detection trusts self-reported sizes.** `archive_slip.py:270-308` accumulates `info.file_size`/`compress_size` from the ZIP central directory without decompressing. Classic lie-in-CD bombs not caught. Same for `member.size` in tarballs.

### Top 5 genuine strengths

1. **Pickle opcode engine.** `pickletools.genops` with raw-byte fallback on crash, EXT1/2/4 + `copyreg.add_extension` registry reconstruction, introspection-chain detection (`__subclasses__`/`__builtins__`), CodeType/FunctionType/marshal chain, GET/PUT expansion + DUP flood, unused-assignment side-effect, nested-pickle-in-string with 32-byte FP guard (`pickle_scanner.py:393-684`). Better than `picklescan`, roughly at parity with `fickling`.
2. **Archive-slip breadth.** Multi-step symlink chain resolver (depth ≤10, circular detection), Unicode fraction/fullwidth/slash look-alikes, hardlink-to-sensitive-paths, TAR device/FIFO entries, case-insensitive collisions, Windows ADS, 7z via `py7zr`. Broader than fickling's archive handling.
3. **Rule externalization.** Every regex in `rules/*.yaml`, compiled once behind `@lru_cache(maxsize=1)` (`rules.py:58-335`). Zero hardcoded regex in scanner code. Auditable surface.
4. **Anti-spoofing.** When content-detect vs extension disagree, `FormatAnalyzer.analyze` runs **both** scanners (`format_analyzer.py:301-310`). Polyglot sweep finds pickle markers inside ELF tails.
5. **Post-processing pipeline.** `_post_process` in `cli_dispatch.py:64-122` cleanly separates suppression, severity filter, shadow mode, advisory mode, optional AI FP reduction from detection. Most OSS scanners bake policy into rules.

---

## B. What the scanner genuinely does well

- Pickle: fickling-parity structural checks + extensions (duplicate/misplaced PROTO, GET/PUT expansion, DUP flood, memo-size ceiling, CodeType construction, EXT registry reconstruction, nested-pickle-in-string with FP guard).
- Obfuscation flagging: base64/codecs/marshal/zlib/gzip imports flagged independently of blocklist.
- Archive slip: multi-step symlink chain with cycle detection, Unicode separator/dot look-alike tables, ZIP `external_attr>>28==0xA` symlink detection, TAR hardlink-to-sensitive.
- Format detect: magic-byte primary + extension fallback + ZIP subtype disambiguation (TorchScript `code/`, Keras `config.json`, PyTorch `data.pkl`) + protobuf field-number ONNX vs TF SavedModel.
- Rule engine: pure YAML, `ERESUS_RULES_DIR` override, LRU cache, both list-root and dict-root shapes, invalid-regex entries silently skipped (robust).
- 14+ artifact engines: pickle/safetensors/GGUF/PyTorch/ONNX/TF/TorchScript/TFLite/TorchMobile/LlamaFile/Keras/XGBoost/NumPy/archive.
- Notebook plugin-per-concern separation.
- Red-team probe library (TAP, injection plugins, context-manipulation, apikey leak).

---

## C. Critical weaknesses

### C.1 Architectural
- **No per-file scanner isolation.** Hostile inputs execute parsers in-process. Native-parser bugs (libprotobuf via onnx, TF SavedModel loader, py7zr, h5py, flatbuffers, pickletools) land inside the server. `run_with_timeout` is never invoked from dispatchers.
- **`ProcessPoolExecutor(max_workers=4)` created/torn-down per `/scan/batch`** (`server.py:306-307`). `fork` is unsafe once `transformers`/`torch` have loaded native threads; `spawn` re-imports every scanner per worker per request. No queue, no cap beyond 100, no backpressure.
- **No multi-file correlation.** MCP validator reads one JSON. Skill scanner reads one file. Split-payload attacks (benign manifest + malicious helper) pass entirely.
- **No reachability model.** Every detection is syntactic. Severity not weighted by reachability; dead-code and test-fixture matches score identically to live handlers.

### C.2 Security of the scanner itself
- **Zero server auth.** `/scan/*`, `/hf/assess`, `/metrics`, `/plugins`, `/scanners` all public.
- **CORS `*` + `allow_credentials=True`** is spec-invalid and security-hostile (`server.py:104-110`).
- **Info-disclosure endpoints** (`/plugins`, `/scanners`) fingerprint the scanner set.
- **Unauthenticated ProcessPool endpoint** = unauthenticated worker exhaustion.
- **`multiprocessing.get_context("fork")`** in `scan_safety.py:108` is unsafe on macOS and in any interpreter where a library has loaded threads pre-fork.
- **No egress control.** HFGuard, live_scanner, ai/reasoning, huggingface_scanner all make outbound HTTP. Hostile artifact metadata with a callback URL can beacon out (SSRF-from-scanner).
- **Pickle zip-entry decompression is unbounded.** `pickle_scanner.scan_zip_entry` → `zf.read(entry_name)` reads entire entry into memory; `MAX_DECOMPRESS_SIZE` is not enforced here.

### C.3 Detection engine
- Substring matching dominates. MCP `keyword.lower() in json.dumps(tool).lower()`. Skill scanner `re.search(pat, line)` per line. `taint_rules.yaml` exists but there is no actual source→sink graph — patterns match independently.
- **Protocol-0 pickle** has no PROTO opcode, so duplicate-PROTO/misplaced-PROTO checks never fire. Only the blocklist guards.
- **BUILD / `__setstate__` gadgets** not modeled. Scanner flags *modules in blocklist*; a class from a benign module with an inherited malicious `__setstate__` chain passes.
- **copyreg EXT memo indirection.** `_deep_analyze` tracks `add_extension` only when module/name/code appear in `recent_strings[-3:]` at REDUCE (`pickle_scanner.py:554-567`). PUT args into memos earlier, GET to stack just before REDUCE → `recent_strings` empty at boundary → registration untracked → subsequent EXT1/2/4 fires un-flagged.
- **Polyglot list fixed** (ZIP/GGUF/pickle/ELF/PE/TAR/numpy). Missing SQLite, HDF5, Parquet, Arrow IPC, BSON, MessagePack.
- **YAML markers only cover 3 forms** (`_YAML_MARKERS`). Missing `!!python/name:`, `!!python/tuple`, full-URI `tag:yaml.org,2002:python/object/apply`.
- **Safetensors metadata JSON content** is not cross-scanned against `injection_patterns.yaml`/`secret_patterns.yaml`.
- **GGUF `chat_template` Jinja2** SSTI primitives (`{{ __import__(...) }}`) not scanned inside kv string data.
- **Protobuf parser is hand-rolled** (`protobuf_parser.py`, 4.8 KB). High-risk for integer-overflow / unbounded-allocation bugs. No fuzzing in `tests/`.
- **FlatBuffer parser is hand-rolled.** FlatBuffer offset confusion is the standard attack class. Not fuzzed.
- **No memory caps at parser boundary.** 2 GB I/O ceiling; parsers can amplify length-prefixed fields arbitrarily beyond that.

### C.4 Parsing robustness
- **Single-level archive scan.** No recursion into nested archives; depth-2+ payloads undetected.
- **`pickletools.genops` partial results on crash are discarded** (`pickle_scanner.py:410-419`). Crash-at-opcode-N attack hides N+1..end.
- **`zipfile.is_zipfile` is boolean.** Polyglots (ZIP+pickle+PE) scanned only as ZIP unless `_detect_polyglot` catches — and even then only one scanner dispatches.

### C.5 Operational
- No OpenTelemetry, no correlation IDs into scanner layer (only HTTP header).
- Metrics lack per-parser failure rates, per-rule hit rates, per-format timeout counts.
- Audit log JSONL with no rotation/retention.
- `suppression.filter` runs before severity filter; CRITICAL findings suppressed via `.sentinelignore` hash don't appear in metrics either (data-integrity issue).
- No graceful shutdown, no SIGTERM handler.
- No tenant isolation. Shared rules cache, shared suppression file, shared vault.

---

## D. MCP / Skill / Prompt / Agent Config Assessment

### D.1 Strengths
- Schema hygiene: `additionalProperties: true`, missing `required`, typeless properties, unbounded arrays, unbounded strings, nesting >10 for DoS (`mcp_validator.py:149-316`). This is the best part.
- Missing-auth gated on presence of dangerous capability (`mcp_validator.py:251-272`) — conditional activation reduces FPs, good design.
- Description-injection regexes in `mcp_rules.yaml:290-350` catch explicit jailbreak language.

### D.2 Blind spots
- **Synonym evasion trivial.** 12–20 keywords per capability; rename tool and bypass.
- **Homoglyph evasion trivial.** `json.dumps(tool).lower()` doesn't NFKC.
- **Negated keywords → FP.** "does NOT read_file" matches `read_file` substring.
- **No schema→capability inference.** Tool `format_text` with `inputSchema.properties.cmd:{type:string}` = command executor; misses.
- **No cross-tool chain analysis.** Tool A (read_file) + Tool B (http_request) = exfil primitive; each passes individually.
- **No remote manifest scanning.** Local JSON only.
- **No SKILL.md frontmatter understanding.** `allowed-tools:["*"]` invisible unless `*` is a keyword (it isn't).
- **Indirect injection.** URL referenced in tool description → fetched later → payload arrives post-scan.
- **Instruction-hierarchy bypass.** `<|im_start|>system` ChatML markers undetected.

### D.3 Bypass recipes
1. Synonym rename (`read_file` → `grab_asset`).
2. Single Cyrillic/Greek homoglyph in capability name.
3. Split capability across two cooperating tools.
4. Put logic in a referenced Python module (scanner reads only manifest).
5. Benign "do NOT" prefix.
6. YAML anchors/merges across nested manifest files.

---

## E. Model Artifact / Serialization Assessment

### E.1 Pickle (strong, residual gaps)
- copyreg EXT + memo indirection bypasses 3-string lookahead.
- BUILD/inherited `__setstate__` gadgets not modeled.
- Protocol-0 skips all structural checks.
- `_YAML_MARKERS` misses alternative YAML tag forms.
- Pickle-inside-safetensors not recursed.

### E.2 Safetensors
Structural validation (offsets, dtype, shape) OK. Metadata JSON content not scanned against injection/secret patterns. URL references in metadata ignored. Tensor-name collisions with reserved framework identifiers not checked.

### E.3 GGUF
`gguf_analyzer.py` + `gguf_engine.py` are substantial (52 KB combined) but not measured in this pass for negative/overflow length fields, mismatched type declarations, embedded nulls, and — critically — **Jinja2 SSTI in `chat_template` kv entries**.

### E.4 ONNX / TF SavedModel / TFLite
- Hand-rolled protobuf framing (high parser attack surface, no fuzzing evidence).
- Custom-op detection (external `.so` loaders) not verified in this pass.
- FlatBuffer offset-confusion class untested.

### E.5 Archives
Strong at depth-1. Weak at depth-2+. Lied-CD zip bombs not caught. Nested archives not recursed.

### E.6 Bypass recipes
1. Pickle copyreg + memo indirection.
2. Polyglot pickle+SQLite (SQLite header wins content-sniff, pickle scanner never runs).
3. Zip bomb with advertised 1 KB / actual 10 GB.
4. TAR-in-ZIP-in-TAR path traversal.
5. Safetensors metadata hiding payload.
6. GGUF `chat_template` Jinja2 SSTI.
7. ELF+pickle polyglot late-offset.

---

## F. Competitive Comparison

| Tool | Overlap | Sentinel wins | Competitor wins |
|---|---|---|---|
| **fickling** (Trail of Bits) | Direct — pickle opcode | Broader format coverage, archive-slip broader, MCP layer | Deeper opcode semantic modeling (typed stack sim), more battle-tested, more principled polyglot |
| **ModelScan** (Protect AI) | Pickle + some TF/PyTorch | YAML-driven rules, broader format list, fickling-parity checks | More production deployments, proven CI story, simpler UX |
| **picklescan** (HF) | Pickle only | EXT registry abuse, nested pickle, CodeType, expansion attacks | Tiny, minimal attack surface, HF-scale battle-tested |
| **garak** (NVIDIA) | Partial — red-team only | Integrated platform (artifact+firewall+MCP) | Dramatically more probes, better orchestration, calibrated against real LLMs |
| **PyRIT** (Microsoft) | Partial — red-team orchestration | Lighter, faster to deploy | Proper orchestration, attacker-model integration, azure-native |
| **LLM Guard** (Protect AI) | Direct — input/output firewall | Cheaper heuristic layer, broader scanner catalog | Better-integrated injection classifier, more mature anonymization, battle-tested vault |
| **NeMo Guardrails** (NVIDIA) | Partial — Colang DSL | — | Different paradigm; not apples-to-apples |
| **Rebuff** (archived) | Direct — canary | Present | Was vector-DB backed; Sentinel's equivalent unclear |
| **checkov/kics** | Supply-chain/IaC | Model-focused | 1000s of IaC rules; not comparable |

### Adjudication
- **Pickle**: competitive with fickling on EXT/expansion, behind on semantic opcode modeling. Surpasses picklescan.
- **MCP/skill/prompt**: weak substring approach, but no dedicated competitor really exists → low-bar win by default. No moat.
- **Artifact breadth**: Sentinel wins (14+ engines is rare).
- **Firewall**: LLM Guard is richer/more mature. Sentinel has more scanners but more variable depth.
- **Red-team**: garak and PyRIT class-leading; Sentinel respectable but not a replacement.

---

## G. FP/FN Evaluation

### G.0 Measured numbers (from harness run on this checkout)

`scripts/benchmark_fpfn.py --verbose` against `tests/adversarial_corpus/` produced:

- **Overall**: TP=4 FP=3 TN=2 FN=13 — precision=0.57 recall=0.24 F1=0.33
- **Critical subset (n=15)**: TP=4 FP=0 FN=11 — precision=1.00 recall=0.267 F1=0.42
- **Per category recall**:
  - `mcp`: 1.00 (but precision 0.60 — real FPs on benign calculator and negated-keyword samples)
  - `prompt`: 0.25 (Turkish miss, homoglyph flagged by *different* rule than expected)
  - `pickle` / `archive` / `polyglot` / `gguf` / `yaml`: 0.00 (but see below — this is a bug, not a detection gap)
- **Latency**: p50=1.6 ms, p95=3.7 s (ML classifier load), max=24.4 s (first prompt run loads the injection classifier).

### G.0.1 In-production bug discovered by the harness

**Every artifact scan currently crashes on import.**

```
ImportError: cannot import name 'NumPyScanner' from 'sentinel.artifact.numpy_scanner'
```

Root cause: `@/Users/ibrahim/Downloads/Eresus-sentiel-lite/python/sentinel/cli_dispatch.py:154` imports `NumPyScanner` (camelCase `P`), but the class in `@/Users/ibrahim/Downloads/Eresus-sentiel-lite/python/sentinel/artifact/numpy_scanner.py:117` and the `artifact/__init__.py` export are `NumpyScanner` (lowercase `p`). This import is at the top of `_scan_single_artifact`, so **every invocation of `Sentinel.scan_artifact`, `cli_dispatch.dispatch_artifact`, and the `/scan/artifact` endpoint** dies on the import line before any scanning runs. All 9 artifact samples in the harness crashed with identical errors. This is a critical deployment-blocking regression. Fix: rename the import to `NumpyScanner` in `cli_dispatch.py:154`.

### G.0.2 False-positive evidence (real, measured)

- **Benign MCP calculator emits 3× MCP-020** (`malicious/../benign/mcp_benign_calculator.json`). The calculator has no dangerous capability. MCP-020 fires on substring matches inside the description's anti-description ("no code execution, no filesystem, no network"). Textbook negated-keyword FP.
- **`mcp_negated_keyword.json`** (labeled as clean, intent-benign) emits 3× MCP-020 — confirms the FP pattern holds on a second sample with a clearly benign description.
- **Benign technical editing prompt emits `FIREWALL-INPUT-100`** (hidden-unicode-related). The test prompt contains "ignore / bypass / skip / override / do not override" in ordinary editorial context. At least one rule in that pipeline is noisy.

### G.0.3 True-positive notes on malicious samples

- MCP synonym/homoglyph/split samples all emitted MCP-020/050/060 — but partly because those rules also fire on schema-hygiene issues (missing auth fields on a dangerous-looking tool), not because the validator semantically identified `grab_asset` as `read_file`. The synonym-bypass specifically is **not** detected as "this is a file reader" — it's flagged because the JSON schema is loose enough to trip MCP-050/060. Rename the tool and tighten the schema (add `additionalProperties: false` and bounded types) and the capability bypass becomes invisible.
- Homoglyph prompt hit `FIREWALL-INPUT-006` (not `-003`). This is coincidental detection via a different rule, not by the heuristic-injection scanner. The heuristic layer itself still doesn't fold confusables.
- Base64 prompt hit `FIREWALL-INPUT-005`. Same story: detected via a sibling rule (encoded-content suspicion), not by the heuristic injection layer decoding the payload.
- **Turkish prompt — zero detections**. All five firewall scanners together miss it.
- **Skill indirect-injection markdown — zero detections**. Skill scanner doesn't understand markdown frontmatter; `allowed-tools: ["*"]` walks past.

### G.0.4 Severity of the artifact-crash

The overall-recall number (0.24) is misleadingly low because it includes 9 samples that would otherwise have produced *some* findings (pickle blocklist, archive-slip path traversal, polyglot detection) once the ImportError is fixed. A more honest read of today's detector on artifact formats is "untested — the dispatch is broken in main". Fix the typo, re-run the harness, and expect pickle/archive categories to show non-zero recall. The blind spots documented in section J (copyreg memo indirection, BUILD gadget, protocol-0, YAML alt-tag, lied-CD bomb, nested archive, Jinja2 SSTI) will remain after the fix.

### G.1 Qualitative predictions (code-review based)

### Predicted high-FP modules
- `firewall/input/heuristic.py` — SequenceMatcher 0.6 threshold on 8,360 combinatoric phrases. Benign-context regex is English-only.
- `agent/mcp_validator._check_dangerous_capabilities` — substring match on flattened JSON; security-discussion descriptions trigger.
- `agent/skill_scanner` — regex per-line, no benign-context; safe-wrapper documentation lights up.
- `notebook_scanner/secrets_plugin` — "Generic API Key" regex matches any ≥16-char string assignment; ML notebooks explode.

### Predicted high-FN modules
- Any MCP/skill/prompt against multilingual or homoglyph input.
- Cross-file / split-payload anywhere.
- Nested archives at depth ≥2.
- Custom-op TF/ONNX external loaders.
- Safetensors metadata content.
- GGUF Jinja2 SSTI.
- Pickle BUILD/`__setstate__` gadgets with benign-class names.
- Advertised-size zip bombs.
- YAML alt-tag deserialization.

### Severity modeling
- Flat per-rule YAML severity. No exploitability weighting, no reachability.
- `confidence` mostly hardcoded floats set by scanner authors, not derived from evidence strength.
- File-level aggregation missing — `risk_score` is max confidence, not combined.
- Severity inflation: MCP "overly permissive schema" is HIGH even when no dangerous capability — dilutes HIGH signal.

---

## H. Benchmark Methodology

Delivered: `scripts/benchmark_fpfn.py` + `tests/adversarial_corpus/` (benign + malicious + `labels.yaml`).

### Corpus
- **Benign**: editing-context prompt, calculator MCP, readonly skill, numpy pickle.
- **Malicious**: 17 categories — MCP synonym/homoglyph/negation, Turkish/homoglyph/base64 prompt, pickle copyreg-memo/BUILD/protocol-0, YAML alt-tag, lied-CD zipbomb, ELF+ZIP+pickle polyglot, TorchScript `code/`, GGUF malicious kv, 3-level nested archive, skill invisible-Unicode, split-payload.

### Metrics
- Per-sample: expected, got (rule_ids), duration_ms, crashed, timed_out.
- Aggregate: TP/FP/TN/FN, precision, recall, F1 — overall + per-category.
- Ops: parser crashes, timeouts, p50/p95 latency.
- CI gate: critical-category recall floor (default 0.70).

### Limitations
- Corpus synthesized, not harvested from real HF malicious reports.
- No native-parser fuzzing (requires atheris/AFL, separate effort).
- No concurrency/throughput testing.
- Over-detection on malicious samples not penalized (lenient precision).

---

## I. Detection Blind Spots

**MCP/Skill/Prompt**: synonym & homoglyph evasion; split-payload; indirect URL injection; multilingual; base64/hex/rot13; ChatML markers; tool-chain exfil; SKILL.md frontmatter `allowed-tools:["*"]`; MCP `resources`/`prompts` sections; negation FPs.

**Model artifacts**: BUILD/inherited `__setstate__`; copyreg EXT memo indirection; protocol-0 structural checks; YAML alt tags; safetensors metadata content; GGUF chat_template Jinja2 SSTI; custom-op external loaders; HDF5/Parquet/SQLite polyglots; pickle-inside-safetensors recursion; lied-size zip bombs; nested archives ≥2.

**Scanner itself**: no native-parser sandbox; no egress block on remote scans; unauthenticated endpoints.

---

## J. Bypass Opportunities

Concrete recipes (PoCs in `tests/adversarial_corpus/malicious/`):

1. MCP synonym — `grab_asset` not in keywords → `mcp_synonym_bypass.json`.
2. MCP Cyrillic `reаd_file` → `mcp_unicode_homoglyph.json`.
3. MCP negated `"does NOT read_file"` FP → `mcp_negated_keyword.json`.
4. Turkish injection → `prompt_injection_turkish.txt`.
5. Homoglyph injection `Ignоre` → `prompt_injection_homoglyph.txt`.
6. Base64-wrapped injection → `prompt_injection_base64.txt`.
7. Pickle copyreg + memo indirection → `pickle_copyreg_memo_indirection.pkl`.
8. Pickle BUILD `__setstate__` gadget → `pickle_build_setstate_gadget.pkl`.
9. Protocol-0 GLOBAL chain → `pickle_protocol0_legacy.pkl`.
10. YAML `!!python/name:os.system` → `yaml_apply_alt_tag.yaml`.
11. Lied-CD zip bomb → `zipbomb_lied_size.zip` (structural scaffold).
12. ELF+ZIP+pickle polyglot → `polyglot_zip_pickle_elf.bin`.
13. TorchScript `code/` payload → `torchscript_code_payload.zip`.
14. GGUF malicious kv + SSTI → `gguf_malicious_kv.gguf`.
15. 3-level nested archive → `nested_archive_tar_in_zip_in_tar.tar.gz`.
16. Skill invisible-Unicode in `allowed-tools` → `skill_manifest_indirect_injection.md`.
17. Split-payload manifest + helper → `mcp_split_payload_manifest.json` + `mcp_split_payload_helper.py`.

---

## K. Production Readiness Gaps

| Dimension | Status | Detail |
|---|---|---|
| Authentication | MISSING | No enforcement on any route. AGENTS.md env vars not wired. |
| CORS | MISCONFIGURED | Wildcard + credentials default. |
| Rate limiting | Absent at HTTP | `firewall/input/rate_limiter.py` is pipeline-budget, not request-rate. |
| TLS | Delegated | No `--tls` flag, no guidance. |
| Input caps | Partial | pydantic caps on prompt/output; no artifact-batch cap. |
| Scanner isolation | MISSING | No sandbox between scan worker and host. |
| Egress control | MISSING | Outbound HTTP from HFGuard/live_scanner/ai unauthenticated. |
| Timeout enforcement | Advisory only | `run_with_timeout` not invoked from dispatch. |
| Memory caps | Soft | RLIMIT_AS attempted in would-be subprocess; subprocess not actually used. |
| Concurrency | Weak | ProcessPoolExecutor per request, 100-item hardcoded. |
| Backpressure | Absent | — |
| Structured logging | Partial | `logging.getLogger` throughout; format not enforced. |
| Tracing | MISSING | No OTel. |
| Metrics | Thin | No per-parser failure, per-rule hit, timeout counters. |
| Audit log | JSONL only | No rotation, no retention. |
| Graceful shutdown | MISSING | No SIGTERM handler. |
| Tenant isolation | MISSING | Shared cache, shared suppression, shared vault. |
| RBAC | MISSING | — |
| SBOM | MISSING | — |

---

## L. Risk Matrix

| # | Issue | Category | Sev | Likelihood | Impact | Evidence | Fix |
|---|---|---|---|---|---|---|---|
| 1 | Unauth API server | scanner-self | CRITICAL | High | Unauth scan exec, info disclosure, worker exhaust | `server.py:104-402` no auth | FastAPI dep reading `SENTINEL_AUTH_TYPE`/`_TOKEN`; bind 127.0.0.1 default; require token every route |
| 2 | CORS `*` + credentials | scanner-self | HIGH | High | CSRF, cred leak | `server.py:104-110` | Explicit origin list; forbid `*` when credentials=True |
| 3 | MCP substring match | detection | HIGH | Certain | Trivial synonym/homoglyph bypass | `mcp_validator.py:127-147` | NFKC + confusable + schema-aware AST + synonym expansion |
| 4 | Heuristic English-only | detection | HIGH | Certain | Multilingual bypass | `heuristic.py:30-52` | Language-per-verb-set; NFKC normalize; encoding-decode layer (b64/hex/rot13) |
| 5 | No parser sandbox | scanner-self | CRITICAL | Medium | Hostile artifact → scanner compromise | `cli_dispatch.py:144-213` | nsjail/bubblewrap/gVisor per-scan; seccomp profile; network egress deny |
| 6 | Lied-CD zip bomb | parser | HIGH | Medium | DoS via extraction | `archive_slip.py:270-308` | Decompress with bounded ratio; trust actual bytes not CD |
| 7 | Pickle copyreg memo indirection | detection | HIGH | Medium | EXT abuse un-flagged | `pickle_scanner.py:554-567` | Track PUT/GET into memo during STRING_OPS; resolve stack at REDUCE for add_extension args |
| 8 | BUILD `__setstate__` gadget | detection | HIGH | Medium | Gadget-chain bypass of module blocklist | Opcode model | Taint stack top across BUILD; flag `__setstate__` inheritance from known-dangerous bases |
| 9 | Protocol-0 structural blind | detection | MEDIUM | Medium | Structural checks don't fire | `pickle_scanner.py:453-474` | Adapt GET/PUT heuristics to protocol-0 opcodes (`p`,`q`,`g`,`h`) |
| 10 | Safetensors metadata unscanned | detection | MEDIUM | High | Injection/secrets hide in metadata | `safetensors_engine.py` | Run JSON content through injection/secret rulesets |
| 11 | GGUF Jinja SSTI unscanned | detection | HIGH | Medium | Inference-time RCE via chat_template | `gguf_analyzer.py` | Parse kv string entries; match Jinja SSTI primitives (`{{...attr...__...}}`) |
| 12 | Nested archive not recursed | detection | MEDIUM | High | Depth-2+ traversal missed | `archive_slip.py` | Configurable recursion with depth+size caps |
| 13 | YAML alt-tag gap | detection | MEDIUM | Medium | `!!python/name:` / full-URI deserialization missed | `_YAML_MARKERS` | Expand to full YAML 1.2 python tag set |
| 14 | Hand-rolled protobuf | parser | HIGH | Low-Medium | Integer overflow / OOM in native parser path | `protobuf_parser.py` | Fuzz with atheris; use `google.protobuf` with size limits; run in sandbox |
| 15 | No multi-file correlation | detection | HIGH | Certain | Split-payload undetected | Architecture-wide | Build cross-file reference graph (imports, tool refs, URL refs); taint sources→sinks across files |
| 16 | No tenant isolation | ops | HIGH | Medium | Cross-tenant data leak | Architecture-wide | Per-tenant rule cache, suppression file, vault namespace, audit log |
| 17 | Info-disclosure endpoints | scanner-self | MEDIUM | High | Scanner fingerprinting | `server.py:387-400` | Require auth; rate-limit; optional tenant-scoped view |
| 18 | `fork` start-method | scanner-self | MEDIUM | Medium | macOS instability + post-thread-fork UB | `scan_safety.py:108` | Default `spawn`; opt-in `fork` on Linux-only paths |
| 19 | Pickle zip-entry unbounded read | parser | MEDIUM | Medium | OOM on fat embedded pickle | `pickle_scanner.scan_zip_entry` | Enforce `MAX_DECOMPRESS_SIZE` at entry boundary |
| 20 | Severity not exploitability-weighted | reporting | MEDIUM | Certain | Severity inflation/deflation | Finding model | Add reachability + evidence-strength factors to severity; aggregate file-level risk |
| 21 | `NumPyScanner` import typo | correctness | CRITICAL | Certain | All artifact scans ImportError-crash | `cli_dispatch.py:154` | Rename import to `NumpyScanner` (lowercase p); add a CI smoke test that imports every dispatcher |

---

## M. Concrete Architecture Improvements

1. **Parser isolation**: dedicated short-lived worker per file. `bubblewrap` (Linux) / `sandbox-exec` (macOS) / gVisor. No network namespace. Read-only mount of target file. Memory cgroup. Seccomp deny `execve`/`ptrace`/`clone`+NEWUSER.
2. **Worker model**: persistent worker pool (not per-request ProcessPoolExecutor). `asyncio.Queue` with bounded depth. Drain on SIGTERM. Fd-passing for streaming large files.
3. **Rule engine v2**: schema-aware AST over JSON/YAML/TOML. Pattern language with taint qualifiers (source/sink/sanitizer). Rule-level `requires_context` for reachability gating.
4. **Multi-file graph analyzer**: build import/reference/URL graph. Cross-file taint between MCP tool manifest, tool handler code, referenced Python modules, and configured URLs. Prompt→tool→network→secret chains scored as a unit.
5. **Confusable-normalization layer**: single utility applying NFKC + Unicode confusable folding (UTS #39) + whitespace normalization before every substring/regex match. Wire into MCP validator, heuristic injection, skill scanner, YAML markers.
6. **Benchmark harness as CI gate**: this audit's `benchmark_fpfn.py` runs on PR; recall floor on the critical category gates merge.
7. **Severity redesign**: `severity = f(rule_base_severity, exploitability, reachability, evidence_strength)`; file-level `risk_score` from combined findings, not max confidence. Explicit separation of `confidence` (how sure we are) from `severity` (how bad if true).
8. **Telemetry redesign**: per-parser failure counters, per-rule hit counters, per-format timeout counters, per-sample scan duration histogram. Export OTel traces.
9. **Corpus pipeline**: CI step that pulls latest adversarial samples from fickling/ModelScan/picklescan test corpora + internal corpus, re-runs harness, tracks FP/FN regressions over time.
10. **Scanner-as-server hardening**: bind 127.0.0.1 default; require auth dep on every route; explicit CORS; `/plugins`/`/scanners` behind admin scope; `/metrics` behind token or localhost-only; request-rate limiter (ASGI middleware).

---

## N. Immediate Next Steps (top 10)

0. **Fix the `NumPyScanner` → `NumpyScanner` typo in `cli_dispatch.py:154`.** One-character change. Unblocks the entire artifact scanning path. Add a CI smoke test that imports every module listed in `_scan_single_artifact` to prevent regressions.
1. Ship auth middleware in `server.py`. Wire `SENTINEL_AUTH_TYPE`/`SENTINEL_AUTH_TOKEN`. Default deny.
2. Fix CORS default: explicit origin list; forbid `*` + credentials combo.
3. Bind server to 127.0.0.1 by default; require `--host 0.0.0.0` opt-in.
4. Invoke `run_with_timeout` from `_scan_single_artifact` so the existing sandboxing code actually runs.
5. Switch `multiprocessing` default to `spawn`.
6. Add NFKC + Unicode-confusable normalization in a single `sentinel.normalize` utility; call it in MCP validator, heuristic injection, skill scanner.
7. Expand `_YAML_MARKERS` and add `!!python/name:` pattern.
8. Add zip-bomb detection via streaming decompression with bounded ratio (don't trust CD).
9. Add cross-scan of safetensors metadata JSON against existing injection/secret rulesets.
10. Wire this audit's `scripts/benchmark_fpfn.py` into CI with a recall floor on critical-category.

---

## O. 30 / 60 / 90-day Roadmap

**Day 0–30 — Stop the bleeding.** Auth, CORS, sandbox-wiring, NFKC normalization, YAML-marker gap, zip-bomb streaming check, safetensors metadata scan. Ship benchmark harness in CI.

**Day 31–60 — Close detection gaps.** Expand MCP capability lists + synonym expansion + schema→capability inference. Add GGUF Jinja2 SSTI scan. Add BUILD/`__setstate__` gadget modeling. Add cross-file import-graph analyzer (start with Python imports referenced in MCP manifests). Fuzz protobuf/flatbuffer parsers with atheris. Corpus expansion: import fickling + ModelScan public corpora.

**Day 61–90 — Enterprise posture.** Tenant isolation (per-tenant rule cache, suppression, vault). Worker pool with backpressure + SIGTERM drain. OpenTelemetry traces + per-parser/per-rule metrics. RBAC on server endpoints. SBOM generation in CI. Rotation/retention on audit log. Severity redesign with exploitability + reachability factors. Red-team integration with garak for cross-validation.

---

## P. Final Brutal Verdict

**Current level**: advanced research prototype with two production-class sub-systems (pickle, archive-slip) grafted onto an otherwise under-engineered integration, management, and MCP/prompt layer. "Enterprise-grade AI/LLM Security Platform" is aspirational marketing; the code does not support that claim today.

**Must not ship to production without**, in this order:
1. Server auth implemented and enforced.
2. Parser isolation actually wired (the sandbox code exists; plumb it in).
3. CORS hardened.
4. NFKC/confusable normalization deployed to every substring match path.
5. MCP validator upgraded beyond flattened-JSON substring matching.
6. Heuristic injection upgraded beyond English-only.
7. Zip-bomb streaming validation (stop trusting CD).
8. Multi-file correlation (even minimal: Python imports from MCP manifests).
9. Benchmark harness gating CI with recall floor.
10. Audit log rotation + retention.

**Becomes a serious product if** the 30/60/90 plan is executed and the team treats the pickle/archive subsystems as the template for the rest of the detection engine (YAML-driven rules, fickling-parity structural analysis, crash-resilient fallback, honest severity/confidence separation).

---

## Mandatory six-question check per major subsystem

**Server (`server.py`)**
1. Produces security value? Limited — the scanners do, the server just exposes them, and exposes them **without auth**.
2. Attacker bypass? Trivial — no auth, no rate limit.
3. Hostile input safe? No — feeds artifacts to in-process parsers without isolation.
4. Scales? No — ProcessPoolExecutor per request, no queue, no backpressure.
5. Analyst-usable? Adequate for demos (OpenAPI UI); not for production operations.
6. 1-year maintainable? Yes, the code is small and clean. The issue is feature gaps, not code rot.

**MCP validator (`agent/mcp_validator.py`)**
1. Security value? Low-to-moderate. Catches obvious schema laziness; misses real attacker techniques.
2. Bypass? Trivial (synonym, homoglyph, split).
3. Hostile input safe? Yes — it's a JSON reader.
4. Scales? Yes — O(n) per tool.
5. Analyst-usable? Findings are readable; severity is noisy.
6. Maintainable? Yes — rules are in YAML.

**Heuristic injection (`firewall/input/heuristic.py`)**
1. Security value? Low as a standalone; adequate as a pre-filter before the ML classifier.
2. Bypass? Trivial (non-English, homoglyph, encoding-wrapped).
3. Hostile input safe? Yes — string operations only.
4. Scales? Yes for typical prompt length; SequenceMatcher is quadratic on very long inputs.
5. Analyst-usable? Output is clear; FP rate likely high on technical content.
6. Maintainable? Combinatoric generator is clean; adding languages requires structural change.

**Pickle scanner (`artifact/pickle_scanner.py`)**
1. Security value? High — real opcode analysis with multiple defense layers.
2. Bypass? Non-trivial but exists (copyreg memo indirection, BUILD gadgets, protocol-0 structural bypass).
3. Hostile input safe? Mostly — `pickletools.genops` crashes fall back to raw-byte scan; zip-entry read is unbounded (fix needed).
4. Scales? Yes — opcode iteration is linear.
5. Analyst-usable? Excellent — clear rule IDs, evidence, chain-confirmation field.
6. Maintainable? Yes — rules externalized, clear state machine.

**Archive slip (`artifact/archive_slip.py`)**
1. Security value? High — covers ZIP, TAR, 7z with multi-step symlink chains.
2. Bypass? Moderate — lied-CD zip bombs, nested archives, polyglot boundaries.
3. Hostile input safe? Mostly — no extraction; reads metadata only.
4. Scales? Yes — iterative `tf.next()` avoids OOM.
5. Analyst-usable? Excellent — specific rule IDs per attack class.
6. Maintainable? Yes — single file, readable.

**Format analyzer (`artifact/format_analyzer.py`)**
1. Security value? High — proper content-sniff + extension-disagreement double-scan.
2. Bypass? Moderate — polyglot list is fixed, new format combinations slip.
3. Hostile input safe? Depends on downstream parsers; the analyzer itself is safe.
4. Scales? Yes.
5. Analyst-usable? Yes.
6. Maintainable? Yes — adding a format is a FORMAT_MAP entry + engine.
