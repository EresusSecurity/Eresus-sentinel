# Adversarial Corpus — Sentinel Audit

Read-only proof-of-concept samples built for the Eresus Sentinel deep audit (`AUDIT.md`). Each malicious sample targets a specific scanner blind spot or bypass recipe. Each benign sample is a clean control for FP measurement.

**Safety**: every payload is non-functional. Pickle REDUCE chains reference `builtins.print` or non-existent attributes, not `os.system`. No sample will execute meaningful code if deserialized. All samples are structural demonstrations for the scanner, not working exploits.

## Layout

```
tests/adversarial_corpus/
├── README.md              — this file
├── labels.yaml            — expected scanner output per sample
├── _generate.py           — regenerates binary samples; safe to run
├── benign/                — clean controls (should not flag critical)
└── malicious/             — targeted bypass/detection scaffolds
```

Run `python tests/adversarial_corpus/_generate.py` once to materialize binary samples (pickle, zip, tar, gguf) from their textual specs. Plain-text samples (prompts, JSON, YAML, markdown) are checked in directly.

## Running the harness

```bash
python scripts/benchmark_fpfn.py --corpus tests/adversarial_corpus/ \
    --output benchmark_report.json --summary benchmark_summary.md
```

The harness dispatches each sample to the appropriate Sentinel module and compares findings to `labels.yaml`. CI-gate mode:

```bash
python scripts/benchmark_fpfn.py --critical-recall-floor 0.70
# exit code != 0 if critical-category recall < 0.70
```

## Sample index

### Benign controls

| File | Target module | Purpose |
|---|---|---|
| `benign/prompt_safe_technical.txt` | firewall_input | Editing/technical "ignore" usage — FP pressure |
| `benign/mcp_benign_calculator.json` | agent | Math tool with no dangerous capability |
| `benign/skill_benign_readonly.md` | agent (skill) | Read-only filesystem helper skill |
| `benign/pickle_benign_numpy_stub.pkl.spec` | artifact | Plain dict pickle — no REDUCE chain |

### Malicious — MCP / agent

| File | Blind spot | Expected |
|---|---|---|
| `malicious/mcp_synonym_bypass.json` | Keyword list is finite; renamed capability | Ideally MCP-020 for `file_read`; currently misses |
| `malicious/mcp_unicode_homoglyph.json` | No NFKC/confusable folding | Should flag; currently misses |
| `malicious/mcp_negated_keyword.json` | Substring match on flattened JSON | FP expected (MCP-020 fires on "does NOT read_file") |
| `malicious/mcp_split_payload_manifest.json` | No cross-file correlation | Manifest alone passes; `mcp_split_payload_helper.py` carries the danger |
| `malicious/mcp_split_payload_helper.py` | — | Companion to the manifest |
| `malicious/skill_manifest_indirect_injection.md` | No frontmatter schema, no Unicode-tag scrubbing | `allowed-tools: ["*"]` + U+200B invisibles |

### Malicious — Prompt injection

| File | Blind spot |
|---|---|
| `malicious/prompt_injection_turkish.txt` | English-only verb list |
| `malicious/prompt_injection_homoglyph.txt` | `_normalize` doesn't NFKC |
| `malicious/prompt_injection_base64.txt` | No encoding-decode layer |
| `malicious/prompt_injection_chatml.txt` | No ChatML marker detection |

### Malicious — Pickle

| File | Blind spot |
|---|---|
| `malicious/pickle_copyreg_memo_indirection.pkl` | EXT registry tracking via `recent_strings[-3:]` only |
| `malicious/pickle_build_setstate_gadget.pkl` | BUILD/`__setstate__` gadgets unmodeled |
| `malicious/pickle_protocol0_legacy.pkl` | Protocol-0 has no PROTO opcode; structural checks inert |

### Malicious — YAML / deserialization

| File | Blind spot |
|---|---|
| `malicious/yaml_alt_tag.yaml` | `_YAML_MARKERS` misses `!!python/name:` |

### Malicious — Archive / polyglot

| File | Blind spot |
|---|---|
| `malicious/zipbomb_lied_size.zip` | CD-reported sizes trusted (no streaming check) |
| `malicious/nested_archive.tar.gz` | Nested archives not recursed |
| `malicious/polyglot_pickle_head.bin` | Polyglot list fixed; content-dispatch runs one scanner |
| `malicious/torchscript_code_payload.zip` | `code/` directory payload scanning depth |
| `malicious/gguf_malicious_kv.gguf.spec` | Jinja2 SSTI inside kv `chat_template` not scanned |

### Notes on "expected" labels

`labels.yaml` stores two fields per malicious sample:
- `expected_rule_ids`: rule IDs Sentinel *should* emit in an ideal detector; used for recall computation.
- `currently_expected`: rule IDs Sentinel is known to emit today (may be empty for blind spots).

The harness reports both. Blind spots surface as gaps between `expected_rule_ids` and `currently_expected`.
