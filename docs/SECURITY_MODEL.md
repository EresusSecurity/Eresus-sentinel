# Security Model

This document describes Sentinel's threat model, trust boundaries, scanning guarantees, and known limitations.

---

## Core Guarantee: Static-Only Analysis

**Sentinel never loads, deserializes, or executes any model file.**

Every finding is produced by inspecting raw bytes, opcode streams, protobuf fields, FlatBuffer tables, or text patterns — without invoking any ML framework runtime.

This means:

- A malicious pickle `__reduce__` chain **cannot execute** during a Sentinel scan.
- A Keras model with a Lambda layer **cannot run** its embedded bytecode.
- A TorchScript archive **cannot evaluate** its `code/` Python IR.
- A GGUF file with a crafted header **cannot crash** the ML runtime.

---

## Threat Model

Sentinel is designed to detect the following attack classes before a model is deployed or loaded:

### T1 — Serialization-Based Code Execution
Abuse of Python's pickle/joblib/dill deserialization protocol to embed arbitrary code in model files.

**Attack vector:** `os.system`, `subprocess.Popen`, `builtins.eval`, `operator.attrgetter` gadget chains  
**Affected formats:** `.pkl`, `.pt`, `.pth`, `.bin`, `.ckpt`, `.npy`, `.joblib`, `.dill`, `.skops`, `.mar`  
**Detection:** Pickle opcode GLOBAL/INST enumeration against 300+ blocklisted `module.function` pairs

### T2 — Framework-Specific Code Injection
Injection of executable code through framework-defined extension points.

**Attack vector:** Keras Lambda layers with base64 bytecode; TorchScript `code/` backdoor; PMML SSTI; Jinja2 SSTI; `auto_map` trust_remote_code abuse  
**Affected formats:** `.keras`, `.h5`, `.torchscript`, `.pmml`, `.j2`, `config.json`  
**Detection:** Config traversal, bytecode pattern matching, SSTI regex

### T3 — Path Traversal / Archive Slip
Malicious archive entry names that write files outside the extraction target.

**Attack vector:** `../../../etc/cron.d/backdoor` inside ZIP/TAR; symlinks pointing outside root  
**Affected formats:** `.zip`, `.tar`, `.7z`, `.mar`, `.nemo`  
**Detection:** Entry name normalization check against extraction root

### T4 — Supply Chain Tampering
Models served from compromised or typosquatted sources; integrity bypass.

**Attack vector:** Missing hash pinning; unsigned model cards; typosquatted HuggingFace repo names  
**Detection:** `supply_chain` module — hash verification, provenance audit, OSV.dev lookup

### T5 — Embedded Secrets / Data Exfiltration
Credentials, API keys, or network callbacks embedded in model weights or metadata.

**Attack vector:** Hardcoded AWS/HF/GitHub tokens in `config.json`; C2 URLs in GGUF metadata; socket callbacks in pickle  
**Detection:** Secret pattern matching (2000+ patterns), URL/IP extraction, network module detection in pickle

### T6 — Prompt / Agent Injection
Adversarial content in model metadata, system prompts, or MCP tool definitions that re-purposes an LLM agent.

**Attack vector:** Instruction injection in `README.md`; tool-call hijacking via MCP `description` fields  
**Detection:** `firewall/input/` guardrails, `agent/mcp_validator`, prompt injection YAML rules

### T7 — Backdoored Weights
Statistical anomalies in model weights that indicate a backdoor trigger (e.g., BadNets).

**Attack vector:** Concentrated weight outliers; bimodal weight distribution; suspiciously low loss on trigger inputs  
**Detection:** `weight_distribution` scanner (heuristic, LOW confidence — see Limitations)

---

## Trust Boundaries

```
┌─────────────────────────────────────────────────────┐
│                  UNTRUSTED ZONE                       │
│  Model files, archives, config.json, tokenizers,      │
│  HuggingFace repos, PyPI packages, MCP manifests      │
└────────────────────┬────────────────────────────────┘
                     │  bytes only — never exec'd
                     ▼
┌─────────────────────────────────────────────────────┐
│              SENTINEL SCANNER PROCESS                 │
│  Reads raw bytes. Parses structure. Matches rules.    │
│  No subprocess spawn. No framework import.            │
└────────────────────┬────────────────────────────────┘
                     │  Finding objects
                     ▼
┌─────────────────────────────────────────────────────┐
│               TRUSTED OUTPUT ZONE                     │
│  SARIF / JSON / Table — consumed by CI, dashboards   │
└─────────────────────────────────────────────────────┘
```

**What Sentinel does NOT do:**
- It does **not** import `torch`, `tensorflow`, `onnxruntime`, or any ML framework to scan.
- It does **not** spawn subprocesses per file.
- It does **not** load Python bytecode from scanned files.
- It does **not** make network requests during scanning (unless `--remote` flag is explicitly passed).

---

## Scanner Isolation

Each scanner runs in the same process but:

- Catches all `Exception` types and converts them to `ARTIFACT-099` / `*-PARSE-ERROR` findings.
- Bounds memory via `max_file_size_mb` (default 500 MB) and recursion depth (`max_archive_depth`, default 3).
- Uses read-only `bytes` or `Path.read_bytes()` — no `mmap` with write permissions.

Sentinel is **not** a sandbox. A crafted file that exploits a Python parser vulnerability (e.g., a ReDoS in a YAML loader) could affect the scanner process. For maximum isolation, run Sentinel inside a container:

```bash
docker run --rm -v "$(pwd)/models":/data --read-only \
  ghcr.io/eresussecurity/sentinel:latest artifact /data
```

---

## Known Limitations

| Limitation | Impact | Mitigation |
|------------|--------|------------|
| Weight backdoor detection is heuristic | Low-confidence findings; FP/FN possible | Manual review + behavioral testing |
| Encrypted or password-protected archives | Silent skip | Reported as `ARCHIVE-ENCRYPTED` warning |
| Files > `max_file_size_mb` | Silent skip | Adjust `max_file_size_mb` or use `--no-size-limit` |
| Obfuscated pickle using `REDUCE` chains | May evade opcode scan | Enable `--profile paranoid` for deeper analysis |
| Novel gadget chains not in blocklist | Miss | Report via GitHub Issues; contribute to blocklist |
| RAR archives | Fail-closed: reported unsupported | Extract manually first |
| Pickle protocol 5 out-of-band buffers | Partial analysis | Buffer objects checked for known patterns |

---

## Reporting Vulnerabilities

If you discover a bypass or a Sentinel crash caused by a crafted model file, please report it via our [Security Policy](../SECURITY.md).

Do **not** open a public GitHub issue for bypass techniques — this gives attackers advance notice before a patch is released.
