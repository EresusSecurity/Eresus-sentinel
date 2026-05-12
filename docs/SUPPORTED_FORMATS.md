# Supported Formats

Eresus Sentinel includes **70+ registered scanners** covering model, archive, and configuration formats — the broadest static-analysis surface of any open-source AI security scanner.

> **Static-only guarantee.** No model file is ever loaded, deserialized, or executed during scanning.

---

## Model Formats

| Format | Extensions | Scanner ID | Risk | Key Detections |
|--------|-----------|------------|------|----------------|
| **Pickle** | `.pkl` `.pickle` `.p` `.dill` `.dat` `.data` | `pickle` | CRITICAL | Dangerous GLOBAL opcodes, RCE chains, 300+ blocklisted globals |
| **PyTorch** | `.pt` `.pth` `.bin` `.ckpt` | `pytorch` | CRITICAL | Pickle opcode scan, weights-only bypass, embedded archive checks |
| **TorchScript** | `.torchscript` `.pt` `.zip` | `torchscript` | HIGH | Code execution in `code/` layer, path traversal, pickle constants |
| **TorchServe** | `.mar` | `torchserve` | HIGH | Path traversal, embedded executable, pickle payload in archive |
| **Torch7 (Lua)** | `.t7` `.th` `.net` | `torch7` | HIGH | Lua bytecode `dofile`/`loadstring`, suspicious string patterns |
| **ExecuTorch** | `.pte` `.ptl` | `executorch` | MEDIUM | Pickle payload, suspicious custom ops, binary anomalies |
| **TensorRT** | `.engine` `.plan` `.trt` | `tensorrt` | MEDIUM | Plugin injection, suspicious embedded strings, malformed headers |
| **ONNX** | `.onnx` | `onnx` | HIGH | External data references, opset 0 exploits, malformed proto |
| **TFLite** | `.tflite` | `tflite` | MEDIUM | FlatBuffer parse, custom op abuse, anomalous metadata |
| **Keras (native)** | `.keras` | `keras` | HIGH | Lambda layers, base64 bytecode, `get_file` bypass, safe_mode disable |
| **Keras H5** | `.h5` `.hdf5` | `h5` | HIGH | Lambda bytecode, non-lambda function injection, group structure abuse |
| **TensorFlow SavedModel** | `.pb` `.meta` `saved_model/` | `tensorflow` | HIGH | `ReadFile`/`WriteFile` ops, Lambda layers, PyFunc injection |
| **TF MetaGraph** | `.meta` | `tf_metagraph` | MEDIUM | Op denylist, custom op references |
| **SafeTensors** | `.safetensors` | `safetensors` | LOW | Header SSTI, metadata injection, format integrity |
| **GGUF / GGML** | `.gguf` `.ggml` `.ggmf` `.ggjt` `.ggla` `.ggsa` | `gguf` | LOW | Malformed header, metadata anomalies, embedded URL/IP |
| **JAX / Orbax / Flax** | `.jax` `.checkpoint` `.orbax` `.orbax-checkpoint` `.msgpack` | `jax` | MEDIUM | Pickle in JAX context, dangerous `restore_fn`, anomalous `.pkl` inside Orbax dir |
| **CatBoost** | `.cbm` | `catboost` | MEDIUM | Binary format validation, embedded blob detection |
| **XGBoost** | `.bst` `.model` `.json` `.ubj` | `xgboost` | MEDIUM | JSON model injection, suspicious predictor patterns |
| **LightGBM** | `.lgb` `.lightgbm` `.model` | `lightgbm` | MEDIUM | Config injection, custom objective abuse |
| **CoreML** | `.mlmodel` `.mlpackage` | `coreml` | MEDIUM | Custom layer references, sensitive data in spec |
| **MXNet** | `*-symbol.json` `*-NNNN.params` | `mxnet` | MEDIUM | Custom op abuse, symbol graph analysis |
| **NeMo** | `.nemo` | `nemo` | HIGH | Pickle inside NeMo archive, path traversal |
| **CNTK** | `.dnn` `.cmf` | `cntk` | HIGH | Eval expression injection, command execution, obfuscation, crypto-miner patterns |
| **RKNN** | `.rknn` | `rknn` | MEDIUM | Binary structure anomalies, embedded code detection |
| **Skops** | `.skops` | `skops` | HIGH | `__reduce__` gadgets in sklearn serialization format |
| **PMML** | `.pmml` | `pmml` | MEDIUM | SSTI via PMML fields, XPath injection, external entity abuse |
| **PaddlePaddle** | `.pdmodel` `.pdiparams` | `paddle` | MEDIUM | Protobuf op analysis, custom op references |
| **OpenVINO** | `.xml` | `openvino` | LOW | IR structure anomalies, custom layer abuse |
| **NumPy** | `.npy` `.npz` | `numpy` | HIGH | `allow_pickle` RCE, object array code execution |
| **Llamafile** | `.llamafile` `.exe` | `llamafile` | MEDIUM | GGUF header check, polyglot ZIP detection |
| **R Serialized** | `.rds` `.rda` `.rdata` | `r_serialized` | HIGH | R expression injection, `eval(parse(...))` patterns |
| **Flax** | `.flax` | `flax` | MEDIUM | Pickle in Flax checkpoint, msgpack anomalies |
| **Joblib** | `.joblib` | `joblib` | HIGH | Pickle opcode scan (joblib uses pickle internally) |
| **Torch7** | `.t7` `.th` `.net` | `torch7` | HIGH | Lua execution primitives (os.execute/io.popen/loadstring), dynamic require/ffi.load, network/shell strings, Windows LOLBins |
| **Model Card / README** | `.md` `.rst` `.markdown` | `model_card` | HIGH | Prompt injection, pipe-to-bash instructions, typosquatted pip packages, trust_remote_code docs, hardcoded credentials, suspicious URLs |
| **TensorRT** | `.engine` `.plan` `.trt` | `tensorrt` | CRITICAL | Embedded PE/ELF executables, .so/.dll plugin references, LoadLibrary calls, path traversal, exec/eval strings, TRT plugin entry points |
| **ExecuTorch** | `.pte` `.ptl` | `executorch` | HIGH | FlatBuffer structure validation, eval/exec/import strings in binary, pickle global scanning in ZIP-backed archives |

---

## Archive & Container Formats

| Format | Extensions | Risk | Key Detections |
|--------|-----------|------|----------------|
| **ZIP** | `.zip` `.npz` | HIGH | Path traversal (Zip Slip), symlink attacks, nested archive recursion |
| **TAR** | `.tar` `.tar.gz` `.tar.bz2` `.tar.xz` `.tgz` `.tbz2` | HIGH | Path traversal, absolute paths, device files, symlink attacks |
| **7-Zip** | `.7z` | MEDIUM | Path traversal, solid archive anomalies |
| **RAR** | `.rar` | MEDIUM | Fail-closed: reported as unsupported to prevent silent misses |
| **Compressed Wrappers** | `.gz` `.bz2` `.xz` `.lz4` `.zlib` | MEDIUM | Decompression bomb detection, inner format routing |
| **OCI Image Layers** | OCI directory | HIGH | Malicious layers, embedded model artifacts in container images |

---

## Configuration & Metadata Formats

| Format | Extensions / Paths | Risk | Key Detections |
|--------|-------------------|------|----------------|
| **JSON / YAML Manifests** | `config.json` `tokenizer.json` `*.yaml` `*.yml` | HIGH | SSTI `{{}}` patterns, code injection, hardcoded secrets, weak hashes |
| **Model Cards** | `README.md` `*.md` | MEDIUM | Malicious script tags, embedded URL C2, suspicious license claims |
| **Jinja2 Templates** | `.j2` `.jinja` `.jinja2` | CRITICAL | SSTI execution chains (`{{config.__class__}}` etc.) |
| **HuggingFace `config.json`** | `config.json` | HIGH | `auto_map` RCE, `AutoConfig.trust_remote_code=True` abuse |
| **ML Manifests** | `*.json` metadata | HIGH | Connection string injection, secrets, unsafe download URLs |

---

## Sentinel vs Competitors

| Feature | Sentinel | modelscan | picklescan | fickling |
|---------|----------|-----------|------------|---------|
| Formats covered | 70+ | ~8 | 1 (pickle) | 1 (pickle) |
| Pickle opcode engine | Rust + Python (dual) | Python | Python | Python AST |
| Keras Lambda detection | ✅ base64 bytecode | ✅ basic | ❌ | ❌ |
| TorchScript code analysis | ✅ | ❌ | ❌ | ❌ |
| ONNX proto analysis | ✅ | ❌ | ❌ | ❌ |
| GGUF/GGML | ✅ | ❌ | ❌ | ❌ |
| CNTK | ✅ | ❌ | ❌ | ❌ |
| JAX/Orbax | ✅ | ❌ | ❌ | ❌ |
| Jinja2 SSTI | ✅ | ❌ | ❌ | ❌ |
| Archive path traversal | ✅ ZIP+TAR+7z | ✅ ZIP | ✅ ZIP | ❌ |
| SARIF output | ✅ | ❌ | ❌ | ❌ |
| Pre-commit hook | ✅ | ❌ | ✅ | ❌ |
| MCP / Agent scanning | ✅ | ❌ | ❌ | ❌ |
| Prompt firewall | ✅ | ❌ | ❌ | ❌ |
| Supply chain auditing | ✅ | ❌ | ❌ | ❌ |

---

## Format Routing Logic

Sentinel routes files via a three-stage pipeline:

1. **Extension → Scanner** — Primary routing by file extension.
2. **Magic Bytes → Scanner** — For extensionless files or extension spoofing (e.g., a `.json` containing pickle bytes).
3. **Archive Recursion** — ZIP/TAR/7z containers are opened and inner files re-routed from stage 1.

RAR archives are **fail-closed**: they are detected and reported as unsupported rather than silently skipped.

```bash
# List all active scanners and their extensions
sentinel artifact --list-scanners

# See which scanner would handle a file (dry run)
sentinel artifact model.pkl --dry-run
```
