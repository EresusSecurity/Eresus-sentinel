# Format Support

**Docs:** [Overview](overview.md) · [Quick Start](quickstart.md) · [How It Works](how-it-works.md) · [Detection](detection.md) · [Deception Engine](deception.md) · [Deployment](deployment.md) · [Configuration](configuration.md) · [API Reference](api.md) · [Threat Hunting](threat-hunting.md) · [Format Support](format-support.md)

---

## Supported Model Formats

Eresus Sentinel supports security scanning for **30+ model artifact formats** with automatic format detection via magic bytes and file extensions.

### Full Format Table

| Format | Extensions | Magic Detection | Scanner | Risk Level |
|--------|-----------|-----------------|---------|------------|
| **Pickle** | `.pkl`, `.pickle` | `\x80\x02`–`\x80\x05` | `PickleScanner` | 🔴 Critical — arbitrary code execution |
| **PyTorch** | `.pt`, `.pth`, `.bin` | ZIP + `data.pkl` | `PickleScanner` (ZIP-wrapped) | 🔴 Critical — pickle inside ZIP |
| **Joblib** | `.joblib` | `\x80\x02`–`\x80\x05` | `PickleScanner` | 🔴 Critical — pickle-based |
| **HDF5/H5** | `.h5`, `.hdf5` | `\x89HDF\r\n\x1a\n` | `H5Scanner` | 🟠 High — embedded code, pickle-in-HDF5 |
| **Keras** | `.keras` | ZIP | `KerasScanner` | 🟠 High — Lambda layers, config injection |
| **TensorFlow SavedModel** | `.pb`, `.pbtxt` | Protobuf | `SavedModelScanner` | 🟡 Medium — custom ops |
| **TFLite** | `.tflite` | FlatBuffer | `TFLiteScanner` | 🟢 Low — limited execution |
| **ONNX** | `.onnx` | Protobuf | `ONNXScanner` | 🟡 Medium — custom operators |
| **SafeTensors** | `.safetensors` | Header JSON | `SafeTensorsScanner` | 🟢 Low — no code execution by design |
| **GGUF** | `.gguf` | `GGUF` | `GGUFScanner` (Rust) | 🟡 Medium — metadata injection, overflow |
| **NumPy** | `.npy`, `.npz` | `\x93NUMPY` | Pattern scanner | 🟢 Low — data only |
| **CoreML** | `.mlmodel` | — | Pattern scanner | 🟡 Medium — custom layers |
| **Skops** | `.skops` | ZIP | Pattern scanner | 🟡 Medium — restricted pickle |
| **NeMo** | `.nemo` | TAR | Pattern scanner | 🟡 Medium — archive contents |
| **XGBoost** | `.xgb`, `.ubj` | — | Pattern scanner | 🟢 Low — custom binary |
| **LightGBM** | `.txt` (model) | — | Pattern scanner | 🟢 Low — text format |
| **CatBoost** | `.cbm` | — | Pattern scanner | 🟢 Low — custom binary |
| **OpenVINO** | `.xml`, `.bin` | — | Pattern scanner | 🟢 Low — IR format |
| **PMML** | `.pmml` | `PMML` | Pattern scanner | 🟢 Low — XML format |
| **MsgPack** | `.msgpack` | — | Pattern scanner | 🟡 Medium — Flax/JAX models |
| **Tokenizer JSON** | `.json` | — | `TokenizerScanner` (Rust) | 🟡 Medium — code injection in tokens |
| **MLflow** | ZIP | `MLmodel` inside | Format middleware | 🟡 Medium — multiple inner formats |
| **Cloudpickle** | `.pkl` | Pickle proto | `PickleScanner` | 🔴 Critical — extended pickle |
| **Dill** | `.pkl` | Pickle proto | `PickleScanner` | 🔴 Critical — extended pickle |
| **Marshal** | `.marshal` | — | Pattern scanner | 🔴 Critical — bytecode execution |
| **TorchScript** | `.pt` | ZIP | `PickleScanner` + JIT | 🟠 High — JIT ops |
| **Flax** | `.msgpack` | MsgPack | Pattern scanner | 🟡 Medium |
| **LoRA** | `.safetensors` | Header JSON | `SafeTensorsScanner` | 🟢 Low |
| **PaddlePaddle** | `.pdparams` | — | Pattern scanner | 🟡 Medium |
| **Ollama Modelfile** | `Modelfile` | — | Pattern scanner | 🟡 Medium — directives |
| **LlamaFile** | `.llamafile` | — | Pattern scanner | 🟡 Medium |

### Automatic Format Detection

The format middleware (`sentinel.artifact.format_middleware`) uses a two-stage detection strategy:

1. **Magic bytes** — Read the first 16 bytes and match against known signatures (highest confidence)
2. **File extension** — Fall back to extension-based lookup if magic bytes don't match
3. **ZIP refinement** — For ZIP files, inspect contents to distinguish PyTorch, Keras, MLflow, etc.

### Rust-Accelerated Scanners

Two formats have dedicated Rust scanners for performance:

- **GGUF** (`rust/sentinel-gguf/`) — Header parser with 9 security checks (GGUF-001 to GGUF-015)
- **Tokenizer JSON** (`rust/sentinel-tokenizer/`) — Token analysis with 6 check groups (TOK-010 to TOK-060)

### Risk Classification

| Risk Level | Description | Action |
|------------|-------------|--------|
| 🔴 **Critical** | Format allows arbitrary code execution (pickle, marshal) | Always scan; block untrusted sources |
| 🟠 **High** | Format can embed executable content (HDF5, Keras Lambda, JIT) | Scan and review findings |
| 🟡 **Medium** | Format has limited attack surface (ONNX custom ops, metadata injection) | Scan recommended |
| 🟢 **Low** | Format is data-only or execution-restricted (SafeTensors, NumPy, TFLite) | Scan optional; good baseline choice |
