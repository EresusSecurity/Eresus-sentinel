# Compatibility Matrix

## Python Versions

| Python | Core Scanner | API Server | Web Dashboard | Rust Pickle Engine |
|--------|-------------|------------|---------------|--------------------|
| 3.10 | ✅ | ✅ | ✅ | ✅ |
| 3.11 | ✅ | ✅ | ✅ | ✅ |
| 3.12 | ✅ | ✅ | ✅ | ✅ |
| 3.13 | ✅ | ✅ | ✅ | ✅ |
| 3.14 | ✅ (tested) | ✅ | ✅ | Build from source |
| 3.9 | ❌ | ❌ | ❌ | ❌ |

> **Recommended:** Python 3.11 or 3.12 for the broadest optional dependency support (TensorFlow, ONNX Runtime).

---

## Optional ML Framework Dependencies

Some scanners activate additional checks when the corresponding framework is installed. **No framework is required for static scanning** — these are enhancement-only.

| Package | Version | Used For | Install Extra |
|---------|---------|----------|---------------|
| `torch` | ≥ 2.0 | PyTorch weight analysis, TorchScript runtime checks | `[pytorch]` |
| `tensorflow` | 2.13–2.16 | TF SavedModel op enumeration (Python 3.11–3.12 only) | `[tensorflow]` |
| `onnxruntime` | ≥ 1.16 | ONNX shape inference validation | `[onnx]` |
| `h5py` | ≥ 3.9 | Deep H5/Keras group scanning | `[h5]` |
| `safetensors` | ≥ 0.4 | SafeTensors metadata validation | `[safetensors]` |
| `huggingface_hub` | ≥ 0.20 | Remote HF repo scanning | `[hf]` |
| `transformers` | ≥ 4.35 | AutoMap / trust_remote_code detection | `[hf]` |

### Installation Extras

```bash
# Core only (static scanners — recommended for CI)
pip install eresus-sentinel

# All static extras (no ML runtimes)
pip install "eresus-sentinel[all]"

# With PyTorch support
pip install "eresus-sentinel[pytorch]"

# With TensorFlow (Python 3.11–3.12 only)
pip install "eresus-sentinel[tensorflow]"

# Full environment (all extras including runtimes)
pip install "eresus-sentinel[all,tensorflow,pytorch]"

# Development
pip install "eresus-sentinel[dev]"
```

---

## Operating System Support

| OS | Core | Native Package | Docker |
|----|------|----------------|--------|
| Linux (x86_64) | ✅ | `.deb` `.rpm` `.tar.gz` | ✅ |
| Linux (arm64) | ✅ | `.tar.gz` | ✅ |
| macOS (Apple Silicon) | ✅ | `.dmg` Homebrew | ✅ |
| macOS (Intel) | ✅ | `.dmg` | ✅ |
| Windows (x64) | ✅ | `.exe` (installer) | ✅ |

---

## CI Runner Compatibility

| Runner | Status | Notes |
|--------|--------|-------|
| `ubuntu-latest` (24.04) | ✅ | Default CI environment |
| `ubuntu-22.04` | ✅ | |
| `ubuntu-20.04` | ✅ | |
| `macos-latest` (15) | ✅ | |
| `macos-13` | ✅ | Intel runner |
| `windows-latest` (2022) | ✅ | |
| `windows-2019` | ✅ | |
| Self-hosted (Linux) | ✅ | Requires Python 3.10+ |
| Self-hosted (Windows) | ✅ | Requires Python 3.10+ |

---

## Scanner Format Compatibility

Some format scanners have optional library dependencies for enhanced analysis. The table below shows what each scanner does with and without the optional dep.

| Scanner | Without Optional Dep | With Optional Dep | Optional Package |
|---------|---------------------|-------------------|-----------------|
| `h5` | Magic bytes + group name scan | Full dataset recursion | `h5py` |
| `onnx` | Protobuf binary parse | Shape/type inference | `onnxruntime` |
| `tensorflow` | Protobuf op enumeration | Runtime op validation | `tensorflow` |
| `safetensors` | Header parse + SSTI scan | Metadata deep validation | `safetensors` |
| `pytorch` | Pickle opcode scan | Weights-only load check | `torch` |
| `numpy` | Binary header + magic | `allow_pickle` detection | (built-in) |

---

## API / Server Dependencies

| Component | Required Packages | Python Version |
|-----------|-----------------|----------------|
| Core CLI | `pyyaml` `rich` `click` | 3.10+ |
| REST API | `fastapi` `uvicorn` | 3.10+ |
| Web dashboard | `fastapi` `uvicorn` + built frontend | 3.10+ |
| MCP proxy (stdio) | `anyio` | 3.10+ |
| MCP proxy (HTTP) | `httpx` `anyio` | 3.10+ |
| Rust pickle engine | `maturin` (build) | 3.10+ |

---

## Version Policy

- **Patch releases** (0.1.x): backward-compatible bug fixes, rule additions.
- **Minor releases** (0.x.0): may add new scanner IDs or finding fields; existing fields stable.
- **Major releases** (x.0.0): CLI flags, finding schema, and rule ID format may change.

During the **alpha phase** (0.x), any release may contain breaking changes. Pin to an exact version in production:

```toml
# pyproject.toml
eresus-sentinel==0.1.0
```

```bash
# Or pin in requirements.txt
eresus-sentinel==0.1.0
```
