# Scanner Selection

Sentinel runs all applicable scanners by default. This page explains how to run a targeted subset, exclude noisy scanners, and understand scanner discovery.

---

## List Available Scanners

```bash
# Human-readable table
sentinel artifact --list-scanners

# JSON (for scripting)
sentinel artifact --list-scanners -f json
```

Output columns: **Scanner ID**, **Class**, **Extensions**, **Optional Deps**.

---

## Run Only Selected Scanners

Use `--scanner` (repeatable) or a comma-separated list:

```bash
# Run only the pickle scanner
sentinel artifact ./models --scanner pickle

# Run pickle + pytorch
sentinel artifact ./models --scanner pickle,pytorch

# Class name also works
sentinel artifact ./models --scanner PickleScanner
```

`--scanner` starts from an explicit allowlist — only the named scanners run, regardless of the default set.

For **container formats** (ZIP, TAR) you should include both the container scanner and the nested payload scanner:

```bash
# Scan a zip that may contain pickle files
sentinel artifact archive.zip --scanner zip,pickle
```

---

## Exclude a Scanner

```bash
# Skip the weight-distribution heuristic scanner (slow on large models)
sentinel artifact ./models --exclude-scanner weight_distribution

# Exclude multiple
sentinel artifact ./models --exclude-scanner weight_distribution,watermark
```

`--exclude-scanner` subtracts from either the explicit `--scanner` allowlist or the default set.

---

## Adjust Minimum Severity

```bash
# Only show CRITICAL and HIGH findings (suppress MEDIUM/LOW/INFO)
sentinel artifact model.pkl --min-severity HIGH

# Show everything including INFO
sentinel artifact model.pkl --min-severity INFO
```

---

## Profile Shortcuts

Built-in scan profiles bundle common scanner+severity combinations:

```bash
# Fast profile — high-signal scanners only, CRITICAL+HIGH
sentinel artifact ./models --profile fast

# Full profile — all scanners, all severities (default)
sentinel artifact ./models --profile full

# Paranoid profile — all scanners + strict mode + max recursion
sentinel artifact ./models --profile paranoid
```

---

## Per-Format Configuration (`sentinel.toml`)

Fine-tune scanner behaviour in `sentinel.toml`:

```toml
[scanners.artifact]
enabled = true
min_severity = "MEDIUM"
max_archive_depth = 3        # recursion limit for nested archives
max_file_size_mb = 500       # skip files larger than this

# Disable specific scanner classes
disabled_scanners = ["weight_distribution", "watermark_detector"]

# Allowlist — these module.function pairs are never flagged in pickle
[scanners.artifact.pickle_allowlist]
"numpy.core.multiarray" = ["_reconstruct", "scalar"]
"torch._utils" = ["_rebuild_tensor_v2"]
```

---

## Scanner Selection in CI

```yaml
# GitHub Actions — fast scan, fail on critical only
- name: Sentinel Artifact Scan
  run: |
    sentinel artifact ./models \
      --profile fast \
      --min-severity CRITICAL \
      --format sarif \
      --output sentinel.sarif

# Paranoid gate before production deploy
- name: Sentinel Full Scan
  run: |
    sentinel artifact ./models \
      --profile paranoid \
      --format json \
      --output sentinel-full.json
    sentinel check-threshold sentinel-full.json --max-critical 0
```

---

## Scanner IDs Reference

| Scanner ID | Handles |
|-----------|---------|
| `pickle` | `.pkl` `.pickle` `.p` `.dill` `.dat` `.data` |
| `pytorch` | `.pt` `.pth` `.bin` `.ckpt` |
| `torchscript` | TorchScript ZIP archives |
| `torchserve` | `.mar` |
| `keras` | `.keras` |
| `h5` | `.h5` `.hdf5` |
| `tensorflow` | `.pb` `.meta` SavedModel dirs |
| `onnx` | `.onnx` |
| `safetensors` | `.safetensors` |
| `gguf` | `.gguf` `.ggml` `.ggmf` `.ggjt` `.ggla` `.ggsa` |
| `tflite` | `.tflite` |
| `jax` | `.jax` `.checkpoint` `.orbax` `.msgpack` |
| `numpy` | `.npy` `.npz` |
| `skops` | `.skops` |
| `cntk` | `.dnn` `.cmf` |
| `catboost` | `.cbm` |
| `xgboost` | `.bst` `.model` |
| `lightgbm` | `.lgb` `.lightgbm` |
| `coreml` | `.mlmodel` `.mlpackage` |
| `mxnet` | `*-symbol.json` `*.params` |
| `nemo` | `.nemo` |
| `rknn` | `.rknn` |
| `paddle` | `.pdmodel` `.pdiparams` |
| `openvino` | `.xml` |
| `r_serialized` | `.rds` `.rda` `.rdata` |
| `llamafile` | `.llamafile` |
| `pmml` | `.pmml` |
| `zip` | `.zip` `.npz` (container) |
| `tar` | `.tar` `.tar.gz` `.tgz` `.tbz2` (container) |
| `sevenz` | `.7z` (container) |
| `rar` | `.rar` (fail-closed detection) |
| `manifest` | `config.json` `tokenizer.json` manifests |
| `yaml_scanner` | `.yaml` `.yml` config files |
| `jinja2` | `.j2` `.jinja` `.jinja2` |
| `weight_distribution` | `.pt` `.pth` `.safetensors` (heuristic) |
| `watermark` | `.pt` `.safetensors` (heuristic) |
| `entropy` | Any file (entropy analysis) |
