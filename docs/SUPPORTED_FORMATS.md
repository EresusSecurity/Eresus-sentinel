# Sentinel — Desteklenen Yapay Zeka Model Formatları

Sentinel **39 scanner** ile **75+ dosya uzantısını** tarar.  
Her scanner kendi tehdit kategorisini kontrol eder (RCE, SSTI, enjeksiyon, DoS, supply-chain vb.)

---

## Tam Format Listesi

| # | Scanner Anahtarı | Uzantılar | Scanner Sınıfı | Tehdit Kategorileri |
|---|-----------------|-----------|----------------|---------------------|
| 1 | `pickle` | `.pkl` `.pickle` `.p` `.dill` `.dat` `.data` `.joblib` | `PickleScanner` | RCE (pickle opcode), `__reduce__` override, protocol 0-5, importlib bypass |
| 2 | `torch` | `.pt` `.pth` `.bin` `.ckpt` | `TorchScanner` | `torch.load` unsafe pickle, checkpoint backdoor, weights poisoning |
| 3 | `safetensors` | `.safetensors` | `SafetensorsValidator` | Header overflow (DoS), SSTI, prompt injection in `__metadata__`, path traversal in tensor name |
| 4 | `gguf` | `.gguf` `.ggml` `.ggmf` `.ggjt` `.ggla` `.ggsa` | `GGUFAnalyzer` | Magic byte tampering, KV count overflow, SSTI in `chat_template`, prompt injection, n_kv flood |
| 5 | `tensorflow` | `.pb` | `TensorFlowScanner` | Arbitrary op execution via SavedModel, XLA injection |
| 6 | `tf_metagraph` | `.meta` | `TFMetaGraphScanner` | MetaGraph checkpoint tampering, saver backdoor |
| 7 | `torchscript` | `.torchscript` `.ptc` | `TorchScriptScanner` | `torch.jit.load` RCE, embedded Python bytecode, GLOBAL opcode via ZIP |
| 8 | `tflite` | `.tflite` | `TFLiteScanner` | FlatBuffer overflow, delegate injection, op misuse |
| 9 | `torchmobile` | `.ptl` | `TorchMobileScanner` | Mobile bundle pickle RCE, ZIP slip |
| 10 | `llamafile` | `.llamafile` `.exe` | `LlamaFileScanner` | Polyglot ZIP+ELF abuse, embedded payload, arbitrary code |
| 11 | `onnx` | `.onnx` | `ONNXScanner` | Protobuf overflow, custom op injection, graph loop DoS (500+ nodes) |
| 12 | `keras` | `.keras` `.h5` `.hdf5` | `KerasScanner` | HDF5 magic bypass, lambda layer RCE, custom object deserialization |
| 13 | `xgboost` | `.xgb` `.bst` `.ubj` `.model` | `XGBoostScanner` | Binary format tampering, JSON model backdoor |
| 14 | `numpy` | `.npy` `.npz` | `NumpyScanner` | NPZ-embedded pickle payload, `allow_pickle=True` RCE |
| 15 | `archive` | `.zip` `.tar` `.tar.gz` `.tgz` `.tar.bz2` `.tbz2` `.tar.xz` `.txz` | `ArchiveSlipDetector` | ZIP slip (path traversal `../`), ZIP bomb (billion laughs), symlink escape |
| 16 | `7z` | `.7z` | `SevenZipScanner` | Archive slip, encrypted bomb, nested extraction DoS |
| 17 | `yaml` | `.yaml` `.yml` | `YamlScanner` | `!!python/object` unsafe deserialization, reverse shell in values, anchor bomb (YAML billion laughs), merge-key injection, **prompt injection** |
| 18 | `catboost` | `.cbm` | `CatBoostScanner` | Binary format anomaly, embedded script |
| 19 | `coreml` | `.mlmodel` `.mlpackage` | `CoreMLScanner` | Custom layer Python exec, NeuralNetwork op injection |
| 20 | `flax` | `.msgpack` `.orbax` `.flax` `.jax` `.checkpoint` `.orbax-checkpoint` | `FlaxScanner` | MessagePack arbitrary object, JAX checkpoint pickle bypass |
| 21 | `lightgbm` | `.lgb` `.lightgbm` | `LightGBMScanner` | Binary model tampering, feature name injection |
| 22 | `mxnet` | `-symbol.json` `.params` | `MXNetScanner` | Symbol JSON code injection, parameter file RCE |
| 23 | `nemo` | `.nemo` | `NeMoScanner` | ZIP-based NeMo archive slip, embedded Jinja2/pickle |
| 24 | `openvino` | `.xml` | `OpenVINOScanner` | IR XML injection, XXE (XML External Entity), op string eval |
| 25 | `paddle` | `.pdmodel` `.pdiparams` `.pdparams` | `PaddleScanner` | Protobuf tampering, custom C++ op injection |
| 26 | `pmml` | `.pmml` | `PMMLScanner` | PMML Extension element code exec, XPath injection |
| 27 | `rknn` | `.rknn` | `RKNNScanner` | Binary format overflow, embedded model integrity |
| 28 | `cntk` | `.dnn` `.cmf` | `CNTKScanner` | Legacy format tampering, deserializable function nodes |
| 29 | `r-serialized` | `.rds` `.rda` `.rdata` | `RSerializedScanner` | R object deserialization RCE (`unserialize`), .GlobalEnv poisoning |
| 30 | `skops` | `.skops` | `SkopsScanner` | sklearn object deserialization, `__reduce__` via joblib backend |
| 31 | `torchserve` | `.mar` | `TorchServeScanner` | MAR archive slip, handler code injection, model store SSRF |
| 32 | `torch7` | `.t7` `.th` `.net` | `Torch7Scanner` | Legacy Lua serialization RCE, Torch7 class abuse |
| 33 | `rar` | `.rar` | `RARScanner` | Archive slip, encrypted payload, DoS via deep nesting |
| 34 | `compressed` | `.gz` `.bz2` `.xz` `.lz4` `.zlib` | `CompressedWrapperScanner` | Decompression bomb, nested format bypass (compressed pickle) |
| 35 | `executorch` | `.pte` | `ExecuTorchScanner` | ExecuTorch flatbuffer overflow, operator set injection |
| 36 | `tensorrt` | `.engine` `.plan` `.trt` | `TensorRTScanner` | Serialized engine tampering, custom plugin RCE |
| 37 | `oci` | `.oci` `.manifest` | `OCIScanner` | OCI image manifest poisoning, layer digest bypass, supply-chain injection |
| 38 | `jinja2` | `.jinja` `.jinja2` `.j2` `.template` | `Jinja2InjectionScanner` | SSTI (CVE-2024-34359), `__subclasses__` MRO bypass, `cycler`/`joiner`/`namespace`/`lipsum` globals, `attr()` filter bypass, unicode variable bypass, blind SSTI |
| 39 | `mlmanifest` | `.json` | `MLManifestScanner` | `auto_map` backdoor, `chat_template` SSTI, `tokenizer_class` injection, model card prompt injection |

---

## HuggingFace'den İndirilen Gerçek Dosyalar (Phase AE)

Phase AE testi aşağıdaki gerçek model dosyalarını HF'den indirip tarar:

| Format | Model / Repo | Dosya | Boyut |
|--------|-------------|-------|-------|
| `.safetensors` | `hf-internal-testing/tiny-random-bert` | `model.safetensors` | ~508 KB |
| `.bin` (PyTorch) | `hf-internal-testing/tiny-random-bert` | `pytorch_model.bin` | ~527 KB |
| `.onnx` | `hf-internal-testing/tiny-random-bert` | `onnx/model.onnx` | ~439 KB |
| `.h5` (Keras/TF) | `hf-internal-testing/tiny-random-bert` | `tf_model.h5` | ~26 MB |
| `.gguf` | `ggml-org/models` | `tinyllamas/stories260K.gguf` | ~512 KB |
| `.json` config | `openai-community/gpt2` | `config.json` | ~665 B |
| `.json` tokenizer | `mistralai/Mistral-7B-Instruct-v0.1` | `tokenizer_config.json` | ~2 KB |
| `.tflite` | `nyadla-sys/whisper-tiny.en.tflite` | `dtln_quantized.tflite` | ~363 KB |
| `.xml` (OpenVINO) | `sentence-transformers/all-MiniLM-L6-v2` | `openvino/openvino_model.xml` | ~100 KB |
| `.skops` | `sklearn-lda/iris-lda` | `iris-lda.skops` | ~small |
| `.msgpack` (Flax) | `google-t5/t5-small` | `flax_model.msgpack` | ~242 MB |
| `.npy` / `.npz` | *(generated from gpt2 vocab)* | `real_vocab_ids.npy/npz` | <1 KB |
| `requirements.txt` | `huggingface/transformers` (GitHub) | `requirements.txt` | ~2 KB |

---

## Desteklenmeyen / Dışarıda Kalan Formatlar

Aşağıdaki formatlar için scanner **yok** (henüz):

| Format | Neden Yok |
|--------|-----------|
| `.pt2` (PyTorch 2 export) | ExecuTorch `.pte` ile örtüşüyor |
| `.safetensors.index.json` | JSON scanner kapsar |
| `.ipynb` | Notebook scanner ayrı (SAST pipeline) |
| `.gguf.part-*` | Fragment dosyalar; birleşik tarama gerektirir |
| `.bin.index.json` (sharded) | JSON scanner kapsar |

---

## Test Sonuçları (Son Çalışma)

```
TOTAL : 548+  |  PASS : 546+  |  FAIL : 2 (kabul edilmiş)
CRASH : 0     |  HANG : 0     |  FP   : 0  |  FN : 2
```

2 kalan FAIL: `JB-016`, `JB-018` — açık injection sinyali olmayan jailbreak
varyantları; firewall tarafından bilinçli geçirilmiştir.
