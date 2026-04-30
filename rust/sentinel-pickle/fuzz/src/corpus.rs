// fuzz/src/corpus.rs — Minimal valid corpus seeds for each format

/// Minimal valid pickle (proto 2, push None, STOP).
pub const PICKLE_SEED: &[u8] = &[0x80, 0x02, b'N', b'.'];

/// Minimal safetensors header.
pub const SAFETENSORS_SEED: &[u8] = b"\x02\x00\x00\x00\x00\x00\x00\x00{}";

/// Minimal numpy .npy.
pub const NUMPY_SEED: &[u8] = b"\x93NUMPY\x01\x00\x76\x00{'descr': '<f4', 'fortran_order': False, 'shape': (1,), }";

/// Minimal GGUF v3 header (magic + version + 0 tensors + 0 KV).
pub const GGUF_SEED: &[u8] = &[
    b'G', b'G', b'U', b'F',
    0x03, 0x00, 0x00, 0x00, // version 3
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // tensor_count = 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // kv_count = 0
];

/// Minimal tokenizer.json.
pub const TOKENIZER_SEED: &[u8] = b"{\"version\":\"1.0\",\"added_tokens\":[]}";

/// Minimal MLflow MLmodel YAML.
pub const MLFLOW_YAML_SEED: &[u8] = b"artifact_path: model\nflavors:\n  python_function:\n    loader_module: mlflow.sklearn\n";

/// Minimal TorchScript data.pkl pickle.
pub const TORCHSCRIPT_PKL_SEED: &[u8] = &[0x80, 0x02, b'N', b'.'];

/// Minimal LoRA adapter_config.json.
pub const LORA_CONFIG_SEED: &[u8] = b"{\"r\":8,\"lora_alpha\":16,\"target_modules\":[\"q_proj\"]}";

/// Minimal Ollama Modelfile.
pub const OLLAMA_SEED: &[u8] = b"FROM llama2\nSYSTEM You are a helpful assistant.\n";

/// Minimal LlamaFile polyglot.
pub const LLAMAFILE_SEED: &[u8] = b"#!/bin/sh\nexec \"$0\"\n#GGUF\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

/// Minimal PaddlePaddle binary.
pub const PADDLE_SEED: &[u8] = b"paddle\x00\x00\x00\x00\x00";

/// Minimal Flax/JAX msgpack.
pub const FLAX_SEED: &[u8] = &[
    0x82, // fixmap with 2 entries
    0xA6, b'p', b'a', b'r', b'a', b'm', b's', // key "params"
    0x80, // fixmap with 0 entries
    0xA5, b's', b't', b'a', b't', b'e', // key "state"
    0x80, // fixmap with 0 entries
];

/// All seeds as (name, bytes) for corpus directory generation.
pub fn all_seeds() -> Vec<(&'static str, &'static [u8])> {
    vec![
        ("pickle.pkl", PICKLE_SEED),
        ("safetensors.safetensors", SAFETENSORS_SEED),
        ("numpy.npy", NUMPY_SEED),
        ("gguf.gguf", GGUF_SEED),
        ("tokenizer.json", TOKENIZER_SEED),
        ("mlmodel.yaml", MLFLOW_YAML_SEED),
        ("data.pkl", TORCHSCRIPT_PKL_SEED),
        ("adapter_config.json", LORA_CONFIG_SEED),
        ("Modelfile", OLLAMA_SEED),
        ("llamafile", LLAMAFILE_SEED),
        ("paddle.pdparams", PADDLE_SEED),
        ("flax.msgpack", FLAX_SEED),
    ]
}
