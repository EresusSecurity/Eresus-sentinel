// fuzz/src/builders.rs — Structure-aware format builders for fuzz targets
//
// Build minimally valid and adversarial format containers from fuzz data.
// Includes standard builders for all supported formats plus adversarial
// variants for security testing (ZIP slip, polyglot, overflow headers, etc.)

use std::io::{Cursor, Write};

// ── ZIP builders ─────────────────────────────────────────────────────

/// Build a ZIP file with given entries.
/// Each entry is (filename, content_bytes).
pub fn build_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let buf = Vec::new();
    let cursor = Cursor::new(buf);
    let mut writer = zip::ZipWriter::new(cursor);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored);

    for (name, content) in entries {
        if writer.start_file(*name, options).is_ok() {
            let _ = writer.write_all(content);
        }
    }

    match writer.finish() {
        Ok(cursor) => cursor.into_inner(),
        Err(_) => Vec::new(),
    }
}

/// Build a ZIP with deflate compression.
pub fn build_zip_deflated(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let buf = Vec::new();
    let cursor = Cursor::new(buf);
    let mut writer = zip::ZipWriter::new(cursor);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    for (name, content) in entries {
        if writer.start_file(*name, options).is_ok() {
            let _ = writer.write_all(content);
        }
    }

    match writer.finish() {
        Ok(cursor) => cursor.into_inner(),
        Err(_) => Vec::new(),
    }
}

// ── MLflow ───────────────────────────────────────────────────────────

/// Build an MLflow model ZIP with MLmodel YAML + model.pkl.
pub fn build_mlflow_zip(yaml_content: &[u8], pkl_content: &[u8]) -> Vec<u8> {
    build_zip(&[
        ("MLmodel", yaml_content),
        ("model.pkl", pkl_content),
    ])
}

/// Build an MLflow ZIP with extra files (conda.yaml, requirements.txt).
pub fn build_mlflow_full_zip(
    yaml_content: &[u8],
    pkl_content: &[u8],
    conda_yaml: &[u8],
    requirements: &[u8],
) -> Vec<u8> {
    build_zip(&[
        ("MLmodel", yaml_content),
        ("model.pkl", pkl_content),
        ("conda.yaml", conda_yaml),
        ("requirements.txt", requirements),
    ])
}

// ── TorchScript ──────────────────────────────────────────────────────

/// Build a TorchScript ZIP with archive/data.pkl + optional code files.
pub fn build_torchscript_zip(pkl_content: &[u8], code_content: &[u8]) -> Vec<u8> {
    build_zip(&[
        ("archive/data.pkl", pkl_content),
        ("archive/code/__torch__.py", code_content),
    ])
}

/// Build a TorchScript ZIP with constants.pkl + multiple code files.
pub fn build_torchscript_full_zip(
    data_pkl: &[u8],
    constants_pkl: &[u8],
    code: &[u8],
    extra_code: &[u8],
) -> Vec<u8> {
    build_zip(&[
        ("archive/data.pkl", data_pkl),
        ("archive/constants.pkl", constants_pkl),
        ("archive/code/__torch__.py", code),
        ("archive/code/__torch__/model.py", extra_code),
    ])
}

// ── LoRA adapter ─────────────────────────────────────────────────────

/// Build a LoRA adapter ZIP with adapter_config.json + adapter_model.safetensors.
pub fn build_lora_zip(config_json: &[u8], safetensors_content: &[u8]) -> Vec<u8> {
    build_zip(&[
        ("adapter_config.json", config_json),
        ("adapter_model.safetensors", safetensors_content),
    ])
}

// ── Ollama Modelfile ─────────────────────────────────────────────────

/// Build an Ollama Modelfile with injected content.
pub fn build_ollama_modelfile(
    model_name: &str,
    system_prompt: &str,
    template: &str,
) -> Vec<u8> {
    let mut buf = Vec::new();
    let _ = write!(buf, "FROM {}\n", model_name);
    if !system_prompt.is_empty() {
        let _ = write!(buf, "SYSTEM {}\n", system_prompt);
    }
    if !template.is_empty() {
        let _ = write!(buf, "TEMPLATE \"{}\"\n", template);
    }
    buf
}

/// Build a full Ollama Modelfile with all directives.
pub fn build_ollama_full_modelfile(
    model_name: &str,
    system_prompt: &str,
    template: &str,
    params: &[(&str, &str)],
    adapter: Option<&str>,
    license: Option<&str>,
) -> Vec<u8> {
    let mut buf = Vec::new();
    let _ = write!(buf, "FROM {}\n", model_name);
    if !system_prompt.is_empty() {
        let _ = write!(buf, "SYSTEM {}\n", system_prompt);
    }
    if !template.is_empty() {
        let _ = write!(buf, "TEMPLATE \"{}\"\n", template);
    }
    for (key, val) in params {
        let _ = write!(buf, "PARAMETER {} {}\n", key, val);
    }
    if let Some(a) = adapter {
        let _ = write!(buf, "ADAPTER {}\n", a);
    }
    if let Some(l) = license {
        let _ = write!(buf, "LICENSE \"{}\"\n", l);
    }
    buf
}

// ── LlamaFile polyglot ──────────────────────────────────────────────

/// Build a LlamaFile polyglot (shell script + GGUF body).
pub fn build_llamafile(shell_script: &[u8], gguf_body: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(shell_script.len() + gguf_body.len() + 32);
    buf.extend_from_slice(b"#!/bin/sh\n");
    buf.extend_from_slice(shell_script);
    buf.push(b'\n');
    buf.extend_from_slice(b"GGUF");
    buf.extend_from_slice(gguf_body);
    buf
}

/// Build a LlamaFile with a valid GGUF v3 header after the shell script.
pub fn build_llamafile_with_gguf_header(
    shell_script: &[u8],
    tensor_count: u64,
    kv_count: u64,
    body: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(shell_script.len() + body.len() + 48);
    buf.extend_from_slice(b"#!/bin/sh\n");
    buf.extend_from_slice(shell_script);
    buf.push(b'\n');
    buf.extend_from_slice(b"GGUF");
    buf.extend_from_slice(&3u32.to_le_bytes()); // version 3
    buf.extend_from_slice(&tensor_count.to_le_bytes());
    buf.extend_from_slice(&kv_count.to_le_bytes());
    buf.extend_from_slice(body);
    buf
}

// ── PaddlePaddle ────────────────────────────────────────────────────

/// Build a minimal PaddlePaddle binary with magic + fuzz data.
pub fn build_paddle_binary(fuzz_data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(fuzz_data.len() + 7);
    buf.extend_from_slice(b"paddle\x00");
    buf.extend_from_slice(fuzz_data);
    buf
}

/// Build a Paddle binary with embedded pickle payload.
pub fn build_paddle_with_pickle(proto: u8, pkl_body: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(pkl_body.len() + 16);
    buf.extend_from_slice(b"paddle\x00");
    if proto >= 2 {
        buf.extend_from_slice(&[0x80, proto]);
    }
    buf.extend_from_slice(pkl_body);
    buf.push(b'.'); // STOP
    buf
}

// ── Flax/JAX msgpack ────────────────────────────────────────────────

/// Build a minimal Flax/JAX msgpack checkpoint (fixmap + fuzz data).
pub fn build_flax_msgpack(fuzz_data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(fuzz_data.len() + 1);
    buf.push(0x82); // fixmap with 2 entries
    buf.extend_from_slice(fuzz_data);
    buf
}

/// Build a Flax checkpoint with named params and embedded pickle.
pub fn build_flax_with_pickle(proto: u8, pkl_body: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(pkl_body.len() + 32);
    buf.push(0x82); // fixmap with 2 entries
    buf.push(0xA6); // fixstr(6)
    buf.extend_from_slice(b"params");
    if proto >= 2 {
        buf.extend_from_slice(&[0x80, proto]);
    }
    buf.extend_from_slice(pkl_body);
    buf.push(b'.'); // STOP
    buf.push(0xA5); // fixstr(5)
    buf.extend_from_slice(b"state");
    buf.push(0xC0); // nil
    buf
}

// ── Adversarial pickle payloads ─────────────────────────────────────

/// Build a dangerous pickle payload with GLOBAL os.system.
pub fn build_evil_pickle(proto: u8) -> Vec<u8> {
    let mut buf = Vec::new();
    if proto >= 2 {
        buf.extend_from_slice(&[0x80, proto]);
    }
    buf.push(b'c'); // GLOBAL
    buf.extend_from_slice(b"os\nsystem\n");
    buf.push(0x8c); // SHORT_BINUNICODE
    buf.push(2);
    buf.extend_from_slice(b"id");
    buf.push(0x85); // TUPLE1
    buf.push(b'R'); // REDUCE
    buf.push(b'.'); // STOP
    buf
}

/// Build a pickle with multiple dangerous globals.
pub fn build_multi_evil_pickle(proto: u8) -> Vec<u8> {
    let mut buf = Vec::new();
    if proto >= 2 {
        buf.extend_from_slice(&[0x80, proto]);
    }
    // os.system
    buf.push(b'c');
    buf.extend_from_slice(b"os\nsystem\n");
    buf.push(0x8c); buf.push(2); buf.extend_from_slice(b"id");
    buf.push(0x85); buf.push(b'R');
    buf.push(b'0'); // POP

    // subprocess.Popen
    buf.push(b'c');
    buf.extend_from_slice(b"subprocess\nPopen\n");
    buf.push(0x8c); buf.push(6); buf.extend_from_slice(b"whoami");
    buf.push(0x85); buf.push(b'R');
    buf.push(b'0'); // POP

    // builtins.eval
    buf.push(b'c');
    buf.extend_from_slice(b"builtins\neval\n");
    buf.push(0x8c); buf.push(10); buf.extend_from_slice(b"print('hi')");
    buf.push(0x85); buf.push(b'R');

    buf.push(b'.'); // STOP
    buf
}

/// Build a benign pickle (push None, STOP).
pub fn build_benign_pickle(proto: u8) -> Vec<u8> {
    let mut buf = Vec::new();
    if proto >= 2 {
        buf.extend_from_slice(&[0x80, proto]);
    }
    buf.push(b'N'); // NONE
    buf.push(b'.'); // STOP
    buf
}

// ── SafeTensors ─────────────────────────────────────────────────────

/// Build a safetensors header with given JSON content.
pub fn build_safetensors(header_json: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(header_json.len() + 8);
    buf.extend_from_slice(&(header_json.len() as u64).to_le_bytes());
    buf.extend_from_slice(header_json);
    buf
}

/// Build a GGUF v3 header with given counts.
pub fn build_gguf_header(version: u32, tensor_count: u64, kv_count: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(24);
    buf.extend_from_slice(b"GGUF");
    buf.extend_from_slice(&version.to_le_bytes());
    buf.extend_from_slice(&tensor_count.to_le_bytes());
    buf.extend_from_slice(&kv_count.to_le_bytes());
    buf
}
