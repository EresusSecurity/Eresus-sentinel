// fuzz_all_formats.rs — Multi-format ML model file fuzzer
//
// This target feeds arbitrary bytes to every format scanner Eresus
// Sentinel supports:  pickle, safetensors, numpy, GGUF, ONNX, HDF5,
// plus the 8 newer formats: MLflow ZIP, TorchScript ZIP, LoRA adapter,
// Tokenizer JSON, Ollama Modelfile, LlamaFile polyglot, Paddle, Flax.
//
// For each format we verify:
//   1. No panic (the invariant libFuzzer enforces automatically).
//   2. scan_data() returns a Vec<Finding> (never Err on raw bytes).
//   3. Every returned Finding has a non-empty rule_id.
//   4. confidence values are within [0.0, 1.0].
//
// Run with:
//   cargo +nightly fuzz run fuzz_all_formats -- -max_len=65536

#![no_main]

use libfuzzer_sys::fuzz_target;
use sentinel_pickle::scanner::{scan_data};
use sentinel_pickle::policy::ScanPolicy;

// ── Minimal magic-byte prefixes for each format ──────────────────────
const PICKLE_PROTOS: &[&[u8]] = &[
    &[0x80, 0x02],  // proto 2
    &[0x80, 0x04],  // proto 4
    &[0x80, 0x05],  // proto 5
    b"\x80\x00",    // proto 0 (text)
];

// SafeTensors: JSON length prefix (8-byte little-endian u64) + JSON body
const SAFETENSORS_PREFIX: &[u8] = b"\x08\x00\x00\x00\x00\x00\x00\x00{";

// NumPy .npy magic
const NUMPY_MAGIC: &[u8] = b"\x93NUMPY";

// GGUF magic
const GGUF_MAGIC: &[u8] = b"GGUF";

// ONNX — Protocol Buffers (field 1, wire type 2 = LEN, tag 0x0a)
const ONNX_PREFIX: &[u8] = &[0x0A];

// HDF5 signature
const HDF5_MAGIC: &[u8] = b"\x89HDF\r\n\x1a\n";

// ── New format prefixes ─────────────────────────────────────────────

// ZIP local file header (used by MLflow, TorchScript, LoRA adapter)
const ZIP_MAGIC: &[u8] = b"PK\x03\x04";

// Tokenizer JSON — starts with '{'
const JSON_PREFIX: &[u8] = b"{";

// Ollama Modelfile — starts with "FROM "
const OLLAMA_PREFIX: &[u8] = b"FROM ";

// LlamaFile polyglot — shell script header + GGUF
const LLAMAFILE_PREFIX: &[u8] = b"#!/bin/sh\n";

// PaddlePaddle binary — "paddle\0"
const PADDLE_PREFIX: &[u8] = b"paddle\x00";

// Flax/JAX msgpack — fixmap marker
const MSGPACK_FIXMAP: &[u8] = &[0x82];

fuzz_target!(|data: &[u8]| {
    let policy = ScanPolicy::new(false);

    // ── 1. Raw pickle ────────────────────────────────────────────────
    for proto_prefix in PICKLE_PROTOS {
        let mut pkl = proto_prefix.to_vec();
        pkl.extend_from_slice(data);
        pkl.push(b'.');  // STOP opcode
        let findings = scan_data(&pkl, &policy);
        assert_findings_valid(&findings);
    }

    // ── 2. SafeTensors ──────────────────────────────────────────────
    {
        let mut st = SAFETENSORS_PREFIX.to_vec();
        st.extend_from_slice(data);
        let findings = scan_data(&st, &policy);
        assert_findings_valid(&findings);
    }

    // ── 3. NumPy .npy ───────────────────────────────────────────────
    {
        let mut npy = NUMPY_MAGIC.to_vec();
        npy.extend_from_slice(data);
        let findings = scan_data(&npy, &policy);
        assert_findings_valid(&findings);
    }

    // ── 4. GGUF ─────────────────────────────────────────────────────
    {
        let mut gguf = GGUF_MAGIC.to_vec();
        gguf.extend_from_slice(data);
        let findings = scan_data(&gguf, &policy);
        assert_findings_valid(&findings);
    }

    // ── 5. ONNX (raw proto bytes) ───────────────────────────────────
    {
        let mut onnx = ONNX_PREFIX.to_vec();
        onnx.extend_from_slice(data);
        let findings = scan_data(&onnx, &policy);
        assert_findings_valid(&findings);
    }

    // ── 6. HDF5 ─────────────────────────────────────────────────────
    {
        let mut h5 = HDF5_MAGIC.to_vec();
        h5.extend_from_slice(data);
        let findings = scan_data(&h5, &policy);
        assert_findings_valid(&findings);
    }

    // ── 7. MLflow / TorchScript / LoRA adapter (ZIP containers) ─────
    // All three are ZIP-based; the scanner must handle arbitrary ZIP
    // payloads without panicking even when entries are truncated.
    {
        let mut zip = ZIP_MAGIC.to_vec();
        zip.extend_from_slice(data);
        let findings = scan_data(&zip, &policy);
        assert_findings_valid(&findings);
    }

    // ── 8. Tokenizer JSON ───────────────────────────────────────────
    {
        let mut tok = JSON_PREFIX.to_vec();
        tok.extend_from_slice(data);
        // Close as valid-ish JSON
        tok.push(b'}');
        let findings = scan_data(&tok, &policy);
        assert_findings_valid(&findings);
    }

    // ── 9. Ollama Modelfile ─────────────────────────────────────────
    {
        let mut mf = OLLAMA_PREFIX.to_vec();
        mf.extend_from_slice(data);
        let findings = scan_data(&mf, &policy);
        assert_findings_valid(&findings);
    }

    // ── 10. LlamaFile polyglot (shell + GGUF) ───────────────────────
    {
        let mut lf = LLAMAFILE_PREFIX.to_vec();
        lf.extend_from_slice(b"exec \"$0\"\n#");
        lf.extend_from_slice(GGUF_MAGIC);
        lf.extend_from_slice(data);
        let findings = scan_data(&lf, &policy);
        assert_findings_valid(&findings);
    }

    // ── 11. PaddlePaddle binary ─────────────────────────────────────
    {
        let mut pd = PADDLE_PREFIX.to_vec();
        pd.extend_from_slice(data);
        let findings = scan_data(&pd, &policy);
        assert_findings_valid(&findings);
    }

    // ── 12. Flax/JAX msgpack checkpoint ─────────────────────────────
    {
        let mut fl = MSGPACK_FIXMAP.to_vec();
        fl.extend_from_slice(data);
        let findings = scan_data(&fl, &policy);
        assert_findings_valid(&findings);
    }

    // ── 13. Bare fuzz data (no magic) — exercises fallback path ─────
    {
        let findings = scan_data(data, &policy);
        assert_findings_valid(&findings);
    }
});

/// Invariants every Finding must satisfy.
#[inline]
fn assert_findings_valid(findings: &[sentinel_pickle::report::Finding]) {
    for f in findings {
        // rule_id must be non-empty
        assert!(!f.rule_id.is_empty(), "Finding has empty rule_id");
        // description must be non-empty
        assert!(!f.description.is_empty(), "Finding has empty description");
        // confidence in [0.0, 1.0]
        assert!(
            f.confidence >= 0.0 && f.confidence <= 1.0,
            "confidence out of range: {}",
            f.confidence
        );
    }
}
