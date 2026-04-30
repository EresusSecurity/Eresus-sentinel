# sentinel-pickle — cargo-fuzz Targets

This directory contains [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) targets for the `sentinel-pickle` Rust crate.
All targets use [libFuzzer](https://llvm.org/docs/LibFuzzer.html) and require a nightly toolchain.

## Quick Start

```bash
# Install cargo-fuzz (once)
cargo install cargo-fuzz

# Run any target (from the crate root, not this directory)
cd rust/sentinel-pickle

# Generic byte-level scanner fuzzer
cargo +nightly fuzz run fuzz_scanner -- -max_len=65536

# Differential checker: Rust vs Python pickletools
cargo +nightly fuzz run fuzz_differential -- -max_len=2048

# Structured opcode-sequence fuzzer
cargo +nightly fuzz run fuzz_opcode_sequence -- -max_len=8192

# Policy engine edge-case fuzzer
cargo +nightly fuzz run fuzz_policy -- -max_len=256
```

## Targets

| Target | File | Purpose |
|--------|------|---------|
| `fuzz_scanner` | `fuzz_targets/fuzz_scanner.rs` | Generic raw-byte fuzzer — exercises `scan_data_with_stats()` with arbitrary bytes and verifies structural invariants |
| `fuzz_differential` | `fuzz_targets/fuzz_differential.rs` | Differential tester — compares Rust scanner output against Python `pickletools.genops()` to catch false negatives on dangerous opcodes |
| `fuzz_opcode_sequence` | `fuzz_targets/fuzz_opcode_sequence.rs` | Structured fuzzer — generates syntactically valid pickle streams from a typed `PickleOp` enum to maximise opcode-level coverage |
| `fuzz_policy` | `fuzz_targets/fuzz_policy.rs` | Policy engine fuzzer — generates arbitrary (module, name) pairs and verifies that known-dangerous entries are never downgraded to `Safe` |
| `fuzz_all_formats` | `fuzz_targets/fuzz_all_formats.rs` | Multi-format fuzzer — feeds arbitrary bytes with 13 different format magic prefixes (pickle, safetensors, numpy, GGUF, ONNX, HDF5, ZIP/MLflow/TorchScript/LoRA, tokenizer JSON, Ollama, LlamaFile, Paddle, Flax msgpack) |

## Invariants Checked

### `fuzz_scanner`
1. All returned findings have non-empty `rule_id` and `severity` fields.
2. `stats.max_stack_depth ≤ MAX_STACK_DEPTH` (4 096) — the depth guard is always respected.
3. If `stats.aborted == true`, then `stats.opcode_count ≥ MAX_OPCODE_COUNT` (1 000 000).
4. Strict mode produces ≥ as many findings as non-strict mode for the same input.

### `fuzz_differential`
- For inputs containing known-dangerous opcodes (`GLOBAL`/`INST`/`STACK_GLOBAL` with modules like `os`, `subprocess`, `ctypes` etc.), the Rust scanner must return at least one `HIGH`/`CRITICAL` finding.

### `fuzz_opcode_sequence`
1. No panics (implicit).
2. All findings are well-formed (non-empty `rule_id`).
3. `stats.max_stack_depth ≤ MAX_STACK_DEPTH`.

### `fuzz_policy`
1. Any member of `ALWAYS_DANGEROUS_PAIRS` must never evaluate to `Safe`.
2. Arbitrary `(module, name)` pairs must not cause panics.
3. Empty `("", "")` must never evaluate to `Dangerous`.
4. Explicitly allowed entries must not evaluate to `Dangerous`.

## Corpus Management

Seed corpus files live under `corpus/<target>/`. To add a seed:

```bash
# Add an existing .pkl file as a seed for fuzz_scanner
cp /path/to/payload.pkl fuzz/corpus/fuzz_scanner/

# The adversarial corpus in tests/ can be linked in
ls ../../tests/adversarial_corpus/pickle/*.pkl | xargs -I{} cp {} fuzz/corpus/fuzz_scanner/
```

## Reproducing Crashes

cargo-fuzz writes crash inputs to `artifacts/<target>/`. Replay with:

```bash
cargo +nightly fuzz run fuzz_scanner fuzz/artifacts/fuzz_scanner/crash-<hash>
```

Or with the standard binary:

```bash
cargo +nightly fuzz run fuzz_scanner -- fuzz/artifacts/fuzz_scanner/crash-<hash>
```

## CI Integration

The `make fuzz-ci` target (see project `Makefile`) runs each fuzzer for 60 s in CI using a pre-built corpus.  Long fuzzing runs are done locally or on dedicated fuzz infrastructure.

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1` | Required when the system Python ≥ 3.14 (PyO3 stable ABI workaround) |
| `RUST_LOG=debug` | Enable verbose scanner logging |

## Building Without Running

```bash
# Just compile (no fuzzing)
PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1 cargo +nightly fuzz build fuzz_scanner
```
