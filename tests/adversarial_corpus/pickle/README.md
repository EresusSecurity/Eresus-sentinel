# Pickle Adversarial Fuzzing Corpus

Coverage-guided seed corpus for fuzzing Sentinel's pickle scanner and the
underlying pickle deserialization stack.

## Seed Files

| File | Description |
|------|-------------|
| `seed_empty_bytes.pkl` | Empty input — triggers immediate parse failure |
| `seed_benign_list.pkl` | Valid protocol-2 pickle (list of mixed types) |
| `seed_benign_dict.pkl` | Valid protocol-4 pickle (nested dict) |
| `seed_rce_reduce.pkl` | `__reduce__` RCE gadget via `os.system` |
| `seed_subprocess_reduce.pkl` | `__reduce__` via `subprocess.check_output` |
| `seed_truncated.pkl` | Half-truncated pickle (corpus diversity) |
| `seed_global_opcode.pkl` | Raw `GLOBAL` opcode (`cos\nsystem\n`) |
| `seed_deep_nested.pkl` | 500-deep nested list (stack depth probe) |

## Running with Atheris (libFuzzer)

```bash
pip install atheris
python tests/adversarial_corpus/pickle/fuzz_pickle_scanner.py \
    -corpus=tests/adversarial_corpus/pickle/ \
    -max_total_time=60
```

## Running with pytest (regression/smoke)

```bash
pytest tests/test_pickle_corpus.py -v
```
