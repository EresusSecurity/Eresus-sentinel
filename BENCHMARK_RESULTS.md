# Eresus Sentinel — Benchmark Results

**Date:** 2025-04-21
**Corpus:** `tests/adversarial_corpus/` (22 samples: 4 benign, 18 malicious)
**Scanner version:** post-picklescan integration

---

## Headline Numbers

| Metric | Value |
|--------|-------|
| **Samples** | 22 |
| **Crashes** | 0 |
| **Timeouts** | 0 |
| **Latency p50 / p95 / max** | 0.74 ms / 228.6 ms / 9912 ms |

## Overall

| TP | FP | TN | FN | Precision | Recall | F1 |
|----|----|----|----|-----------|---------|----|
| 13 | 3  | 2  | 4  | 0.8125    | 0.7647  | 0.7879 |

## Critical Subset (malicious samples only)

| n  | TP | FP | FN | Precision | Recall | F1 |
|----|----|----|----|-----------|---------|----|
| 15 | 13 | 0  | 2  | 1.0       | 0.8667  | 0.9286 |

---

## Per-Category Breakdown

| Category | n | TP | FP | FN | Precision | Recall | F1 |
|----------|---|----|----|----|-----------|---------|----|
| archive  | 3 | 0  | 0  | 3  | 0.0       | 0.0     | 0.0 |
| gguf     | 1 | 1  | 0  | 0  | 1.0       | 1.0     | 1.0 |
| mcp      | 5 | 3  | 2  | 0  | 0.6       | 1.0     | 0.75 |
| pickle   | 4 | 2  | 0  | 1  | 1.0       | 0.667   | 0.80 |
| polyglot | 1 | 1  | 0  | 0  | 1.0       | 1.0     | 1.0 |
| prompt   | 5 | 4  | 1  | 0  | 0.8       | 1.0     | 0.89 |
| skill    | 2 | 1  | 0  | 0  | 1.0       | 1.0     | 1.0 |
| yaml     | 1 | 1  | 0  | 0  | 1.0       | 1.0     | 1.0 |

---

## Changes in This Release

### Critical Security Fix

**Allowlist/blocklist conflict** — `functools.partial`, `operator.attrgetter`,
and `operator.itemgetter` were present in BOTH the blocklist and the allowlist.
Since the allowlist takes priority, these dangerous functions were silently
**allowed** despite being known RCE vectors:

- `functools.partial(os.system, "echo pwned")` → RCE
- `operator.attrgetter("system")(__import__("os"))("echo pwned")` → RCE
- `operator.itemgetter` → data exfiltration chain

Also removed `ast.literal_eval`, `ast.parse`, and `platform.*` from the
allowlist — these are blocklisted for good reason.

### New Features (from picklescan analysis)

1. **Multi-pickle scanning loop** — The pickle scanner now iterates through
   concatenated pickle streams (STOP → next PROTO) instead of a single
   `genops()` call.  This is essential for PyTorch files which serialise a
   magic-number pickle followed by several data pickles.

2. **Partial-pickle error recovery** — When `genops()` fails midway, any
   globals already extracted are still analysed (previously only raw byte
   scan ran).  This catches malicious truncated pickles that embed dangerous
   imports before the corrupted section.

3. **PyTorch magic-number bypass detection** — Old-format PyTorch files
   start with a pickle containing just the magic integer.  If that first
   pickle contains GLOBAL/INST opcodes, the magic was produced via
   `eval()` or `exec()` — a confirmed RCE bypass.  New rule: `TORCH-018`.

4. **Extended blocklist** — Added entries from picklescan's GHSA-driven
   unsafe_globals: `builtins.apply`, `__builtin__.apply`,
   `__builtin__.getattr`, `code.InteractiveInterpreter.runcode`.

5. **Severity upgrades** — `partial`, `attrgetter`, `methodcaller` added to
   `_CRITICAL_NAMES` for CRITICAL severity classification.

---

## Remaining Blind Spots

| Sample | Expected | Status |
|--------|----------|--------|
| `pickle_build_setstate_gadget.pkl` | ARTIFACT-001 | `__setstate__` gadget not traced |
| `zipbomb_lied_size.zip` | ARCHSLIP-002/022 | Declared vs actual size mismatch not checked |
| `nested_archive.tar.gz` | ARCHSLIP-004 | TAR-in-archive not recursed |
| `torchscript_code_payload.zip` | ARTIFACT-001 | TorchScript IR in ZIP not routed to scanner |

## Remaining False Positives

| Sample | Emitted | Reason |
|--------|---------|--------|
| `benign/prompt_safe_technical.txt` | FIREWALL-INPUT-100 | Heuristic ML model FP on technical prose |
| `benign/mcp_benign_calculator.json` | MCP-020 ×2 | Schema hygiene warnings on benign tool |
| `malicious/mcp_negated_keyword.json` | MCP-020 | Residual auth-check FP after negation guard |
