# Eresus Sentinel — FP/FN Benchmark Summary

- samples: 22
- crashes: 0
- timeouts: 0
- latency p50/p95/max (ms): 0.62 / 213.27 / 8360.83

## Overall
- TP=13 FP=3 TN=2 FN=4
- precision=0.8125 recall=0.7647 f1=0.7879

## Critical subset
- n=15 TP=13 FP=0 FN=2
- precision=1.0 recall=0.8667 f1=0.9286

## Per category
| category | n | tp | fp | fn | precision | recall | f1 |
|---|---|---|---|---|---|---|---|
| archive | 3 | 0 | 0 | 3 | 0.0 | 0.0 | 0.0 |
| gguf | 1 | 1 | 0 | 0 | 1.0 | 1.0 | 1.0 |
| mcp | 5 | 3 | 2 | 0 | 0.6 | 1.0 | 0.75 |
| pickle | 4 | 2 | 0 | 1 | 1.0 | 0.6667 | 0.8 |
| polyglot | 1 | 1 | 0 | 0 | 1.0 | 1.0 | 1.0 |
| prompt | 5 | 4 | 1 | 0 | 0.8 | 1.0 | 0.8889 |
| skill | 2 | 1 | 0 | 0 | 1.0 | 1.0 | 1.0 |
| yaml | 1 | 1 | 0 | 0 | 1.0 | 1.0 | 1.0 |

## Blind spots (expected detections that did NOT fire)
| sample | expected | got | crashed? | error |
|---|---|---|---|---|
| `malicious/pickle_build_setstate_gadget.pkl` | ARTIFACT-001 | — | no |  |
| `malicious/zipbomb_lied_size.zip` | ARCHSLIP-002,ARCHSLIP-022 | — | no |  |
| `malicious/nested_archive.tar.gz` | ARCHSLIP-004 | — | no |  |
| `malicious/torchscript_code_payload.zip` | ARTIFACT-001 | — | no |  |

## False positives on clean samples
| sample | emitted |
|---|---|
| `benign/prompt_safe_technical.txt` | FIREWALL-INPUT-100 |
| `benign/mcp_benign_calculator.json` | MCP-020,MCP-020 |
| `malicious/mcp_negated_keyword.json` | MCP-020 |
