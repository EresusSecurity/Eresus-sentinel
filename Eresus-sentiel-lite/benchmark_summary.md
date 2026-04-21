# Eresus Sentinel — FP/FN Benchmark Summary

- samples: 22
- crashes: 0
- timeouts: 0
- latency p50/p95/max (ms): 0.65 / 214.55 / 7123.44

## Overall
- TP=14 FP=3 TN=2 FN=3
- precision=0.8235 recall=0.8235 f1=0.8235

## Critical subset
- n=15 TP=14 FP=0 FN=1
- precision=1.0 recall=0.9333 f1=0.9655

## Per category
| category | n | tp | fp | fn | precision | recall | f1 |
|---|---|---|---|---|---|---|---|
| archive | 3 | 0 | 0 | 3 | 0.0 | 0.0 | 0.0 |
| gguf | 1 | 1 | 0 | 0 | 1.0 | 1.0 | 1.0 |
| mcp | 5 | 3 | 2 | 0 | 0.6 | 1.0 | 0.75 |
| pickle | 4 | 3 | 0 | 0 | 1.0 | 1.0 | 1.0 |
| polyglot | 1 | 1 | 0 | 0 | 1.0 | 1.0 | 1.0 |
| prompt | 5 | 4 | 1 | 0 | 0.8 | 1.0 | 0.8889 |
| skill | 2 | 1 | 0 | 0 | 1.0 | 1.0 | 1.0 |
| yaml | 1 | 1 | 0 | 0 | 1.0 | 1.0 | 1.0 |

## Blind spots (expected detections that did NOT fire)
| sample | expected | got | crashed? | error |
|---|---|---|---|---|
| `malicious/zipbomb_lied_size.zip` | ARCHSLIP-002,ARCHSLIP-022 | — | no |  |
| `malicious/nested_archive.tar.gz` | ARCHSLIP-004 | — | no |  |
| `malicious/torchscript_code_payload.zip` | ARTIFACT-001 | — | no |  |

## False positives on clean samples
| sample | emitted |
|---|---|
| `benign/prompt_safe_technical.txt` | FIREWALL-INPUT-100 |
| `benign/mcp_benign_calculator.json` | MCP-020,MCP-020 |
| `malicious/mcp_negated_keyword.json` | MCP-020 |
