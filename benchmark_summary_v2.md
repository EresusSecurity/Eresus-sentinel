# Eresus Sentinel — FP/FN Benchmark Summary

- samples: 22
- crashes: 0
- timeouts: 0
- latency p50/p95/max (ms): 0.66 / 224.96 / 9470.62

## Overall
- TP=7 FP=3 TN=2 FN=10
- precision=0.7 recall=0.4118 f1=0.5185

## Critical subset
- n=15 TP=7 FP=0 FN=8
- precision=1.0 recall=0.4667 f1=0.6364

## Per category
| category | n | tp | fp | fn | precision | recall | f1 |
|---|---|---|---|---|---|---|---|
| archive | 3 | 0 | 0 | 3 | 0.0 | 0.0 | 0.0 |
| gguf | 1 | 0 | 0 | 1 | 0.0 | 0.0 | 0.0 |
| mcp | 5 | 3 | 2 | 0 | 0.6 | 1.0 | 0.75 |
| pickle | 4 | 1 | 0 | 2 | 1.0 | 0.3333 | 0.5 |
| polyglot | 1 | 0 | 0 | 1 | 0.0 | 0.0 | 0.0 |
| prompt | 5 | 2 | 1 | 2 | 0.6667 | 0.5 | 0.5714 |
| skill | 2 | 0 | 0 | 1 | 0.0 | 0.0 | 0.0 |
| yaml | 1 | 1 | 0 | 0 | 1.0 | 1.0 | 1.0 |

## Blind spots (expected detections that did NOT fire)
| sample | expected | got | crashed? | error |
|---|---|---|---|---|
| `malicious/skill_manifest_indirect_injection.md` | SKILL-001 | SKILL-OVERBROAD_PERMISSIONS,SKILL-INVISIBLE_UNICODE_IN_FRONTMATTER,SKILL-SUSPICIOUS_LICENSE | no |  |
| `malicious/prompt_injection_homoglyph.txt` | FIREWALL-INPUT-003 | FIREWALL-INPUT-006 | no |  |
| `malicious/prompt_injection_base64.txt` | FIREWALL-INPUT-003 | FIREWALL-INPUT-005 | no |  |
| `malicious/pickle_copyreg_memo_indirection.pkl` | ARTIFACT-031,ARTIFACT-001 | ARTIFACT-099 | no |  |
| `malicious/pickle_build_setstate_gadget.pkl` | ARTIFACT-001 | — | no |  |
| `malicious/zipbomb_lied_size.zip` | ARCHSLIP-002,ARCHSLIP-022 | — | no |  |
| `malicious/nested_archive.tar.gz` | ARCHSLIP-004 | — | no |  |
| `malicious/polyglot_pickle_head.bin` | ARTIFACT-035,ARTIFACT-001 | TORCH-016 | no |  |
| `malicious/torchscript_code_payload.zip` | ARTIFACT-001 | — | no |  |
| `malicious/gguf_malicious_kv.gguf` | GGUF-SSTI | GGUF-030 | no |  |

## False positives on clean samples
| sample | emitted |
|---|---|
| `benign/prompt_safe_technical.txt` | FIREWALL-INPUT-100 |
| `benign/mcp_benign_calculator.json` | MCP-020,MCP-020,MCP-020 |
| `malicious/mcp_negated_keyword.json` | MCP-020,MCP-020,MCP-020 |
