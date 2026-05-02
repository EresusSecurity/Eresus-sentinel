# Rule Authoring Guide

Sentinel rules live in `rules/*.yaml` and are loaded through `sentinel.rules`.
Prefer YAML rules over new hardcoded regex. Use Python only when a rule needs
parsing, binary decoding, protocol state, or cross-file analysis.

## Rule Shape

```yaml
- id: SAST-EXAMPLE-001
  name: unsafe eval
  pattern: "\\beval\\s*\\("
  severity: HIGH
  description: "Dynamic code execution from untrusted input."
  cwe_ids: ["CWE-95"]
  fix_hint: "Replace eval with ast.literal_eval or an explicit parser."
  fp_risk: MEDIUM
```

## Requirements

- Use stable `id` values; never recycle an ID for different behavior.
- Include `severity`, `description`, and remediation or `fix_hint`.
- Keep regex bounded. Avoid nested greedy groups that can produce ReDoS.
- Add one positive and one negative fixture for new high-risk rules.
- Run `sentinel rules test RULE_ID -f json` before committing.

## False Positive Hygiene

- Prefer specific context over broad keywords.
- Add benign fixtures for operational words like `ignore`, `bypass`, `token`,
  `shell`, and `network`.
- Put allowlists in rule metadata or scanner policy, not in reporter code.
