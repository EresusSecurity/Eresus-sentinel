# Eresus Sentinel — Rule Format Reference

## Overview

All detection rules are stored as YAML files in the `rules/` directory. The engine loads, validates, and compiles these rules at startup. No detection patterns are hardcoded in Python or Rust.

## Rule Files

| File | Purpose | Pattern Count |
|------|---------|--------------|
| `secret_patterns.yaml` | Credential/secret detection | 120+ |
| `injection_patterns.yaml` | Prompt injection + jailbreak | 100+ |
| `sast_rules.yaml` | Static analysis rules | 30+ |
| `artifact_blocklist.yaml` | Dangerous pickle globals | 200+ |
| `mcp_rules.yaml` | MCP tool security checks | 13 categories |
| `supply_chain_rules.yaml` | File types, vulns, deps | 35+ extensions |
| `scanner_rules.yaml` | Artifact scanner patterns | TF/TS/TFLite/LlamaFile |

## Secret Pattern Format

```yaml
- id: aws-access-key           # Unique identifier
  description: AWS Access Key ID  # Human-readable description
  pattern: '(?:^|[^A-Z0-9])(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}'
  severity: CRITICAL            # CRITICAL / HIGH / MEDIUM / LOW / INFO
  category: cloud_provider      # Logical grouping
```

### Categories
`cloud_provider`, `ai_ml`, `payment`, `vcs`, `messaging`, `database`, `saas`, `crypto`, `cicd`, `generic`

## Injection Pattern Format

```yaml
direct_injection:               # Category name
  - pattern: '(?i)ignore\s+(?:all\s+)?previous\s+instructions?'
    name: instruction_override   # Pattern identifier
    severity: CRITICAL
```

### Categories
`direct_injection`, `jailbreak`, `system_extraction`, `encoding_attack`, `role_manipulation`, `tool_abuse`, `output_manipulation`, `delimiter_injection`

## SAST Rule Format

```yaml
rules:
  - id: SAST-001
    name: unsafe_pickle_load
    description: "Unsafe pickle.load() call detected"
    pattern: '(?:pickle|cPickle)\.loads?\s*\('
    severity: CRITICAL
    cwe_ids: ["CWE-502"]
    fix_hint: "Use safetensors or json instead of pickle"
    fp_risk: LOW
```

## MCP Rule Format

```yaml
dangerous_capabilities:
  command_exec:
    keywords: [exec, execute, shell, bash, subprocess]
    severity: CRITICAL
    description: "Tool can execute arbitrary commands"
    cwe: "CWE-78"

description_injection_patterns:
  - pattern: '(?i)ignore\s+previous\s+instructions'
    name: instruction_override
    description: "Instruction override in tool description"
    severity: CRITICAL
```

## Supply Chain Rule Format

```yaml
dangerous_extensions:
  .pkl:
    description: "Pickle file — arbitrary code execution"
    severity: CRITICAL
    cwe: "CWE-502"

known_vulnerable_packages:
  - name: transformers
    versions_before: "4.36.0"
    reason: "Multiple deserialization vulnerabilities"
    severity: HIGH
```

## Custom Rules

Override the rules directory with the `ERESUS_RULES_DIR` environment variable:

```bash
export ERESUS_RULES_DIR=/path/to/custom/rules
sentinel scan ./my-project
```

## Adding New Rules

1. Choose the appropriate YAML file
2. Add entry following the format above
3. Test with `sentinel validate`
4. Regex is Python-compatible (re module)
5. Severity must be one of: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`
