# Sentinel CLI Contract

This document is the public contract for automation users. New commands should follow it unless a command documents a narrower domain-specific shape.

## Exit Codes

| Code | Meaning | Typical Cause |
|------|---------|---------------|
| `0` | Clean or informational command completed | No findings, `--plan`, `doctor`, `rules list` |
| `1` | Findings, blocked decision, or failed quality gate | Scan findings at/above threshold, rule test failure |
| `2` | Usage, target, or internal error | Missing path, unsupported arguments, scanner exception |

## Common JSON Shape

Security scan commands should converge on this root shape:

```json
{
  "schema_version": "0.1",
  "command": "scan",
  "summary": {
    "command": "scan",
    "target": "./project",
    "profile": "balanced",
    "status": "clean",
    "exit_code": 0,
    "duration_ms": 123.4
  },
  "totals": {
    "modules": 9,
    "modules_passed": 9,
    "findings": 0,
    "severity": {
      "CRITICAL": 0,
      "HIGH": 0,
      "MEDIUM": 0,
      "LOW": 0,
      "INFO": 0
    }
  },
  "findings": [],
  "errors": [],
  "metadata": {}
}
```

`sentinel scan -f json` and `sentinel scan --plan -f json` now emit this structure. Older domain commands may still return legacy arrays while they are migrated.

## Profiles

| Profile | Intended Use | Current Behavior |
|---------|--------------|------------------|
| `fast` | Pre-commit and local loops | SAST + secrets |
| `balanced` | Default local audit | Existing multi-domain deterministic scan |
| `deep` | CI and release checks | Balanced + explicit secrets pass |
| `paranoid` | Strict CI / nightly hardening | Deep deterministic modules; long fuzz remains a separate `fuzz selftest` gate |

## Machine-Readable Commands

```bash
sentinel scan ./project --plan --profile fast -f json
sentinel scan ./project --profile balanced -f json
sentinel doctor --json
sentinel config explain -f json
sentinel rules list -f json
sentinel rules test aws-access-key -f json
sentinel finding explain ARTIFACT-031 -f json
```

## Output Rules

- Human Rich/table output goes to stderr when JSON is emitted to stdout.
- Secrets and private tokens must be redacted in every reporter.
- `--output` writes the structured payload to disk and keeps terminal output human-readable.
- New reporters should include `schema_version`, `command`, `summary`, `totals`, `findings`, `errors`, and `metadata`.

## Hook Empty-Input Behavior

`sentinel skill-scan` and `sentinel mcp-validate` fail closed when invoked without matching files. This prevents a direct no-argument invocation from looking like a successful security check.

Pre-commit integrations that intentionally pass no files after filtering must opt in:

```bash
sentinel skill-scan --allow-empty
sentinel mcp-validate --allow-empty
```
