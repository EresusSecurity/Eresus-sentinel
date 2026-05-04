# False Positive Handling

Sentinel is deterministic-first, so false positive handling should be explicit
and testable.

## Triage Flow

1. Reproduce with `-f json` and save the finding payload.
2. Identify the `rule_id`, `evidence`, and scanner module.
3. Add a benign fixture before changing a pattern.
4. Prefer narrowing the rule over suppressing it.
5. Add a suppression only when the behavior is truly acceptable for the repo.

## Suppression Principles

- Suppress by stable rule ID and target path.
- Keep suppressions reviewed in code.
- Do not suppress `CRITICAL` deserialization or credential findings without a
  documented compensating control.

## Reporting Template

```text
Rule ID:
Command:
Expected:
Actual:
Benign context:
Minimal fixture:
```
