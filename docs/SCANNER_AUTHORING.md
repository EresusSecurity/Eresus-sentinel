# Scanner Authoring Guide

New scanners should return `sentinel.finding.Finding` objects and follow the
shared contracts in `sentinel.interfaces`.

## Minimal Scanner

```python
from pathlib import Path

from sentinel.finding import Finding, Severity


class ExampleScanner:
    name = "example"

    def scan_path(self, path: str | Path) -> list[Finding]:
        target = Path(path)
        if not target.exists():
            return []
        return [
            Finding.sast(
                rule_id="EXAMPLE-001",
                title="Example finding",
                description="Example scanner matched a risky pattern.",
                severity=Severity.LOW,
                target=str(target),
            )
        ]
```

## Guidelines

- Never deserialize untrusted artifacts to inspect them.
- For optional dependencies, use `sentinel.optional_deps.require_optional`.
- Normalize mixed severity strings with `sentinel.interfaces.normalize_severity`.
- Keep network integrations offline by default and pass explicit retry settings.
- Include tests for malicious and benign fixtures.
- For archive/container formats, fail closed when extraction is unsupported.
