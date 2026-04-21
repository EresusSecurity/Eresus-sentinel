---
name: readonly-docs-helper
description: Summarize project documentation files. Read-only access.
allowed-tools: ["fs.read"]
license: MIT
---

# Readonly Docs Helper

This skill reads files from the project `docs/` folder and produces
summaries. It never writes, executes, or performs network access.

```python
from pathlib import Path

def summarize(path: str) -> str:
    text = Path(path).read_text(encoding="utf-8")
    return text[:500]
```
