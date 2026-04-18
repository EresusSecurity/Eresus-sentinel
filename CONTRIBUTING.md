# Contributing to Eresus Sentinel

Thank you for your interest in contributing! This guide will help you get started.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/eresus-security/sentinel.git
cd eresus-sentinel

# Install development dependencies
make dev

# Verify installation
make doctor
make test
```

## Project Structure

```
eresus-sentinel/
├── python/sentinel/        # Core Python package
│   ├── firewall/           # Input/output scanner pipelines
│   │   ├── input/          # 23 input scanners
│   │   └── output/         # 25 output scanners
│   ├── artifact/           # Model artifact scanners (12 formats)
│   ├── redteam/            # Red team framework
│   │   ├── probes/         # 34 attack probes
│   │   ├── generators/     # 14 LLM backend adapters
│   │   ├── detectors/      # 13 response detectors
│   │   └── buffs/          # Prompt mutation buffs
│   ├── agent/              # Agent/MCP security
│   ├── supply_chain/       # ML supply chain audit
│   ├── notebook_scanner/   # Jupyter security scanning
│   ├── diff_scanner/       # Git diff security analysis
│   ├── data/               # YAML pattern databases
│   ├── cli.py              # CLI interface
│   ├── server.py           # FastAPI REST API
│   ├── sdk.py              # Python SDK
│   ├── middleware.py        # LangChain/OpenAI wrappers
│   └── policy.py           # YAML policy engine
├── rules/                  # External YAML rule definitions
├── config/                 # API server configuration
├── tests/                  # Test suite
├── notebooks/              # Example notebooks
└── docs/                   # Documentation
```

## Adding a New Scanner

### Input Scanner

1. Create `python/sentinel/firewall/input/my_scanner.py`
2. Inherit from `InputScanner`
3. Implement `scan(prompt, metadata)` method
4. The plugin auto-discovery system will find it automatically

```python
from sentinel.firewall.base import InputScanner, ScanResult, ScanAction

class MyCustomScanner(InputScanner):
    \"\"\"Scans for custom security patterns.\"\"\"

    def __init__(self, threshold: float = 0.5):
        self.threshold = threshold

    def scan(self, prompt: str, metadata: dict | None = None) -> ScanResult:
        # Your detection logic here
        risk_score = self._analyze(prompt)
        is_valid = risk_score < self.threshold
        return ScanResult(
            is_valid=is_valid,
            risk_score=risk_score,
            action=ScanAction.BLOCK if not is_valid else ScanAction.PASS,
            sanitized=prompt,
        )
```

### Output Scanner

Same pattern, inherit from `OutputScanner`, implement `scan(prompt, output, metadata)`.

### Artifact Scanner

1. Create `python/sentinel/artifact/my_format_scanner.py`
2. Add a class with `scan_file(filepath)` returning `list[Finding]`
3. Auto-discovered via `_plugins.py`

## Code Standards

- **Linting**: `ruff` (run `make lint`)
- **Formatting**: `ruff format` (run `make lint-fix`)
- **Type checking**: `mypy` (run `make typecheck`)
- **Line length**: 100 characters
- **Python**: 3.10+

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run quality checks: `make check`
5. Run tests: `make test`
6. Commit with descriptive message
7. Push and create a Pull Request

### Commit Messages

```
feat: add new GGUF metadata scanner
fix: resolve false positive in encoding attack detection
docs: update quickstart with Docker deployment
refactor: split monolithic CLI into subcommands
test: add unit tests for policy engine
```

## Reporting Issues

Use GitHub Issues with labels:
- `bug` — Something isn't working
- `enhancement` — Feature request
- `security` — Security vulnerability (use SECURITY.md process instead)
- `scanner` — New scanner idea
- `documentation` — Docs improvement
