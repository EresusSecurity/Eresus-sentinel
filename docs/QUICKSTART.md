# Eresus Sentinel — Quick Start

## Installation

### Python (Security Modules)

```bash
# Clone the repository
git clone https://github.com/eresus-security/eresus-sentinel.git
cd eresus-sentinel

# Install in development mode
pip install -e ".[dev]"

# Verify installation
python -c "from sentinel.rules import load_secret_patterns; print(f'{len(load_secret_patterns())} patterns loaded')"
```

The package installs the `sentinel` CLI. A compatibility alias,
`eresus-sentinel`, is also published for older scripts.

## Quick Scan

### Scan a model directory
```bash
sentinel scan ./models/my-model/
```

### Scan model artifacts for backdoors
```bash
sentinel artifact ./model.pkl
```

### Check prompts for injection attacks
```bash
sentinel firewall "Ignore all previous instructions"
```

### Run SAST on LLM application code
```bash
sentinel sast ./src/
```

### Validate MCP tool definitions
```bash
sentinel agent ./tools.json
```

### Audit supply chain
```bash
sentinel supply-chain ./models/
```

### Validate your rules
```bash
sentinel validate
```

## Python API

```python
from sentinel.artifact.pickle_scanner import PickleScanner
from sentinel.agent.mcp_validator import MCPValidator
from sentinel.supply_chain.provenance import ProvenanceVerifier
from sentinel.supply_chain.dependency import DependencyAuditor

# Scan a pickle file
scanner = PickleScanner()
findings = scanner.scan_file("model.pkl")

# Validate MCP tools
validator = MCPValidator()
findings = validator.validate_file("tools.json")

# Audit model directory
verifier = ProvenanceVerifier()
findings = verifier.audit_directory("./models/bert/")

# Scan dependencies
auditor = DependencyAuditor()
findings = auditor.audit_file("requirements.txt")
```

## Interactive Notebooks

```bash
# Install jupytext for notebook conversion
pip install jupytext

# Convert to notebooks
jupytext --to notebook notebooks/model_backdoor_lab.py
jupytext --to notebook notebooks/prompt_attack_lab.py

# Launch Jupyter
jupyter notebook notebooks/
```

## Configuration

Create `sentinel.toml` in your project root:

```toml
[general]
rules_dir = "rules"
min_severity = "LOW"

[scanners]
artifact = true
sast = true
agent_mcp = true
supply_chain = true
red_team = false    # Explicit opt-in required

[ai]
enabled = false     # Deterministic-first by default

[reporting]
format = "json"     # "sarif", "table", "html"
```

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `ERESUS_RULES_DIR` | Override rules directory |
| `ERESUS_AI_API_KEY` | API key for AI-assisted mode |
| `HF_TOKEN` | HuggingFace token for remote repo scanning |

## Running Tests

```bash
# All tests
python -m pytest tests/ -v

# With coverage
python -m pytest tests/ --cov=sentinel --cov-report=term-missing

# Rust tests
python -m build
```
