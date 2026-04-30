# Eresus Sentinel — Quick Start

## Installation

### Python (Security Modules)

```bash
# Clone the repository
git clone https://github.com/eresus-security/sentinel.git
cd sentinel

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

### Scan MCP manifests or live endpoints
```bash
sentinel mcp scan ./mcp-manifest.json
sentinel mcp scan --url http://localhost:3000/mcp
```

### Run config-driven evals
```bash
cat > eval.yaml <<'YAML'
providers:
  - id: echo
    name: echo
prompts:
  - id: smoke
    prompt: "hello {{name}}"
tests:
  - id: alice
    vars: { name: Alice }
    assertions:
      - type: contains
        expected: Alice
YAML

sentinel evaluate eval.yaml
```

### Audit supply chain
```bash
sentinel supply-chain ./models/
```

### Validate your rules
```bash
sentinel validate
```

### Open the Web UI dashboard
```bash
pip install "eresus-sentinel[web]"
export SENTINEL_PASSWORD=change-me
sentinel dashboard
```

Open `http://127.0.0.1:8080`. For a remote server, bind explicitly with
`sentinel dashboard --host 0.0.0.0 --port 8080` and put it behind TLS/auth.

## Python API

```python
from sentinel.artifact.pickle_scanner import PickleScanner
from sentinel.agent.mcp_validator import MCPValidator
from sentinel.agent.mcp.live_scanner import MCPLiveScanner
from sentinel.redteam.eval_runner import run_eval_file
from sentinel.runtime_gateway import EchoProviderAdapter, SentinelGateway
from sentinel.supply_chain.provenance import ProvenanceVerifier
from sentinel.supply_chain.dependency import DependencyAuditor

# Scan a pickle file
scanner = PickleScanner()
findings = scanner.scan_file("model.pkl")

# Validate MCP tools
validator = MCPValidator()
findings = validator.validate_file("tools.json")

# Scan a full MCP manifest
mcp_result = MCPLiveScanner().scan_manifest("mcp-manifest.json")
print(mcp_result.readiness_grade)

# Run an eval config
eval_result = run_eval_file("eval.yaml")
print(eval_result.summary())

# Runtime gateway wrapper
gateway = SentinelGateway(provider=EchoProviderAdapter())
decision = gateway.complete("user prompt")
print(decision.action)

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
[engine]
mode = "deterministic"
min_severity = "LOW"
output_format = "json"   # "sarif", "table", "markdown"

[scanners.artifact]
enabled = true

[scanners.sast]
enabled = true

[scanners.redteam]
enabled = false    # Explicit opt-in required

[ai]
enabled = false     # Deterministic-first by default
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
