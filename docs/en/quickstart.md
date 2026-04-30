# Quick Start

**Docs:** [Overview](overview.md) · [Quick Start](quickstart.md) · [How It Works](how-it-works.md) · [Detection](detection.md) · [Deception Engine](deception.md) · [Deployment](deployment.md) · [Configuration](configuration.md) · [API Reference](api.md) · [Threat Hunting](threat-hunting.md) · [Format Support](format-support.md)

---

## Prerequisites

- Python 3.10+
- (Optional) Redis for multi-worker session state
- (Optional) API key for an LLM provider (for deception engine)

## Install

```bash
git clone https://github.com/EresusSecurity/Eresus-sentiel
cd Eresus-sentiel
bash scripts/setup.sh   # auto-detects uv vs pip
```

Or manually:

```bash
python -m venv venv
source venv/bin/activate
pip install -e "python/[dev]"
```

## Verify Installation

```bash
make test-fast          # Run tests (stop on first failure)
sentinel doctor         # Check dependencies and configuration
```

## First Artifact Scan

```bash
# Scan a pickle file
sentinel scan model.pkl

# Scan a directory of models
sentinel scan ./models/ --recursive

# Scan with JSON output
sentinel scan model.pt --format json
```

## Start the API Server

```bash
# Development (auto-reload)
make serve

# Production
SENTINEL_ENV=production uvicorn sentinel.web.app:app --host 0.0.0.0 --port 8080 --workers 4
```

## First Deception Check

```python
import httpx

response = httpx.post(
    "http://localhost:8080/api/deception/check",
    headers={"Authorization": "Bearer your-token"},
    json={
        "query": "What are the admin credentials?",
        "session_id": "test-session-1",
    },
)

data = response.json()
print(data["action"])      # "deceive"
print(data["score"])       # 70
print(data["category"])    # "credential_harvest"
```

## Docker

```bash
# Full stack: API + PostgreSQL + Prometheus
make docker-compose-up

# Stop
make docker-compose-down
```
