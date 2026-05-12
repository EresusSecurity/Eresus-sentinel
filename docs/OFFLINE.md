# Offline / Air-Gapped Usage

Sentinel's core scanner is fully offline by default. This page covers installation in air-gapped environments, what features require network access, and how to configure Sentinel for restricted networks.

---

## What Works Offline (No Network Required)

Everything in the core scanning path:

- `sentinel artifact` — all 70+ format scanners
- `sentinel firewall` — all input/output guardrails
- `sentinel sast` — all static analysis and secret detection
- `sentinel mcp scan` — manifest-only (offline) mode
- `sentinel rules audit` — rule validation
- `sentinel doctor` — dependency check (local only)

---

## What Requires Network Access

| Feature | Flag / Command | Why |
|---------|---------------|-----|
| HuggingFace model scanning | `sentinel artifact hf://org/repo` | Downloads model files |
| Supply chain OSV.dev lookup | `sentinel supply-chain` | Queries osv.dev API |
| HF repo typosquatting check | `sentinel supply-chain --hf` | Queries HuggingFace API |
| AI-assisted mode | `[ai] enabled = true` | LLM API calls |
| Remote MCP live scan | `sentinel mcp scan --url http://...` | HTTP connection to MCP server |
| Rule update (future) | `sentinel rules update` | Downloads updated rules |

---

## Air-Gapped Installation

### Method 1 — Pip with pre-downloaded wheels

On an internet-connected machine:

```bash
# Download all wheels (including dependencies)
pip download eresus-sentinel[all] -d ./sentinel-wheels/

# Pack for transfer
tar czf sentinel-wheels.tar.gz sentinel-wheels/
```

Transfer `sentinel-wheels.tar.gz` to the air-gapped machine, then:

```bash
tar xzf sentinel-wheels.tar.gz
pip install --no-index --find-links=./sentinel-wheels eresus-sentinel[all]
```

### Method 2 — Docker image export

On an internet-connected machine:

```bash
docker pull ghcr.io/eresussecurity/sentinel:latest
docker save ghcr.io/eresussecurity/sentinel:latest | gzip > sentinel-image.tar.gz
```

Transfer and load:

```bash
docker load < sentinel-image.tar.gz
docker run --rm -v "$(pwd)/models":/data sentinel:latest artifact /data
```

### Method 3 — Install from source (no PyPI)

```bash
# Clone or copy the repo
git clone https://github.com/EresusSecurity/Eresus-sentinel.git
cd Eresus-sentinel

# Install from local source
pip install -e "." --no-build-isolation
```

---

## Disabling All Network Features

Set in `sentinel.toml`:

```toml
[network]
offline = true          # Disables all outbound HTTP/HTTPS
allow_hf_download = false
allow_osv_lookup = false
allow_remote_mcp = false

[ai]
enabled = false         # Disables LLM API calls
```

Or via environment variable:

```bash
export SENTINEL_OFFLINE=1
sentinel artifact ./models/
```

When `offline = true`:
- Any command that would require network access will fail with a clear error instead of hanging.
- HuggingFace `hf://` URIs are rejected.
- `supply-chain --hf` skips the live API check and warns.

---

## Scanning Without Internet — HuggingFace Models

If you have already downloaded a model locally:

```bash
# Works fully offline — no HF API calls
sentinel artifact /path/to/downloaded-model/
sentinel artifact /path/to/model.safetensors
sentinel artifact /path/to/pytorch_model.bin
```

To scan a HF repo in an air-gapped environment, first download it on an internet-connected machine:

```bash
# On internet-connected machine
pip install huggingface_hub
huggingface-cli download org/model-name --local-dir ./model-cache/

# Transfer model-cache/ to air-gapped machine, then:
sentinel artifact ./model-cache/
```

---

## Proxy Configuration

If your air-gapped environment has an internal proxy:

```bash
export HTTP_PROXY=http://proxy.internal:8080
export HTTPS_PROXY=http://proxy.internal:8080
export NO_PROXY=localhost,127.0.0.1,*.internal

sentinel supply-chain ./models/  # Uses proxy for OSV.dev
```

Or per-command:

```bash
sentinel artifact hf://org/model \
  --hf-endpoint https://huggingface.internal/  # Internal HF mirror
```

---

## Rule Updates in Air-Gapped Environments

Rules live in the `rules/` directory alongside the package. To update rules without network access:

1. Download the updated `rules/` directory from the release assets on GitHub.
2. Copy it to your installation:

```bash
# Find the installed rules directory
python -c "import sentinel; import pathlib; print(pathlib.Path(sentinel.__file__).parent.parent.parent / 'rules')"

# Replace rules
cp -r ./new-rules/* /path/to/installed/rules/

# Verify rules loaded correctly
sentinel rules audit
```

Or point Sentinel at your own rules directory:

```bash
export ERESUS_RULES_DIR=/path/to/custom-rules
sentinel artifact ./models/
```

---

## Docker in Air-Gapped Environments

The Sentinel Docker image includes all rule files and Python dependencies — it requires no outbound connections for scanning:

```bash
# Scan a local directory — fully offline
docker run --rm \
  --network none \
  -v "$(pwd)/models":/data:ro \
  ghcr.io/eresussecurity/sentinel:latest \
  artifact /data --format json
```

`--network none` guarantees no accidental network access.
