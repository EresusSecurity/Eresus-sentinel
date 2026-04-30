# Configuration

**Docs:** [Overview](overview.md) · [Quick Start](quickstart.md) · [How It Works](how-it-works.md) · [Detection](detection.md) · [Deception Engine](deception.md) · [Deployment](deployment.md) · [Configuration](configuration.md) · [API Reference](api.md) · [Threat Hunting](threat-hunting.md) · [Format Support](format-support.md)

---

## Environment Variables

### Core

| Variable | Default | Description |
|----------|---------|-------------|
| `SENTINEL_ENV` | `development` | `production` disables Swagger UI, debug info, verbose errors |
| `SENTINEL_AUTH_TYPE` | — | `bearer` or `api-key` |
| `SENTINEL_AUTH_TOKEN` | — | API authentication token |
| `SENTINEL_CORS_ORIGINS` | `*` | Comma-separated allowed CORS origins |
| `SENTINEL_AUDIT_LOG` | — | Path to audit JSONL log |
| `SENTINEL_PASSWORD` | — | Admin password (required for DB mode) |
| `ERESUS_RULES_DIR` | `rules` | Override rules directory path |
| `DATABASE_URL` | — | PostgreSQL URL (`postgresql+asyncpg://...`) |

### Deception Engine

| Variable | Default | Description |
|----------|---------|-------------|
| `DECEPTION_MODE` | `template` | `template` or `generative` |
| `SCORE_BLOCK` | `90` | Hard block threshold (50–100) |
| `SCORE_DECEIVE` | `40` | Deception injection threshold (1–SCORE_BLOCK−1) |
| `SCORE_WARN` | `20` | Warn-only threshold (1–SCORE_DECEIVE−1) |
| `SESSION_DECEIVE_THRESHOLD` | `300` | Cumulative session score for auto-escalation |
| `CUSTOM_RULES_FILE` | — | Path to JSON custom rules file |
| `REDIS_URL` | — | Redis URL for shared session state |

### LLM Examiner (Optional)

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_EXAMINER_ENABLED` | `false` | Enable secondary LLM classifier |
| `LLM_EXAMINER_URL` | — | OpenAI-compatible `/v1/chat/completions` endpoint |
| `LLM_EXAMINER_MODEL` | — | Model name (e.g. `llama3`, `gpt-4o-mini`) |
| `LLM_EXAMINER_API_KEY` | — | Leave blank for local models |
| `LLM_EXAMINER_TIMEOUT` | `8` | Seconds — timeouts are silently swallowed |

### AI Enrichment (Optional)

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | OpenAI API key for AI enrichment |
| `ANTHROPIC_API_KEY` | Anthropic API key for AI enrichment |
| `HF_TOKEN` | HuggingFace token for remote repo scanning |

### Threshold Tuning

`SCORE_WARN < SCORE_DECEIVE < SCORE_BLOCK` must hold. Out-of-range values are clamped with a startup warning.

```env
# Deceive earlier — catch more borderline probing
SCORE_DECEIVE=30
SCORE_WARN=15

# Stricter hard block
SCORE_BLOCK=70

# Catch persistent probers faster
SESSION_DECEIVE_THRESHOLD=150
```
