# Eresus Sentinel — Agent Instructions

Eresus Sentinel is a **deterministic-first security platform for AI/LLM ecosystems**. It provides ten security domains (artifact scanning, input/output firewall, SAST, red team, MCP proxy, supply chain, notebook, diff) with optional AI enrichment. Core scanning never depends on AI — all patterns live in YAML rules.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/QUICKSTART.md](docs/QUICKSTART.md) for full documentation.

## Key Directories

| Path | Purpose |
|------|---------|
| `python/sentinel/` | Core Python package |
| `python/sentinel/firewall/input/` | Input guardrail scanners |
| `python/sentinel/firewall/output/` | Output guardrail scanners |
| `python/sentinel/artifact/` | Model artifact format scanners |
| `rules/` | All YAML detection patterns — no hardcoded regex in Python |
| `tests/` | pytest test suite |
| `config/` | Policy, Prometheus, and scanner config |
| `docs/` | Architecture, quickstart, and rules reference |

## Commands

```bash
# Dev setup (auto-detects uv vs pip)
bash scripts/setup.sh
# OR
make dev

# Quality checks (run before committing)
make lint          # ruff check + format
make typecheck     # mypy
make check         # lint + typecheck combined

# Tests
make test          # Full suite
make test-fast     # Stop on first failure
make test-cov      # With HTML coverage report (min 60%)
make test-unit     # Exclude slow/integration markers

# API server
make serve         # Dev server with auto-reload at http://localhost:8080

# Docker
make docker-compose-up    # Full stack: API + PostgreSQL + Prometheus
make docker-compose-down

# Utilities
make scan-self       # Run Sentinel on its own codebase
make validate-rules  # Validate all YAML rule files
```

## Architecture Principles

1. **Deterministic-first** — All core detection is regex/AST/opcode-based. AI (`[ai] enabled = true` in `sentinel.toml`) is optional enrichment only.
2. **YAML-driven rules** — All patterns externalized to `rules/*.yaml`. Never add hardcoded regex to Python scanners.
3. **Plugin auto-discovery** — Drop a scanner class in the right module; `_plugins.py` discovers it via `pkgutil` + class inspection. No registration required.
4. **Universal Finding DTO** — Every domain returns `Finding` objects (see `python/sentinel/finding.py`). Use factory methods: `Finding.artifact()`, `Finding.input_firewall()`, etc.
5. **LRU-cached rule loading** — `rules.py` caches rule sets with `@lru_cache(maxsize=1)`. Rules compile once at load time.

## Code Conventions

### Rule IDs
Format: `DOMAIN-XXX` — e.g., `ARTIFACT-001`, `FIREWALL-INPUT-003`, `SAST-042`.

### Scanner Naming
- **File**: `snake_case.py` in the appropriate subpackage
- **Class**: `PascalCaseScanner` (e.g., `PromptInjectionScanner`)
- **Plugin registry key** (auto-generated): kebab-case (e.g., `prompt-injection`)

### Adding an Input/Output Scanner
Inherit from `InputScanner` / `OutputScanner` in `firewall/base.py`, implement `scan()`, place file in `firewall/input/` or `firewall/output/`. Auto-discovered — no other changes needed.

### Adding an Artifact Scanner
Implement `scan_file(filepath: str) -> list[Finding]` or `scan_bytes(data: bytes, source: str) -> list[Finding]`. Place in `python/sentinel/artifact/`.

### Severity & Confidence
Use `Severity` enum (CRITICAL/HIGH/MEDIUM/LOW/INFO) and float confidence 0.0–1.0 on every `Finding`.

### Post-processing
`cli_dispatch.py` runs all findings through a pipeline: suppression → severity filter → shadow mode → action policy. Do not implement policy logic inside scanners.

## Testing Conventions

```bash
# pytest markers
pytest tests/ -m "not slow"        # Exclude slow tests
pytest tests/ -m integration       # Integration tests (need external services)
pytest tests/ -m "not gpu"         # Exclude GPU-requiring tests
```

- Tests use `unittest.TestCase` classes and pytest fixtures.
- Async tests use `pytest-asyncio`.
- Coverage minimum: 60% (enforced by `make test-cov`).

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `ERESUS_RULES_DIR` | Override rules directory path |
| `DATABASE_URL` | PostgreSQL URL (`postgresql+asyncpg://...`) |
| `SENTINEL_ENV` | `production` or `development` (affects error verbosity) |
| `SENTINEL_AUTH_TYPE` | `bearer` or `api-key` |
| `SENTINEL_AUTH_TOKEN` | API auth token |
| `SENTINEL_CORS_ORIGINS` | Comma-separated allowed CORS origins |
| `SENTINEL_AUDIT_LOG` | Path to audit JSONL log |
| `SENTINEL_PASSWORD` | Admin password (required for DB mode, no default) |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` | Optional AI enrichment backends |
| `HF_TOKEN` | HuggingFace token for remote repo scanning |

## Security Notes

- **Never** introduce `yaml.load()` — use `yaml.safe_load()` throughout.
- **Never** add `eval()`/`exec()` outside of pattern detection rule strings.
- Report vulnerabilities to security@eresussec.com — **not** as public issues. See [SECURITY.md](SECURITY.md).
- Production: always set auth (`SENTINEL_AUTH_TYPE`), restrict CORS, and enable audit logging.

## Commit Convention

Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`.
