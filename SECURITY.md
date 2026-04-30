# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | ✅ Active          |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Please report security vulnerabilities via:

- **Email**: security@eresussec.com
- **Subject**: `[VULN] Eresus Sentinel — <brief description>`

Include:
1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if any)

### Response Timeline

| Action                    | Timeline     |
|---------------------------|-------------|
| Acknowledgment            | 24 hours    |
| Initial assessment        | 72 hours    |
| Patch development         | 7-14 days   |
| Public disclosure          | 30-90 days  |

### Scope

The following are in scope for security reports:

**Artifact Scanning**
- Pickle/model deserialization bypass
- Scanner evasion techniques (format confusion, magic byte forgery)
- YAML rule injection or rule file poisoning
- H5/HDF5/ONNX/GGUF parser vulnerabilities
- ZIP/TAR path traversal in model archives

**Firewall & Deception Engine**
- Deception directive leakage to the caller (preamble text visible in LLM response)
- Session ID prediction or session fixation attacks
- Guardrail bypass — query scoring 0 when it should score >0
- ReDoS or denial-of-service via crafted regex input
- Information disclosure: real credentials, internal config, LLM system prompts returned to callers
- Custom rules validation bypass (malformed JSON/regex injection)
- Session store race conditions (in-memory or Redis)

**Web API**
- API authentication or authorization bypass
- Information disclosure via error messages or stack traces
- Rate limiting bypass
- CORS misconfiguration exploitation

**General**
- Dependency vulnerabilities with a realistic exploit path (critical/high)
- Docker image vulnerabilities
- Secrets or credentials committed to the repository

### Out of Scope

- Denial of service against the CLI (local tool, not network-exposed)
- Vulnerabilities in optional ML dependencies (PyTorch, TensorFlow, etc. — report upstream)
- Social engineering or phishing of maintainers
- Issues that require physical access or a fully compromised host
- The LLM provider's own safety and security (report to the provider directly)

## Security Architecture

### Deterministic-First Design
All core detection is regex/AST/opcode-based. AI enrichment (`[ai] enabled = true` in `sentinel.toml`) is optional and never gates security decisions. This eliminates prompt injection as an attack vector against detection logic.

### Input Safety
- **ReDoS mitigation**: All regex patterns are applied to the first 4,096 characters only (`MAX_DETECTION_CHARS`)
- **Input size limits**: Enforced via Pydantic models before any processing
- **YAML parsing**: `yaml.safe_load()` used exclusively — `yaml.load()` is prohibited
- **No `eval()`/`exec()`**: Prohibited outside of pattern detection rule strings

### Deception Engine Safety
- **Preamble isolation**: Deception preambles are injected into the system prompt only, never visible in the API response
- **Session state server-side**: Cumulative scores and history are never exposed to callers (defender-only endpoints require admin auth)
- **Output scanning**: Every response is scanned for leaked deception directives before serving
- **Block actions**: Return synthetic refusals without calling the LLM — no token counts, no model metadata

### Authentication & Authorization
- **Constant-time comparison**: `hmac.compare_digest()` on all token checks — prevents timing attacks
- **Separate admin credentials**: Session/defender endpoints use `SENTINEL_AUTH_TOKEN`
- **Production mode**: Swagger UI, debug info, and verbose errors disabled when `SENTINEL_ENV=production`

## Security Best Practices

When deploying Eresus Sentinel in production:

1. **Never run as root** — Use the Docker image or a dedicated service account
2. **Enable authentication** — Set `SENTINEL_AUTH_TYPE=bearer` and `SENTINEL_AUTH_TOKEN`
3. **Restrict CORS** — Set `SENTINEL_CORS_ORIGINS` to your domain(s) only
4. **Enable audit logging** — Set `SENTINEL_AUDIT_LOG` for compliance trails
5. **Pin dependencies** — Use `pip freeze` or `uv lock` for reproducible builds
6. **Rotate API tokens** — Change `SENTINEL_AUTH_TOKEN` regularly
7. **Monitor metrics** — Use `/metrics` endpoint with Prometheus
8. **Set production mode** — `SENTINEL_ENV=production` disables debug info
9. **Use Redis for multi-worker** — In-memory session store is per-worker; use `REDIS_URL` for shared state
10. **Restrict deception endpoints** — `/api/deception/session/*` endpoints expose defender-only data

## Ethical Use

Eresus Sentinel's deception engine is a **defensive tool**. It is designed to protect systems by misleading attackers who probe LLM-backed services. Using the deception features to deceive legitimate users, operate without disclosure where legally required, or facilitate any illegal activity is outside the intended use and is not endorsed by the maintainers.

**Legal note**: Intentionally false AI-generated outputs may create compliance exposure in medical, legal, or financial contexts. Legal review is recommended before deploying deception mode in regulated environments.
