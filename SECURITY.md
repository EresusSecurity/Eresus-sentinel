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

- Pickle/model deserialization bypass
- Scanner evasion techniques
- API authentication bypass
- Information disclosure via error messages
- YAML rule injection
- Dependency vulnerabilities (critical/high)
- Docker image vulnerabilities

### Out of Scope

- Denial of service against the CLI (local tool)
- Vulnerabilities in optional ML dependencies (report upstream)
- Social engineering attacks

## Security Best Practices

When deploying Eresus Sentinel in production:

1. **Never run as root** — Use the Docker image or a dedicated service account
2. **Enable authentication** — Set `SENTINEL_AUTH_TYPE=http_bearer` and `SENTINEL_AUTH_TOKEN`
3. **Restrict CORS** — Set `SENTINEL_CORS_ORIGINS` to your domain(s)
4. **Enable audit logging** — Set `SENTINEL_AUDIT_LOG` for compliance trails
5. **Pin dependencies** — Use `pip freeze` or `uv lock` for reproducible builds
6. **Rotate API tokens** — Change `SENTINEL_AUTH_TOKEN` regularly
7. **Monitor metrics** — Use `/metrics` endpoint with Prometheus
