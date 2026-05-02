# Eresus Sentinel Public Roadmap

Sentinel is currently alpha. The near-term strategy is reliability first, then larger product expansion. The deterministic scanner core stays primary; AI/judge adapters remain optional.

## Product Promise

Sentinel is a deterministic-first AI security toolkit for:

- Model artifact scanning without loading unsafe files.
- Prompt input/output firewall testing.
- MCP, agent, and skill security review.
- Local SAST, secrets, notebook, diff, and supply-chain audits.
- Red-team/eval playbooks for repeatable checks.

## 30-Day Hardening Sprint

| Track | Deliverable | Status |
|-------|-------------|--------|
| CLI | `scan --plan` and `--profile fast|balanced|deep|paranoid` | Done |
| CLI | `doctor --json` | Done |
| CLI | `config explain` | Done |
| CLI | `rules list/test/explain` | Done |
| CLI | `finding explain <rule_id>` | Done |
| Reporting | Initial scan JSON root shape | Done for `sentinel scan` |
| Docs | Exit code and output contract | Done |
| Docs | README alpha/product-positioning cleanup | Done |
| Docs | Public roadmap | Done |
| Docs | Turkish quickstart | Done |
| Community | Issue templates for bugs/features/false positives | Done |
| Artifact | Pickle fuzz CI gate | Next |
| MCP | Proxy local HTTP passthrough E2E | Next |
| HF | Mocked/live integration split | Next |
| Reporting | SARIF/JSON snapshots across domains | Next |
| Rules | Duplicate rule ID CI gate | Next |
| Release | Release checklist and package-data smoke | Next |

## 90-Day Beta Criteria

- CLI behavior and exit codes are consistent across scan domains.
- `Finding`/`ScanResult` normalization covers JSON, SARIF, Markdown, HTML, CSV, and JUnit.
- Artifact scanner fuzz gate blocks known pickle bypasses.
- MCP scanner/proxy have real HTTP and stdio E2E fixtures.
- HF live tests are marked integration and separated from fast CI.
- Rule schema, validation, duplicate ID gates, and docs are stable.
- Dashboard/API smoke tests are reliable enough for basic local deployment.
- README/docs use verified current commands.

## 6-Month Direction

- Reduce P0/P1 partials in the parity manifest with issue/milestone tracking.
- Stabilize AIBOM v1 JSON schema and graph output.
- Add runtime gateway provider adapters behind a tested adapter contract.
- Expand red-team/eval assertion registry and deterministic graders.
- Add remote resolver v1 for HF/S3/GCS/MLflow/JFrog/DVC-style sources.
- Add team policy profiles, org rule packs, baseline/diff workflows, and dashboard triage.

## Maturity Labels

| Domain | Maturity |
|--------|----------|
| Pickle/artifact no-load scanning | Beta |
| Prompt firewall deterministic checks | Beta |
| SAST/secrets/notebook/diff | Beta |
| MCP manifest/live scanning | Beta |
| MCP proxy runtime enforcement | Experimental |
| Dashboard/API | Experimental |
| HF/supply-chain live integrations | Experimental |
| Runtime gateway provider adapters | Experimental |
| AI/judge enrichment | Optional experimental |
