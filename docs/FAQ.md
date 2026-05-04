# FAQ

## Does Sentinel need an LLM?

No. Findings are produced by deterministic scanners. LLM or judge adapters are
optional enrichment.

## Is Sentinel stable?

It is alpha-stage. Artifact, firewall, SAST, MCP, notebook, and diff scanners
are usable, but APIs and report schemas can still evolve.

## Does Sentinel execute model files?

No. Artifact scanners inspect bytes, metadata, archives, and opcode streams
without loading untrusted models.

## Can I use it in CI?

Yes. Start with `sentinel scan --profile fast -f json`, the pre-commit hooks,
and the workflow in `ci/github-actions.yml`.

## Where should new rules go?

Use `rules/*.yaml` whenever possible. Add Python scanner logic only when a rule
needs parsing, binary structure, protocol state, or cross-file analysis.
