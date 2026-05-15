# Sentinel Plugin Format

Sentinel plugin manifests are declarative. They describe capability, format support, permissions, and rule ownership without executing package code.

Supported manifest extensions:

- `.sentinel`
- `.yaml`
- `.yml`
- `.json`
- `.toml`
- `.yar`
- `.yara`

Recommended package manifest:

```yaml
schema_version: sentinel.plugin.v1
id: sentinel.example.artifact-scanner
name: Example Artifact Scanner
version: 0.1.0
kind: scanner
description: Deterministic artifact checks for one model family.
entrypoint: sentinel_example_artifact:Plugin
formats:
  - .bin
  - .safetensors
permissions:
  - scan:file-read
  - scan:artifact
  - network:none
tags:
  - artifact
  - deterministic
```

TOML variant:

```toml
schema_version = "sentinel.plugin.v1"
id = "sentinel.example.rulepack"
name = "Example Rule Pack"
version = "0.1.0"
kind = "rulepack"
rules = ["prompt.injection.basic", "artifact.pickle.global"]
permissions = ["scan:file-read", "network:none"]
formats = [".sentinel", ".yar"]
tags = ["rules"]
```

YARA files are accepted as rule packs. Sentinel extracts rule names and treats the file as a read-only `yara` manifest.

Denied manifest capabilities include shell execution, process execution, unrestricted network access, secret access, filesystem deletion, and filesystem write permissions.

Safe authoring rules:

- Use Python entry point references such as `package.module:Plugin`.
- Keep permissions minimal.
- Put rule packs under `rules/packs`.
- Keep manifests below 1 MB.
- Treat every manifest as untrusted input.
- Validate with `sentinel mcp serve` tools or the Python SDK before packaging.
