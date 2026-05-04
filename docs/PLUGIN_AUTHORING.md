# Scanner Plugin Authoring

Eresus Sentinel discovers scanner plugins through the `sentinel.scanners` Python entry point group.

Create a scaffold:

```bash
sentinel plugin new my-scanner --output ./plugins --json
```

The generated package subclasses `sentinel.plugin_sdk.BaseScanner` and returns `sentinel.finding.Finding` objects from `scan_path()`.

Install a plugin pack ZIP:

```bash
sentinel plugin install ./my-scanner.zip --json
```
