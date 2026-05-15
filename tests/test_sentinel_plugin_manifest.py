from sentinel.mcp.secure_server import SecureMCPServer
from sentinel.plugins.manifest import discover_manifests, validate_manifest_file


def test_manifest_loader_supports_yaml_toml_sentinel_and_yara(tmp_path):
    yaml_path = tmp_path / "sentinel.plugin.yaml"
    yaml_path.write_text(
        "\n".join([
            "schema_version: sentinel.plugin.v1",
            "id: sentinel.test.scanner",
            "name: Test Scanner",
            "version: 0.1.0",
            "kind: scanner",
            "entrypoint: sentinel_test:Plugin",
            "permissions:",
            "  - scan:file-read",
            "  - network:none",
        ]),
        encoding="utf-8",
    )
    toml_path = tmp_path / "sentinel.plugin.toml"
    toml_path.write_text(
        "\n".join([
            'schema_version = "sentinel.plugin.v1"',
            'id = "sentinel.test.toml"',
            'name = "Test TOML"',
            'version = "0.1.0"',
            'kind = "rulepack"',
            'rules = ["rule.one"]',
            'permissions = ["scan:file-read", "network:none"]',
        ]),
        encoding="utf-8",
    )
    sentinel_path = tmp_path / "pack.sentinel"
    sentinel_path.write_text(
        "\n".join([
            "schema_version: sentinel.plugin.v1",
            "id: sentinel.test.pack",
            "name: Test Pack",
            "version: 0.1.0",
            "kind: rulepack",
            "rules:",
            "  - rule.one",
            "permissions:",
            "  - scan:file-read",
            "  - network:none",
        ]),
        encoding="utf-8",
    )
    yara_path = tmp_path / "artifact.yara"
    yara_path.write_text("rule SentinelTestRule { condition: true }\n", encoding="utf-8")

    for path in (yaml_path, toml_path, sentinel_path, yara_path):
        manifest, issues = validate_manifest_file(path, workspace_root=tmp_path)
        assert manifest is not None
        assert not [issue for issue in issues if issue.severity in {"critical", "high"}]


def test_manifest_validator_rejects_dangerous_permissions_and_entrypoints(tmp_path):
    path = tmp_path / "sentinel.plugin.yaml"
    path.write_text(
        "\n".join([
            "schema_version: sentinel.plugin.v1",
            "id: sentinel.bad.scanner",
            "name: Bad Scanner",
            "version: 0.1.0",
            "kind: scanner",
            "entrypoint: bash -c whoami",
            "permissions:",
            "  - shell:exec",
            "  - network:any",
        ]),
        encoding="utf-8",
    )

    manifest, issues = validate_manifest_file(path, workspace_root=tmp_path)
    codes = {issue.code for issue in issues}

    assert manifest is not None
    assert "PLUGIN-PERM-001" in codes
    assert "PLUGIN-ENTRYPOINT-001" in codes


def test_manifest_path_is_constrained_to_workspace(tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside.sentinel"
    outside.write_text("schema_version: sentinel.plugin.v1\nid: sentinel.outside.pack\n", encoding="utf-8")

    manifest, issues = validate_manifest_file(outside, workspace_root=tmp_path)

    assert manifest is None
    assert issues[0].code == "PLUGIN-LOAD-001"


def test_discovery_only_returns_loadable_manifests(tmp_path):
    good = tmp_path / "sentinel.plugin.yaml"
    bad = tmp_path / "bad.sentinel"
    good.write_text(
        "\n".join([
            "schema_version: sentinel.plugin.v1",
            "id: sentinel.good.pack",
            "name: Good Pack",
            "version: 0.1.0",
            "kind: rulepack",
            "rules:",
            "  - rule.good",
            "permissions:",
            "  - scan:file-read",
            "  - network:none",
        ]),
        encoding="utf-8",
    )
    bad.write_text(
        "\n".join([
            "schema_version: sentinel.plugin.v1",
            "id: sentinel.bad.pack",
            "name: Bad Pack",
            "version: 0.1.0",
            "kind: scanner",
            "entrypoint: python -c bad",
            "permissions:",
            "  - shell:exec",
        ]),
        encoding="utf-8",
    )

    manifests = discover_manifests(tmp_path)

    assert [manifest.plugin_id for manifest in manifests] == ["sentinel.good.pack"]


def test_secure_mcp_server_validates_plugin_without_execution(tmp_path):
    path = tmp_path / "sentinel.plugin.yaml"
    path.write_text(
        "\n".join([
            "schema_version: sentinel.plugin.v1",
            "id: sentinel.mcp.pack",
            "name: MCP Pack",
            "version: 0.1.0",
            "kind: rulepack",
            "rules:",
            "  - rule.mcp",
            "permissions:",
            "  - scan:file-read",
            "  - network:none",
        ]),
        encoding="utf-8",
    )
    server = SecureMCPServer(tmp_path)

    response = server.handle_request({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "sentinel.plugins.validate", "arguments": {"path": "sentinel.plugin.yaml"}},
    })

    payload = response["result"]["structuredContent"]
    assert payload["manifest"]["id"] == "sentinel.mcp.pack"
    assert payload["issues"] == []


def test_secure_mcp_server_blocks_path_escape(tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-mcp-outside.sentinel"
    outside.write_text("schema_version: sentinel.plugin.v1\nid: sentinel.escape.pack\n", encoding="utf-8")
    server = SecureMCPServer(tmp_path)

    response = server.handle_request({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "sentinel.plugins.validate", "arguments": {"path": str(outside)}},
    })

    assert response["error"]["code"] == -32602
