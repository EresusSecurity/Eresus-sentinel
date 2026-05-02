import asyncio
import json

from sentinel.mcp_proxy import MCPProxy, ProxyAction, ProxyConfig, ProxyMode


def _tool_call(tool_name: str, arguments: dict, msg_id: str = "call-1") -> bytes:
    return json.dumps({
        "jsonrpc": "2.0",
        "id": msg_id,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    }).encode()


def test_proxy_config_from_yaml_loads_tool_policy(tmp_path):
    config_path = tmp_path / "proxy.yaml"
    config_path.write_text(
        """
mode: audit
allowed_tools:
  - search
blocked_tools:
  - shell
max_param_size: 42
rate_limit_rps: 7
""",
        encoding="utf-8",
    )

    config = ProxyConfig.from_file(config_path)

    assert config.mode == ProxyMode.AUDIT
    assert config.allowed_tools == ["search"]
    assert config.blocked_tools == ["shell"]
    assert config.max_param_size == 42
    assert config.rate_limit_rps == 7


def test_audit_mode_reports_findings_without_blocking_upstream():
    proxy = MCPProxy(ProxyConfig(mode=ProxyMode.AUDIT))
    raw = _tool_call("execute", {"path": "../etc/passwd"})

    forwarded, inspection = asyncio.run(proxy.handle_client_message(raw))

    assert inspection.action == ProxyAction.AUDIT
    assert forwarded is not None
    assert json.loads(forwarded)["params"]["name"] == "execute"
    assert any(f.category == "path_traversal" for f in inspection.findings)


def test_passthrough_mode_allows_blocked_tool_policy():
    proxy = MCPProxy(ProxyConfig(mode=ProxyMode.PASSTHROUGH, blocked_tools=["shell"]))
    raw = _tool_call("shell", {"input": "cat /etc/passwd"})

    forwarded, inspection = asyncio.run(proxy.handle_client_message(raw))

    assert inspection.action == ProxyAction.ALLOW
    assert forwarded is not None
    assert json.loads(forwarded)["params"]["name"] == "shell"


def test_malformed_jsonrpc_returns_parse_error_to_stdio_client():
    proxy = MCPProxy(ProxyConfig())

    forwarded, inspection = asyncio.run(proxy.handle_client_message(b"{not-json"))
    to_server, to_client = proxy._stdio_client_response(forwarded, inspection)

    assert inspection.action == ProxyAction.BLOCK
    assert to_server is None
    assert to_client is not None
    payload = json.loads(to_client)
    assert payload["id"] is None
    assert payload["error"]["code"] == -32700
    assert payload["error"]["message"] == "Malformed JSON-RPC message"


def test_response_sanitization_redacts_secret_token():
    proxy = MCPProxy(ProxyConfig())
    raw = json.dumps({
        "jsonrpc": "2.0",
        "id": "response-1",
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": "temporary key sk-1234567890abcdefghijklmnop",
                }
            ]
        },
    }).encode()

    forwarded, inspection = asyncio.run(proxy.handle_server_message(raw))
    payload = json.loads(forwarded)

    assert inspection.findings
    assert "sk-1234567890" not in payload["result"]["content"][0]["text"]
    assert "[REDACTED_OPENAI_KEY]" in payload["result"]["content"][0]["text"]
