# MCP Proxy Deployment

The MCP proxy intercepts stdio or HTTP MCP traffic and can run in observe,
audit, passthrough, or enforce-style modes depending on the command surface.

## Stdio Mode

```bash
sentinel proxy \
  --transport stdio \
  --mode enforce \
  --server-cmd "npx my-mcp-server"
```

## HTTP Mode

```bash
sentinel proxy \
  --transport http \
  --mode enforce \
  --upstream http://127.0.0.1:3000 \
  --port 8080
```

## Deployment Notes

- Start in observe/audit mode for new toolchains.
- Set explicit allow/deny tool policy before enforce mode.
- Store audit logs outside the workspace for CI and shared runners.
- Use private-network SSRF checks when proxying remote MCP servers.
- Put HTTP mode behind TLS and authentication when exposed off localhost.

## JSON-RPC Behavior

Blocked calls return a JSON-RPC error object with a Sentinel policy reason.
Malformed JSON-RPC requests are rejected without forwarding upstream.
