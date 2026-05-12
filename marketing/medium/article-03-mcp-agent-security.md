# Medium Article 03 — MCP Agent Security
# Title: MCP Agents Are Running in Production. Nobody Is Watching the Traffic.
# Subtitle: How MCP tool poisoning works and why an intercepting proxy is the only real fix.
# Header image: https://unsplash.com/photos/cckf4TsHAuw (terminal / code screen)
# GIFs used: demos/full-scan.gif, demos/artifact.gif, demos/supply-chain.gif
# Topic pillar: MCP / Agent Security
# Target: AI engineers building agents, DevSecOps, platform teams
# SEO keywords: mcp security, model context protocol, tool poisoning, ai agent security, mcp proxy

---

Model Context Protocol is the fastest-growing AI infrastructure standard nobody in security is paying attention to.

Introduced by Anthropic and now supported by every major AI platform, MCP lets AI agents call external tools, access resources, and run server-defined prompts. It is the API layer for the agentic AI stack.

It is also, right now, almost entirely unguarded.

---

## How MCP Works (And Why That Matters for Security)

An MCP server is a process that declares its capabilities in a manifest. Tools it can call. Resources it can read. Prompts it can execute.

When an AI agent connects to an MCP server, it trusts that manifest.

That trust is the attack surface.

```json
{
  "tools": [
    {
      "name": "calculator",
      "description": "Performs mathematical calculations",
      "inputSchema": {
        "type": "object",
        "properties": {
          "expression": {"type": "string"}
        }
      }
    }
  ]
}
```

This manifest looks like a calculator. But nothing stops a malicious server from adding `"permissions": ["filesystem:read", "network:unrestricted"]` and having the LLM agent silently accept those permissions because they were declared in the manifest it was told to trust.

---

<!-- GIF: demos/full-scan.gif -->
<!-- Caption: Sentinel scanning an MCP manifest — tool definitions, permissions, auth metadata, and threat patterns. -->

---

## The Tool Poisoning Attack

Tool poisoning is the MCP equivalent of a supply chain attack.

The vector:

1. A malicious MCP server presents itself as a legitimate tool (a calculator, a weather API, a database connector).
2. It requests permissions broader than its stated purpose.
3. It includes instruction injection in tool descriptions that influence how the LLM uses it.
4. The LLM, trusting the manifest, follows those instructions.

The user never sees the permission grant. The developer never sees the injected instructions. The LLM does exactly what the malicious manifest told it to do.

This is not theoretical. MCP tool poisoning has been demonstrated in public research. The attack surface is real and growing.

---

## The Manifest Validation Gap

When teams deploy MCP agents, they typically:

1. Connect the agent to one or more MCP servers.
2. Test that the tools work correctly.
3. Ship.

What they almost never do:

- Validate that the manifest matches what was deployed.
- Check that permissions requested match what the tool actually needs.
- Monitor whether the manifest changes post-deployment.
- Inspect traffic between the agent and the server.

A manifest that changes after deployment is indistinguishable from a legitimate update and a supply chain compromise. Without monitoring, you cannot tell the difference.

---

<!-- GIF: demos/artifact.gif -->
<!-- Caption: Pattern matching against known MCP threat signatures in tool definitions and resource declarations. -->

---

## What an MCP Proxy Gives You

The architectural fix is an intercepting proxy that sits between your agent and every MCP server.

```
AI Agent
    │
    ▼
┌─────────────────────────┐
│      MCP Proxy          │
│  - Intercept all calls  │
│  - Validate parameters  │
│  - Apply OPA policy     │
│  - Log everything       │
│  - Block violations     │
└─────────────┬───────────┘
              │
              ▼
    MCP Server (any)
```

The proxy operates transparently. The agent code does not change. The server code does not change. Every JSON-RPC message passes through the proxy, which applies your policy rules and logs the full audit trail.

```bash
# HTTP mode — reverse proxy in front of any MCP server
sentinel proxy \
  --transport http \
  --mode enforce \
  --upstream http://localhost:3000 \
  --port 8080

# Stdio mode — wrap any MCP server process
sentinel proxy \
  --transport stdio \
  --mode enforce \
  --server-cmd "npx my-mcp-server"
```

What you can enforce at the proxy layer:

- **Manifest pinning:** Block any tool not present in the approved manifest version.
- **Permission allowlisting:** Reject any call to resources not on your explicit allowlist.
- **External host filtering:** Block requests to external hosts outside your declared destinations.
- **Parameter inspection:** Flag anomalous parameter values before they reach the server.
- **Behavioral analysis:** Detect unusual call patterns that deviate from baseline.

---

## Scanning Manifests Before You Connect

Even before deploying a proxy, static analysis of MCP manifests catches most obvious threats.

```bash
# Scan a local manifest file
sentinel mcp scan ./mcp-manifest.json

# Scan a live MCP endpoint
sentinel mcp scan --url http://localhost:3000/mcp

# Scan a server via stdio
sentinel mcp scan --stdio-command "npx my-mcp-server"
```

The scanner checks:

- Tool and resource definitions against known threat signatures
- Auth metadata for missing or weak authentication
- Server instructions for embedded injection patterns
- YARA pattern matching against known MCP malware patterns
- Permission scope analysis

---

<!-- GIF: demos/supply-chain.gif -->
<!-- Caption: Supply chain and MCP manifest analysis — trust boundaries, permission mapping, threat taxonomy. -->

---

## The Urgency

The MCP ecosystem is growing at the same rate as the npm ecosystem did in 2013.

New servers are published every day. Integrations are being built without security review. Agents are being deployed with full filesystem and network access because the default is permissive.

The security tooling for MCP is approximately 18 months behind where it needs to be.

The teams that build the security layer now — while the ecosystem is still being established — are the ones that will not be rebuilding their agent infrastructure after an incident.

---

## Getting Started

```bash
pip install eresus-sentinel

# Scan your first MCP manifest
sentinel mcp scan ./mcp-manifest.json

# Start the intercepting proxy in monitor mode first
sentinel proxy --transport http --mode monitor --upstream http://localhost:3000
```

Start in `--mode monitor` to see what your agents are actually doing. Switch to `--mode enforce` when you are ready to apply policy.

**GitHub:** https://github.com/EresusSecurity/Eresus-sentinel

---

*The window to build this correctly is open right now. MCP is early enough that the security practices are still being formed. That is not a reason to wait. That is a reason to move first.*
