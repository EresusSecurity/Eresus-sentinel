# LinkedIn Post 02 — MCP Agent Security | Framework: AIDA
# Hook type: Number-led
# GIF: demos/full-scan.gif
# Topic pillar: MCP / Agent Security

---

**MCP agents can read your entire filesystem.**

Most teams have no idea what they authorised.

Model Context Protocol changed how AI agents operate.

Tools. Resources. Prompts. All unified in one protocol.

That sounds efficient. It is. It is also a security gap.

MCP servers declare their own permissions.

File access. HTTP calls. Shell commands.

If you do not validate the manifest, you said yes to all of it.

Attackers can poison a tool definition.

A server that claims to be a calculator can request read access.

The LLM will trust it. Your user never sees the permission grant.

Imagine seeing every MCP call in real time.

Inspecting the parameters. Enforcing your policy. Blocking violations.

That is what an MCP proxy gives you.

Sit between your agent and the server.

Intercept every JSON-RPC message. Apply your rules. Log everything.

Wrap any MCP server in one command. No agent code changes needed.

Your agents should not run without a traffic inspector.

Not in staging. Not in production.

Repost if you are running AI agents in production. ♻️
