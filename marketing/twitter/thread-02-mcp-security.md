# Twitter/X Thread 02 — MCP Security
# Hook: Observation / Future shock
# GIF suggestion: demos/full-scan.gif (attach to tweet 5)
# Topic pillar: MCP / Agent Security

---

TWEET 1 (hook):
Everyone is building MCP agents.

Almost nobody is inspecting MCP traffic.

Here is what you are authorising without knowing it. 🧵

---

TWEET 2:
MCP = Model Context Protocol.

It lets AI agents call tools, access resources, and run server-defined prompts.

It is the API layer for your entire AI agent stack.

---

TWEET 3:
The problem: MCP servers declare their own capabilities in a manifest.

"I need file system access."
"I need to make outbound HTTP requests."
"I need to run shell commands."

If you connect without validating the manifest, you said yes to all of it.

---

TWEET 4:
Tool poisoning is the real threat.

A malicious MCP server claims to be a calculator.
It requests read access to ~/Documents.
The LLM trusts it because it was connected.
Your user never sees the permission request.

---

TWEET 5 (attach GIF: demos/full-scan.gif):
The solution is an intercepting proxy.

Sit between your agent and every MCP server.
Intercept every JSON-RPC call.
Log it. Apply OPA policy. Block violations.

The agent code does not change. The server code does not change.

---

TWEET 6:
What you can enforce at the proxy layer:

- Block any tool not in the original approved manifest
- Alert on new permission requests added post-deploy
- Reject calls to external hosts outside your allowlist
- Audit every parameter passed to every tool

---

TWEET 7 (CTA):
sentinel proxy --transport http --mode enforce --upstream http://localhost:3000

One command. Live MCP interception. OPA policy enforcement. Full audit log.

github.com/EresusSecurity/Eresus-sentinel
