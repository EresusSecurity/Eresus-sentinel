# Twitter/X Thread 03 — AI DevSecOps / SAST
# Hook: Number-led
# GIF suggestion: demos/secrets.gif (attach to tweet 3)
# Topic pillar: AI DevSecOps

---

TWEET 1 (hook):
I ran a full SAST scan on an AI startup's codebase.

47 secrets. 6 high severity. Found 6 hours before the next prod deploy.

This is the security gap every fast-moving AI team has. 🧵

---

TWEET 2:
AI codebases have unique attack surface compared to standard web apps.

1. Model loading code that executes arbitrary files
2. API keys for 8+ external AI providers
3. Prompt templates with injection surface
4. Notebook files that bypass standard git scanning

Standard SAST tools miss most of this.

---

TWEET 3 (attach GIF: demos/secrets.gif):
The secrets problem is worse in AI repos.

You have keys for: OpenAI, Anthropic, HuggingFace, AWS, GCP, Pinecone, Weaviate, LangSmith.

And they rotate often, which means old keys get left in branches nobody cleans.

Git history is the richest attack surface in the whole codebase.

---

TWEET 4:
The fix is three layers:

1. Pre-commit hook that blocks secrets before they hit git
2. CI scan that checks the full history on every PR
3. SARIF upload so findings appear in GitHub Security tab automatically

None of these require changing how your team works.

---

TWEET 5:
Jupyter notebooks are a separate problem.

They store outputs inline including API responses, tokens, and credentials.
Standard git scanning does not parse .ipynb cell outputs.
They get committed and forgotten.

You need a notebook-aware scanner.

---

TWEET 6:
sentinel scan ./src --profile fast -f sarif

120+ secret patterns. Entropy analysis. Git history scan. Notebook cell inspection.

SARIF output direct to GitHub Security tab.

One command. No configuration needed to start.

---

TWEET 7 (CTA):
AI moves fast. Security usually trails by 12 months.

The teams that close that gap early do not slow down.

They just stop getting breached.

github.com/EresusSecurity/Eresus-sentinel
