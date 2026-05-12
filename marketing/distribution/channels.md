# Distribution Channels — Eresus Sentinel
# All platforms where content should be published

---

## TIER 1 — Highest Impact (Do First)

### Hacker News
- Show HN post → see other/show-hn-post.md
- Ask HN: "How are you securing your ML model supply chain in 2026?"
- Timing: Tuesday 10:00 EST
- Front page = thousands of GitHub stars, PyPI downloads overnight

### dev.to
- Cross-post all 3 Medium articles with canonical tag
- Add to top of every article:
  canonical_url: https://medium.com/your-article-url
- Free dofollow backlink per article, indexes fast on Google

### Hashnode
- Connect to blog.eresussec.com (own domain = SEO goes to your site)
- Publish all articles here instead of Medium if possible
- Hashnode → your domain authority, not Medium's

---

## TIER 2 — Community Traffic

### Reddit
| Subreddit          | Post type  | Topic                        |
|--------------------|------------|------------------------------|
| r/MachineLearning  | Discussion | Pickle RCE finding           |
| r/netsec           | Link       | Medium article link          |
| r/LocalLLaMA       | Discussion | GGUF/safetensors scanner     |
| r/cybersecurity    | Discussion | MCP agent security           |
| r/Python           | Show&Tell  | pip install eresus-sentinel  |
| r/devops           | Discussion | CI/CD SARIF integration      |
| r/AISecOps         | Everything | Primary home base            |

### Discord Servers
- Hugging Face Discord → #tools-and-tips
- LangChain Discord → #security
- OWASP Slack → #llm-ai-security
- MLOps Community Discord → artifact scanning topic

---

## TIER 3 — SEO Backlinks

### Awesome Lists (GitHub PR = permanent dofollow backlink)
- awesome-mlsec → add as model artifact scanner
- awesome-llm-security → input/output firewall + MCP proxy
- awesome-mcp → MCP scanner + proxy
- awesome-devsecops → SAST + SARIF integration
- awesome-ai-tools → general AI toolkit

### Directory Listings
| Site                    | Category               | Priority |
|-------------------------|------------------------|----------|
| alternativeto.net       | Rebuff/Guardrails alt  | HIGH     |
| toolify.ai              | AI security tool       | HIGH     |
| taaft.com               | Security               | MED      |
| futurepedia.io          | AI toolkit             | MED      |
| saashub.com             | Security software      | LOW      |
| sourceforge.net         | Open source tool       | LOW      |
| slant.co                | Best LLM security list | LOW      |

---

## TIER 4 — Technical Publishing

### arXiv / Papers With Code
- Short technical report: "Deterministic Static Analysis for ML Model Artifact Security"
- Benchmark results (fickling vs sentinel parity tests already exist in tests/)
- Papers With Code listing → Google Scholar + academic citations

### OWASP
- OWASP LLM Top 10 project page → tool list PR
- OWASP AI Security Guide → reference list addition

### GitHub Marketplace
- action.yml already exists → submit Actions Marketplace listing
- Name: "Sentinel Security Scan"
- Every marketplace tool gets organic traffic

---

## TIER 5 — Security Media

| Platform              | What to submit                      | Audience        |
|-----------------------|-------------------------------------|-----------------|
| Security Boulevard    | Guest post: MCP security article    | DA 60+, DevSec  |
| The Hacker News (THN) | Press release or guest post         | 1M+ readers     |
| Dark Reading          | Contributed article                 | Enterprise      |
| InfoSecurity Magazine | Contributed article                 | CISOs           |
| DEF CON CFP           | "MCP Agent Security: New Attack Surface" | Researchers |
| Black Hat Arsenal     | Tool demo submission                | Developers      |

---

## TIER 6 — Video

### YouTube (5-8 min each)
1. "Scanning a Malicious PyTorch Model — Live Demo" → use malicious-detect.gif as thumbnail
2. "MCP Proxy Setup in 60 Seconds"
3. "Add AI Security to GitHub Actions in 10 Minutes"

YouTube description: pip install eresus-sentinel + GitHub link = SEO backlink

### Loom
- Faster: record terminal sessions with Loom
- Embed directly in LinkedIn posts for 3x more engagement

---

## SEO Keyword Map

| Article / Page             | Primary Keyword              | Secondary Keywords                                  |
|----------------------------|------------------------------|-----------------------------------------------------|
| article-01-hf-models       | huggingface model security   | torch.load vulnerability, pickle rce python         |
| article-02-llm-firewall    | llm prompt injection defense | llm firewall, prompt injection fix                  |
| article-03-mcp-security    | mcp security                 | model context protocol security, ai agent security  |
| future: SAST               | ai code security scanner     | sast for machine learning, ai secrets detection     |
| future: supply chain       | ml supply chain security     | model provenance, huggingface safe download         |
| homepage                   | ai security toolkit          | mlsecops, llm security platform, model scanning     |

Every article: primary keyword in H1, first H2, meta description, and URL slug.
Hashnode gives you control over all of these.
