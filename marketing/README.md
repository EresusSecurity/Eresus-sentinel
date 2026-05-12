# Eresus Sentinel — Marketing Content

All copy is ready to paste. GIF assets are in `demos/` — upload to Imgur first,
then embed in Medium / LinkedIn via URL.

---

## Directory Structure

```
marketing/
├── linkedin/
│   ├── post-01-pickle-rce-PAS.md          ← PAS framework, Contrarian hook
│   ├── post-02-mcp-security-AIDA.md       ← AIDA framework, Number-led hook
│   ├── post-03-huggingface-supply-chain-BAB.md  ← BAB framework
│   ├── post-04-prompt-injection-SLAY.md   ← SLAY framework
│   └── post-05-sast-secrets-STAR.md       ← STAR framework
│
├── twitter/
│   ├── thread-01-pickle-rce.md            ← 7 tweets, attach malicious-detect.gif
│   ├── thread-02-mcp-security.md          ← 7 tweets, attach full-scan.gif
│   └── thread-03-ai-devsecops.md          ← 7 tweets, attach secrets.gif
│
├── medium/
│   ├── article-01-scanning-hf-models.md   ← ~1800 words, 3 GIFs
│   ├── article-02-llm-firewall.md         ← ~1900 words, 3 GIFs
│   └── article-03-mcp-agent-security.md   ← ~1800 words, 3 GIFs
│
├── hooks/
│   └── all-hooks.md                       ← 30 hook variations, 5 topics × 6 types
│
├── other/
│   ├── show-hn-post.md                    ← Hacker News Show HN
│   └── product-hunt-launch.md             ← Full PH launch copy + first comment
│
└── content-matrix.md                      ← 32 post ideas (4 pillars × 8 formats)
```

---

## GIF to Article Mapping

| GIF file | Used in |
|----------|---------|
| `demos/malicious-detect.gif` | LinkedIn post-01, Medium article-01, Twitter thread-01 tweet 4 |
| `demos/hf-scan.gif` | LinkedIn post-03, Medium article-01 |
| `demos/artifact.gif` | Medium article-01, Medium article-03 |
| `demos/firewall-v2.gif` | LinkedIn post-04, Medium article-02 |
| `demos/firewall.gif` | Medium article-02 |
| `demos/redteam.gif` | Medium article-02 |
| `demos/full-scan.gif` | LinkedIn post-02, Medium article-03, Twitter thread-02 tweet 5 |
| `demos/supply-chain.gif` | Medium article-03 |
| `demos/secrets.gif` | LinkedIn post-05, Twitter thread-03 tweet 3 |
| `demos/sast.gif` | Extra — use in future DevSecOps posts |
| `demos/fuzz.gif` | Extra — use in fuzzer / red team posts |
| `demos/benchmark.gif` | Extra — use in comparison posts |
| `demos/aibom.gif` | Extra — use in supply chain / AIBOM posts |

---

## Publish Order (Recommended)

### Week 1
- [ ] LinkedIn post-01 (Pickle RCE — PAS)
- [ ] Twitter thread-01 (Pickle RCE)
- [ ] Medium article-01 (HuggingFace scanning)

### Week 2
- [ ] Show HN post (timing: Mon/Tue 09:00–11:00 EST)
- [ ] LinkedIn post-02 (MCP Security — AIDA)
- [ ] Twitter thread-02 (MCP Security)

### Week 3
- [ ] Medium article-02 (LLM Firewall)
- [ ] LinkedIn post-04 (Prompt Injection — SLAY)
- [ ] Product Hunt launch

### Week 4
- [ ] Medium article-03 (MCP Agent Security)
- [ ] LinkedIn post-05 (SAST/Secrets — STAR)
- [ ] Twitter thread-03 (AI DevSecOps)

---

## Before Publishing Checklist

- [ ] GitHub repo is public
- [ ] PyPI package published (`pip install eresus-sentinel` works)
- [ ] GIFs uploaded to Imgur (or GitHub raw URLs work if repo is public)
- [ ] eresussec.com is live and docs are accessible
- [ ] GitHub Actions marketplace listing submitted (action.yml is ready)
