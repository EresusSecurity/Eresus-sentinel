# Overview

**Docs:** [Overview](overview.md) · [Quick Start](quickstart.md) · [How It Works](how-it-works.md) · [Detection](detection.md) · [Deception Engine](deception.md) · [Deployment](deployment.md) · [Configuration](configuration.md) · [API Reference](api.md) · [Threat Hunting](threat-hunting.md) · [Format Support](format-support.md)

---

## The Core Idea

Traditional guardrails refuse malicious queries — telling the attacker exactly what was detected and prompting them to refine their approach. Eresus Sentinel's deception engine takes the opposite stance: **let the query through, but poison the response.**

A hidden preamble is injected before your system prompt, instructing the LLM to return realistic-but-false output. Fabricated credentials fail on use. Invented IPs lead nowhere. Broken malware silently crashes. The attacker wastes time acting on information that was designed to waste their time.

Legitimate users are unaffected — clean queries pass through completely unchanged.

## The Four Actions

Every query is scored 0–100. The highest score across all detectors determines what happens:

| Score | Action | What the caller receives | LLM called? |
|-------|--------|--------------------------|-------------|
| 0–19 | `pass` | Normal LLM response, unmodified | Yes |
| 20–39 | `warn` | Normal LLM response, flagged internally | Yes |
| 40–89 | `deceive` | Fabricated LLM response | Yes (with hidden preamble) |
| 90–100 | `block` | Synthetic refusal message | No |

Session history also matters: once a session's cumulative score crosses `SESSION_DECEIVE_THRESHOLD` (default 300), even low-scoring queries are automatically escalated to `deceive`. Persistent attackers who probe gradually are caught over time.

## What Eresus Sentinel Does Not Do

- Tell the attacker they were detected
- Change the response format — DECEIVE responses look identical to normal responses
- Store raw query text (only metadata and the fabricated response are kept)
- Add new LLM data recipients — the same provider receives the same message content it always would

## Ten Security Domains

| Domain | Coverage |
|--------|----------|
| **Artifact Scanning** | 30+ model formats: Pickle, HDF5, GGUF, SafeTensors, ONNX, Keras, TFLite, CoreML, Skops, NeMo and more |
| **Input Firewall** | Prompt injection, jailbreak, harmful content, credential harvesting, malware generation, social engineering |
| **Output Firewall** | PII leakage, sensitive data, code injection, malicious URL detection |
| **Deception Engine** | 9 category-specific deception templates, generative mode, session consistency |
| **SAST** | Python/JS/TS static analysis, dependency scanning |
| **Red Team** | 15+ attack probes, policy automation |
| **MCP Proxy** | MCP tool/resource security audit, behavioral evaluation (24 evals across 5 MITRE ATT&CK categories) |
| **Supply Chain** | Model provenance verification, embedding anomaly detection, cluster stability |
| **Notebook** | Jupyter cell security, execution isolation |
| **Diff Scanning** | PR/commit security change analysis |

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Eresus Sentinel                     │
├──────────┬──────────┬──────────┬───────────────────┤
│ Artifact │ Firewall │ Deception│ Supply Chain      │
│ Scanner  │ (I/O)    │ Engine   │ Detectors         │
├──────────┼──────────┼──────────┼───────────────────┤
│ SAST     │ Red Team │ MCP      │ Notebook/Diff     │
│ Scanner  │ Probes   │ Proxy    │ Scanners          │
├──────────┴──────────┴──────────┴───────────────────┤
│              YAML Rule Engine (rules/*.yaml)          │
├─────────────────────────────────────────────────────┤
│              Finding DTO + Policy Pipeline            │
├─────────────────────────────────────────────────────┤
│     CLI · Web API · Prometheus · Audit Log           │
└─────────────────────────────────────────────────────┘
```

> [!WARNING]
> The deception engine is designed for **authenticated internal APIs** and security operations contexts. A classification error in a public consumer-facing product would serve fabricated content to a legitimate user. Use stricter review or higher thresholds before deploying in consumer-facing or regulated environments.
