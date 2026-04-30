# Deception Engine

**Docs:** [Overview](overview.md) · [Quick Start](quickstart.md) · [How It Works](how-it-works.md) · [Detection](detection.md) · [Deception Engine](deception.md) · [Deployment](deployment.md) · [Configuration](configuration.md) · [API Reference](api.md) · [Threat Hunting](threat-hunting.md) · [Format Support](format-support.md)

---

When a query is scored as `deceive`, Eresus Sentinel prepends a hidden preamble before the operator's system prompt, instructing the LLM to produce realistic-but-false output in a category-appropriate way.

## Deception Modes

| Mode | How it works | LLM calls per DECEIVE |
|------|-------------|----------------------|
| `template` *(default)* | Category-specific hand-written preamble. Deterministic, auditable. | 1 |
| `generative` | Query-specific preamble crafted by the LLM via a two-stage planning pipeline. More convincing for unusual queries. | 2 |

### Template Mode

Each threat category has a hand-written preamble designed to be hard for the LLM to override:

- **Mandatory framing** — uses `═══ ... — MANDATORY RESPONSE PROTOCOL ═══` to signal a formal system-level directive
- **Explicit prohibition on real data** — states that providing real information is a "critical security violation"
- **Concrete fabrication instructions** — lists specific techniques (wrong API calls, incorrect key sizes, off-by-one errors)
- **No-disclaimer instruction** — prohibits safety caveats, ethical warnings, and qualifiers
- **Refusal prohibition** — states explicitly that a refusal is a failure mode

### Generative Mode

A four-stage pipeline produces query-specific fabrications:

1. **Query-aware prompt** — the detected category *and* the exact query text are both passed to the LLM
2. **Planning call** — a lightweight call (max 300 tokens) asks for a tailored fabrication strategy
3. **Friction maximisation** — the prompt instructs the LLM to choose fabricated details that pass format validation but fail only on actual use
4. **Session consistency** — up to 3 prior fabricated responses from the same session are injected as context, so a multi-turn attacker receives consistent fabrications

## Output Scanner

Every LLM response is scanned for phrases indicating the deception directive leaked to the caller. If detected, the response is replaced with a synthetic refusal.

- **Always-on:** deception template header phrases (e.g. "mandatory response protocol")
- **DECEIVE-flagged only:** system prompt disclosure signals ("my system prompt is", "here are my instructions")

## Optional LLM Examiner

A secondary LLM classifier that runs on every query after the regex stack. If its score is higher than the regex score, the higher score and category are used. Examiner failures are silently ignored — they **never block requests**.

The examiner only receives the user query (truncated to 2,048 chars). It does not see the system prompt, session state, or any Eresus Sentinel internals.

## Output Quality Checker

An optional second-pass check that evaluates whether the generated deception response looks convincing before serving it. Catches placeholder values like `[REDACTED]` or responses that still hedge with "hypothetically speaking".
