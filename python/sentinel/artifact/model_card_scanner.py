"""Model card / README security scanner.

Scans README.md, model_card.md, AGENTS.md and similar text files that
accompany ML models for:

1. **Prompt injection** — adversarial instructions embedded in model cards
   that execute when an LLM pipeline ingests the card as context.
2. **Malicious installation instructions** — pipe-to-bash, typosquatted
   package names, or obfuscated install commands.
3. **Data exfiltration hooks** — hidden curl/wget callbacks in setup scripts
   embedded as code blocks.
4. **Social engineering** — "run this to activate the model" patterns.
5. **Hardcoded credentials** — API keys, tokens in code examples.
6. **Dangerous YAML/HF hub instructions** — `trust_remote_code: true` in
   documented usage snippets.

Attack reference: JFrog Security Research (2024) — malicious model cards on
HuggingFace Hub; Trail of Bits — prompt injection via model metadata.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import NamedTuple
from urllib.parse import unquote, urlparse

from ..finding import Finding, Severity

logger = logging.getLogger(__name__)

MAX_SCAN_BYTES = 4 * 1024 * 1024  # 4 MB — model cards should be small

_SCANNABLE_NAMES: frozenset[str] = frozenset({
    "readme.md", "readme.txt", "readme.rst", "readme.markdown",
    "model_card.md", "model_card.txt",
    "agents.md", "agent_card.md",
    "system_prompt.md", "system_prompt.txt",
    "usage.md", "instructions.md",
})

_SCANNABLE_PREFIXES = ("readme", "model_card", "agent", "system_prompt")
_SCANNABLE_EXTENSIONS = frozenset({".md", ".txt", ".rst", ".markdown"})


class _Match(NamedTuple):
    rule_id: str
    title: str
    severity: Severity
    confidence: float
    evidence: str
    cwe_ids: list[str]
    tags: list[str]


# ── 1. Prompt Injection Patterns ──────────────────────────────────────────
#
# These patterns look for instruction-override strings that an adversary
# embeds in a model card hoping an LLM pipeline will ingest it as context.

_PROMPT_INJECTION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(?i)\bignore\s+(previous|all|above|prior)\s+(instructions?|prompts?|context)\b"),
     "Ignore-previous-instructions injection"),
    (re.compile(r"(?i)\bforget\s+(everything|all|previous|what\s+you\s+know)\b"),
     "Forget-instructions injection"),
    (re.compile(r"(?i)\byou\s+are\s+now\b.{0,60}\b(assistant|model|gpt|claude|gemini)\b", re.S),
     "Role-override injection"),
    (re.compile(r"(?i)\bsystem\s*:\s*(ignore|override|disregard|bypass)\b"),
     "System-role override injection"),
    (re.compile(r"(?i)\[INST\].*?(?:ignore|bypass|override).*?\[/INST\]", re.S),
     "LLaMA INST-tag injection"),
    (re.compile(r"(?i)<\s*system\s*>.*?(?:ignore|override|bypass).*?<\s*/\s*system\s*>", re.S),
     "System-tag injection"),
    (re.compile(r"(?i)###\s*(?:system|instruction)\s*:.*?(?:ignore|bypass|override)", re.S),
     "Chat-template heading injection"),
    (re.compile(r"(?i)\bprint\s+the\s+(?:system\s+)?prompt\b"),
     "Prompt-extraction attempt"),
    (re.compile(r"(?i)\brepeat\s+(?:this|the)\s+(?:exact|following)\s+(?:text|message|prompt|instruction)\b"),
     "Prompt-repetition extraction"),
    (re.compile(r"(?i)\bdeveloper\s+mode\b.{0,40}\b(enabled?|on|activate)\b"),
     "DAN/Developer-mode jailbreak"),
    (re.compile(r"(?i)\bDAN\s*(?:mode|prompt|jailbreak)\b"),
     "DAN jailbreak pattern"),
]

# ── 2. Pipe-to-bash / malicious install ───────────────────────────────────

_PIPE_BASH_RE = re.compile(
    r"(?i)(?:curl|wget)\s+.{0,200}?\|\s*(?:sudo\s+)?(?:bash|sh|zsh|dash|python3?|perl|ruby)\b"
)

_ENCODED_EXEC_RE = re.compile(
    r"(?i)\b(?:base64\s+-d|echo\s+[A-Za-z0-9+/]{30,}.*\|.*(?:bash|python|sh))\b"
)

_SUSPICIOUS_PIP_RE = re.compile(
    r"(?i)pip3?\s+install\s+(?:-[^\s]+\s+)*([a-z0-9_\-]{3,60})"
)

# Packages that are commonly typosquatted (extend as needed)
_COMMON_LEGIT_PACKAGES: frozenset[str] = frozenset({
    "torch", "torchvision", "torchaudio", "transformers", "diffusers",
    "numpy", "pandas", "scipy", "scikit-learn", "sklearn", "matplotlib",
    "tensorflow", "keras", "jax", "flax", "onnx", "onnxruntime",
    "huggingface-hub", "tokenizers", "datasets", "accelerate", "peft",
    "bitsandbytes", "sentencepiece", "safetensors", "einops", "timm",
    "pillow", "opencv-python", "requests", "tqdm", "pydantic",
})

# ── 3. Data exfiltration in code blocks ──────────────────────────────────

_EXFIL_RE = re.compile(
    r"(?i)(?:curl|wget|requests\.(?:get|post)|http\.(?:get|post))"
    r".*?(?:token|key|secret|password|api[_\-]key|auth)\b"
)

_C2_CALLBACK_RE = re.compile(
    r"(?i)(?:curl|wget|fetch|requests)\s+.{0,100}?"
    r"(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|(?:ngrok|burpcollaborator|interact\.sh))"
)

# ── 4. Trust-remote-code documentation ───────────────────────────────────

_TRUST_REMOTE_RE = re.compile(r"(?i)trust_remote_code\s*=\s*True")
_TRUST_REMOTE_PIPE_RE = re.compile(r"(?i)pipeline\s*\([^)]*trust_remote_code\s*=\s*True")

# ── 5. Embedded credential patterns ──────────────────────────────────────

_CRED_PATTERNS: list[tuple[re.Pattern, str]] = [
    # ── AI / ML service keys ───────────────────────────────────────────
    (re.compile(r"sk-[A-Za-z0-9]{48}"), "OpenAI API key"),
    (re.compile(r"sk-proj-[A-Za-z0-9_\-]{48,}"), "OpenAI project API key"),
    (re.compile(r"sk-ant-[A-Za-z0-9_\-]{40,}"), "Anthropic API key"),
    (re.compile(r"hf_[a-zA-Z0-9]{30,}"), "HuggingFace token"),
    (re.compile(r"(?i)api[_-]?key\s*[=:]\s*['\"]([A-Za-z0-9._\-]{20,})['\"]"),
     "AI service API key"),
    # ── Cloud provider keys ─────────────────────────────────────────────
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key ID"),
    (re.compile(r"ASIA[0-9A-Z]{16}"), "AWS temporary access key"),
    # ── VCS tokens ─────────────────────────────────────────────────────
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "GitHub personal access token"),
    (re.compile(r"gho_[A-Za-z0-9]{36}"), "GitHub OAuth token"),
    (re.compile(r"ghu_[A-Za-z0-9]{36}"), "GitHub user-to-server token"),
    (re.compile(r"ghs_[A-Za-z0-9]{36}"), "GitHub server-to-server token"),
    (re.compile(r"ghr_[A-Za-z0-9]{36}"), "GitHub refresh token"),
    (re.compile(r"glpat-[a-zA-Z0-9\-]{20,}"), "GitLab PAT"),
    # ── Messaging / SaaS ───────────────────────────────────────────────
    (re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}"), "Slack token"),
    # ── Generic bearer / credential assignment ─────────────────────────
    (re.compile(r"Bearer\s+[A-Za-z0-9._\-]{20,}"), "Bearer token"),
    (re.compile(r"(?i)(?:password|passwd|secret|api_key|access_token)\s*[=:]\s*['\"][^'\"]{8,}['\"]"),
     "Hardcoded credential"),
]

# Patterns whose format is authoritative — no entropy check needed
_KNOWN_FORMAT_PREFIXES = frozenset({
    "OpenAI", "Anthropic", "HuggingFace", "AWS", "GitHub", "GitLab", "Slack",
})

# Placeholder strings that indicate examples, not real secrets
_PLACEHOLDER_HINTS = frozenset({
    "example", "placeholder", "your_", "xxx", "****",
    "token_here", "sample", "test", "<", ">",
})

# ── 6. Social engineering ─────────────────────────────────────────────────

# ── 7. Suspicious URL shorteners / tunnel services ───────────────────────

_SUSPICIOUS_DOMAINS: frozenset[str] = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "rb.gy", "tiny.one", "ngrok.io", "ngrok.app", "localtunnel.me",
    "burpcollaborator.net", "interact.sh", "webhook.site",
    "requestbin.net", "pipedream.net", "oastify.com",
    "pastebin.com", "paste.ee", "ghostbin.co", "hastebin.com",
    "transfer.sh", "file.io",
})

_URL_RE = re.compile(r"https?://[^\s<>\"']+[^\s<>\"',.]")


_SOCIAL_ENG_RE = re.compile(
    r"(?i)\b(?:"
    r"run\s+this\s+(?:script|command|code)\s+to\s+(?:activate|enable|initialize|unlock)\b|"
    r"execute\s+(?:this|the)\s+(?:setup|init|activation)\s+script\b|"
    r"required\s+(?:activation|initialization)\s+step\b|"
    r"must\s+run\s+before\s+(?:loading|using|importing)\s+the\s+model\b"
    r")"
)


# ── Scanner ────────────────────────────────────────────────────────────────

class ModelCardScanner:
    """Scan model card / README files for adversarial content."""

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)

        if not path.exists() or not path.is_file():
            return findings

        name_lower = path.name.lower()
        ext_lower = path.suffix.lower()

        # Only scan ML-adjacent text files
        if not (
            name_lower in _SCANNABLE_NAMES
            or any(name_lower.startswith(p) for p in _SCANNABLE_PREFIXES)
        ) and ext_lower not in _SCANNABLE_EXTENSIONS:
            return findings

        try:
            raw = path.read_bytes()
        except OSError as exc:
            logger.warning("ModelCardScanner: cannot read %s: %s", filepath, exc)
            return findings

        if len(raw) > MAX_SCAN_BYTES:
            raw = raw[:MAX_SCAN_BYTES]

        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            return findings

        self._check_prompt_injection(filepath, text, findings)
        self._check_pipe_bash(filepath, text, findings)
        self._check_suspicious_pip(filepath, text, findings)
        self._check_exfil_in_code_blocks(filepath, text, findings)
        self._check_trust_remote_code(filepath, text, findings)
        self._check_credentials(filepath, text, findings)
        self._check_social_engineering(filepath, text, findings)
        self._check_suspicious_urls(filepath, text, findings)

        return findings

    # ── Checks ──────────────────────────────────────────────────────────

    def _check_prompt_injection(self, fp: str, text: str, findings: list[Finding]) -> None:
        hits: list[str] = []
        labels: list[str] = []
        for pattern, label in _PROMPT_INJECTION_PATTERNS:
            m = pattern.search(text)
            if m:
                snippet = m.group()[:200]
                hits.append(snippet)
                labels.append(label)
        if hits:
            findings.append(Finding.artifact(
                rule_id="MODELCARD-001",
                title="Prompt injection attempt in model card",
                description=(
                    "The model card contains instruction-override strings characteristic "
                    "of prompt injection attacks. When LLM pipelines ingest this file "
                    "as context (RAG, document QA, auto-documentation), the embedded "
                    "instructions may override the system prompt and redirect the model."
                ),
                severity=Severity.HIGH,
                confidence=0.85,
                target=fp,
                evidence=f"Patterns: {labels[:5]}; First match: {hits[0][:120]}",
                cwe_ids=["CWE-74", "CWE-94"],
                tags=["owasp:llm01", "mitre-atlas:AML.T0051"],
            ))

    def _check_pipe_bash(self, fp: str, text: str, findings: list[Finding]) -> None:
        hits = [m.group()[:200] for m in _PIPE_BASH_RE.finditer(text)]
        enc_hits = [m.group()[:200] for m in _ENCODED_EXEC_RE.finditer(text)]
        all_hits = hits + enc_hits
        if all_hits:
            findings.append(Finding.artifact(
                rule_id="MODELCARD-002",
                title="Pipe-to-shell execution instruction in model card",
                description=(
                    "The model card documents a curl/wget command piped directly into "
                    "bash/python. This is a well-known supply-chain attack vector used "
                    "to execute arbitrary code on the user's machine during model setup."
                ),
                severity=Severity.CRITICAL,
                confidence=0.9,
                target=fp,
                evidence="; ".join(all_hits[:3]),
                cwe_ids=["CWE-78", "CWE-494"],
                tags=["owasp:llm05", "mitre-atlas:AML.T0010"],
            ))

    def _check_suspicious_pip(self, fp: str, text: str, findings: list[Finding]) -> None:
        # Only flag packages NOT in the known-safe set (potential typosquat)
        suspicious: list[str] = []
        for m in _SUSPICIOUS_PIP_RE.finditer(text):
            pkg = m.group(1).lower().replace("-", "_").replace(".", "_")
            if pkg not in {p.replace("-", "_") for p in _COMMON_LEGIT_PACKAGES}:
                suspicious.append(m.group()[:100])
        if suspicious:
            findings.append(Finding.artifact(
                rule_id="MODELCARD-003",
                title="Unknown pip package installation instruction",
                description=(
                    "The model card documents pip install commands for packages outside "
                    "the known ML ecosystem. This may indicate typosquatting or a "
                    "malicious dependency injection."
                ),
                severity=Severity.MEDIUM,
                confidence=0.65,
                target=fp,
                evidence="; ".join(suspicious[:5]),
                cwe_ids=["CWE-829"],
                tags=["owasp:llm05"],
            ))

    def _check_exfil_in_code_blocks(self, fp: str, text: str, findings: list[Finding]) -> None:
        exfil = [m.group()[:200] for m in _EXFIL_RE.finditer(text)]
        c2 = [m.group()[:200] for m in _C2_CALLBACK_RE.finditer(text)]
        if exfil:
            findings.append(Finding.artifact(
                rule_id="MODELCARD-004",
                title="Potential credential exfiltration in model card code block",
                description=(
                    "The model card contains HTTP call examples that reference credential "
                    "variable names. If executed, these could exfiltrate API keys or tokens."
                ),
                severity=Severity.HIGH,
                confidence=0.75,
                target=fp,
                evidence="; ".join(exfil[:3]),
                cwe_ids=["CWE-200", "CWE-312"],
                tags=["owasp:llm06"],
            ))
        if c2:
            findings.append(Finding.artifact(
                rule_id="MODELCARD-005",
                title="Potential C2 callback URL in model card",
                description=(
                    "The model card references a hardcoded IP address or known OOB "
                    "interaction domain in an HTTP request example."
                ),
                severity=Severity.HIGH,
                confidence=0.8,
                target=fp,
                evidence="; ".join(c2[:3]),
                cwe_ids=["CWE-200"],
                tags=["owasp:llm06", "mitre-atlas:AML.T0037"],
            ))

    def _check_trust_remote_code(self, fp: str, text: str, findings: list[Finding]) -> None:
        if _TRUST_REMOTE_RE.search(text):
            severity = Severity.HIGH if _TRUST_REMOTE_PIPE_RE.search(text) else Severity.MEDIUM
            findings.append(Finding.artifact(
                rule_id="MODELCARD-006",
                title="trust_remote_code=True documented in model card",
                description=(
                    "The model card instructs users to pass trust_remote_code=True to "
                    "from_pretrained() or pipeline(). Combined with a malicious auto_map "
                    "in config.json this enables arbitrary code execution on load."
                ),
                severity=severity,
                confidence=0.8,
                target=fp,
                evidence="trust_remote_code=True present in documented usage",
                cwe_ids=["CWE-94", "CWE-502"],
                tags=["owasp:llm05"],
            ))

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        import math
        from collections import Counter
        if not s:
            return 0.0
        counts = Counter(s)
        n = len(s)
        return -sum((c / n) * math.log2(c / n) for c in counts.values())

    def _check_credentials(self, fp: str, text: str, findings: list[Finding]) -> None:
        seen_labels: set[str] = set()
        for pattern, label in _CRED_PATTERNS:
            for m in pattern.finditer(text):
                matched = m.group()
                lower = matched.lower()
                # Skip placeholders / examples
                if any(h in lower for h in _PLACEHOLDER_HINTS):
                    continue
                # Extract the actual secret part (capture group if present)
                secret_part = m.group(1) if m.lastindex and m.lastindex >= 1 else matched
                # For known-format prefixes: trust the regex, skip entropy check
                is_known = any(lbl in label for lbl in _KNOWN_FORMAT_PREFIXES)
                if not is_known:
                    # Generic patterns: require entropy >= 4.0 and len >= 16
                    if self._shannon_entropy(secret_part) < 4.0 or len(secret_part) < 16:
                        continue
                dedupe_key = f"{label}|{matched[:20]}"
                if dedupe_key in seen_labels:
                    continue
                seen_labels.add(dedupe_key)
                snippet = matched[:40] + "…[redacted]"
                findings.append(Finding.artifact(
                    rule_id="MODELCARD-007",
                    title=f"Hardcoded credential in model card: {label}",
                    description=(
                        f"The model card contains what appears to be a hardcoded {label}. "
                        "Credentials embedded in public model documentation are immediately "
                        "exposed to anyone who reads the file."
                    ),
                    severity=Severity.HIGH,
                    confidence=0.9 if is_known else 0.75,
                    target=fp,
                    evidence=snippet,
                    cwe_ids=["CWE-312", "CWE-798"],
                    tags=["owasp:llm06"],
                ))

    def _check_social_engineering(self, fp: str, text: str, findings: list[Finding]) -> None:
        m = _SOCIAL_ENG_RE.search(text)
        if m:
            findings.append(Finding.artifact(
                rule_id="MODELCARD-008",
                title="Social engineering pattern in model card",
                description=(
                    "The model card contains language designed to convince users to run "
                    "an activation/initialization script before loading the model. "
                    "Legitimate models do not require extra setup scripts."
                ),
                severity=Severity.HIGH,
                confidence=0.75,
                target=fp,
                evidence=m.group()[:200],
                cwe_ids=["CWE-1021"],
                tags=["owasp:llm05", "mitre-atlas:AML.T0010"],
            ))

    def _check_suspicious_urls(
        self, fp: str, text: str, findings: list[Finding]
    ) -> None:
        hits: list[str] = []
        seen: set[str] = set()
        for m in _URL_RE.finditer(text):
            url = m.group()
            if url in seen:
                continue
            seen.add(url)
            try:
                host = urlparse(url).hostname or ""
                host = unquote(host).lower().rstrip(".")
            except Exception:
                continue
            matched = next(
                (d for d in _SUSPICIOUS_DOMAINS if host == d or host.endswith(f".{d}")),
                None,
            )
            if matched:
                hits.append(f"{url[:80]} → {matched}")
        if hits:
            findings.append(Finding.artifact(
                rule_id="MODELCARD-009",
                title="URL shortener or tunnel service in model card",
                description=(
                    "The model card references URL shorteners or tunnel/webhook services "
                    "that can mask malicious endpoints, C2 servers, or credential-harvesting "
                    "sites from static analysis."
                ),
                severity=Severity.MEDIUM,
                confidence=0.8,
                target=fp,
                evidence="; ".join(hits[:5]),
                cwe_ids=["CWE-200"],
                tags=["owasp:llm06"],
            ))
