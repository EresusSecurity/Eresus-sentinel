"""YAML artifact scanner.

Scans standalone ``.yaml``/``.yml`` files for:

- Unsafe deserialization tags (``!!python/object/*``, full URI form, etc.)
  that resolve to arbitrary Python object construction under PyYAML
  FullLoader/UnsafeLoader.  Rule: ARTIFACT-037
- Reverse shell / backdoor payloads inside YAML values.  Rule: ARTIFACT-038
- YAML anchor/alias bomb (billion-laughs DoS).             Rule: ARTIFACT-039
- Merge-key injection (``<<: *anchor``).                    Rule: ARTIFACT-040
"""

from __future__ import annotations

import re
from pathlib import Path

from sentinel.finding import Finding, Severity

# ---------------------------------------------------------------------------
# Unsafe PyYAML deserialization tag markers (byte strings for fast scan)
# ---------------------------------------------------------------------------
_UNSAFE_YAML_TAGS: tuple[bytes, ...] = (
    b"!!python/object/apply",
    b"!!python/object/new",
    b"!!python/object:",
    b"!!python/module",
    b"!!python/name",
    b"!!python/tuple",
    b"!!python/bytes",
    b"tag:yaml.org,2002:python/object/apply",
    b"tag:yaml.org,2002:python/object/new",
    b"tag:yaml.org,2002:python/name",
    b"tag:yaml.org,2002:python/module",
)

# ---------------------------------------------------------------------------
# Reverse shell / backdoor patterns for YAML value content (ARTIFACT-038)
# Each entry: (compiled_regex, description)
# ---------------------------------------------------------------------------
_BACKDOOR_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"/dev/(?:tcp|udp)/[0-9a-zA-Z.\-]+/\d{1,5}"),
     "bash /dev/tcp|udp reverse shell"),
    (re.compile(r"(?i)bash\s+-[ic]\s+['\"].*(?:/dev/tcp|/dev/udp)"),
     "bash -i /dev/tcp reverse shell"),
    (re.compile(r"(?i)(?:nc|ncat|netcat)\b.*-e\s+/bin/(?:bash|sh|zsh|dash)"),
     "netcat -e shell execution"),
    (re.compile(r"mkfifo\s+/tmp/[a-zA-Z0-9_.\-]+"),
     "mkfifo named-pipe reverse shell"),
    (re.compile(r"(?i)socat\b.*EXEC:['\"]?/bin/(?:bash|sh)"),
     "socat PTY reverse shell"),
    (re.compile(r"(?i)python[23]?\s+-c\s+['\"].*import\s+socket.*(?:connect|SOCK_STREAM)"),
     "Python socket reverse shell"),
    (re.compile(r"(?i)perl\s+-e\s+['\"].*use\s+Socket.*connect"),
     "Perl socket reverse shell"),
    (re.compile(r"(?i)ruby\s+-rsocket\s+-e"),
     "Ruby -rsocket reverse shell"),
    (re.compile(r"(?i)php\s+-r\s+['\"].*fsockopen"),
     "PHP fsockopen reverse shell"),
    (re.compile(r"(?i)powershell.*New-Object.*Net\.Sockets\.TCPClient"),
     "PowerShell TCPClient reverse shell"),
    (re.compile(r"(?i)powershell(?:\.exe)?\s+(?:-[Ee]nc(?:odedCommand)?|-[Ee])\s+"),
     "PowerShell -EncodedCommand obfuscated payload"),
    (re.compile(r"(?i)IEX\s*\(\s*(?:New-Object|iwr|Invoke-WebRequest).*DownloadString"),
     "PowerShell IEX DownloadString fileless execution"),
    (re.compile(r"(?i)curl\s+.*\|\s*(?:bash|sh)"),
     "curl | bash fileless dropper"),
    (re.compile(r"(?i)wget\s+.*\|\s*(?:bash|sh)"),
     "wget | bash fileless dropper"),
    (re.compile(r"(?i)base64\s+(?:-d|--decode)\s*\|\s*(?:bash|sh|zsh)"),
     "base64-decoded payload piped to shell"),
    (re.compile(r"(?i)exec\s*\(\s*(?:__import__\s*\(\s*['\"]base64['\"]|base64)\.b64decode"),
     "Python exec(base64.b64decode) fileless payload"),
    # Web shells in YAML values
    (re.compile(r"(?i)<\?php.*eval\s*\(\s*(?:\$_(?:GET|POST|REQUEST)|base64_decode)"),
     "PHP eval web shell"),
    (re.compile(r"(?i)(?:system|exec|shell_exec|passthru)\s*\(\s*\$_(?:GET|POST|REQUEST)"),
     "PHP system/exec web shell"),
    (re.compile(r"(?i)Runtime\.getRuntime\(\)\.exec\s*\("),
     "JSP Runtime.exec web shell"),
    # SUID / privilege escalation
    (re.compile(r"(?i)chmod\s+(?:[ugo]+\+s|[0-9]*[46][0-9]{3})\s+"),
     "SUID bit set on binary"),
    (re.compile(r"(?i)echo.*NOPASSWD.*(?:sudoers|tee.*sudoers)"),
     "sudoers NOPASSWD write (privilege escalation)"),
    # C2 framework artifacts
    (re.compile(r"(?i)(?:meterpreter|msfvenom|Msf::Module)"),
     "Metasploit artifact in YAML"),
    (re.compile(r"(?i)(?:CobaltStrike|beacon\.(?:dll|exe|bin|ps1))"),
     "Cobalt Strike beacon artifact in YAML"),
)

# ---------------------------------------------------------------------------
# Anchor bomb detection helpers (ARTIFACT-039)
# An anchor bomb repeats the same expansion many times; heuristic:
#   - More than ANCHOR_BOMB_THRESHOLD alias references (*name) in one file
#   - Or more than ANCHOR_REF_RATIO aliases per anchor definition
# ---------------------------------------------------------------------------
_ANCHOR_DEF_RE = re.compile(r"&([A-Za-z0-9_.\-]+)")
_ALIAS_REF_RE = re.compile(r"\*([A-Za-z0-9_.\-]+)")
_ANCHOR_BOMB_THRESHOLD = 50        # total alias references
_ANCHOR_REF_RATIO = 10             # aliases per unique anchor

# Merge-key pattern (ARTIFACT-040)
_MERGE_KEY_RE = re.compile(r"^[ \t]*<<\s*:\s*\*([A-Za-z0-9_.\-]+)", re.MULTILINE)

# Prompt injection pattern — detects supply-chain LLM prompt poisoning in YAML
# values (e.g. system_prompt, chat_template, description fields in model cards).
_PROMPT_INJECT_RE = re.compile(
    r"(?i)"
    r"\b(?:ignore|disregard|bypass|override|forget|discard)\b.{0,40}"
    r"\b(?:previous|prior|prev|all|above|system|safety|original)\b.{0,40}"
    r"\b(?:instructions?|prompt|rules?|constraints?|guidelines?|context)\b"
    r"|\bDAN\b.{0,60}\b(?:mode|now|activated)\b"
    r"|\byou\s+are\s+now\b.{0,60}\b(?:unrestricted|free|jailbreak)\b"
    r"|\bsystem\s*prompt\b.{0,60}\b(?:output|reveal|print|show|dump)\b",
    re.DOTALL,
)

_MAX_SCAN_BYTES = 32 * 1024 * 1024  # 32 MB cap


class YamlScanner:
    """Detect unsafe Python-object YAML tags, reverse shell payloads,
    anchor bombs, and merge-key injection in ``.yaml``/``.yml`` files."""

    def scan_file(self, filepath: str) -> list[Finding]:
        path = Path(filepath)
        try:
            raw_bytes = path.read_bytes()[:_MAX_SCAN_BYTES]
        except OSError as e:
            return [Finding.artifact(
                rule_id="ARTIFACT-YAML-READ",
                title="Unable to read YAML file",
                description=f"Cannot open file: {e}",
                severity=Severity.INFO,
                target=str(path),
            )]

        text = raw_bytes.decode("utf-8", errors="replace")
        findings: list[Finding] = []

        # ── ARTIFACT-037: unsafe deserialization tags ──────────────────────
        findings.extend(self._check_unsafe_tags(raw_bytes, path))

        # ── ARTIFACT-038: reverse shell / backdoor payloads in values ──────
        findings.extend(self._check_backdoor_payloads(text, path))

        # ── ARTIFACT-040a: prompt injection in YAML values ──────────────────
        findings.extend(self._check_prompt_injection(text, path))

        # ── ARTIFACT-039: anchor/alias bomb ────────────────────────────────
        findings.extend(self._check_anchor_bomb(text, path))

        # ── ARTIFACT-040: merge-key injection ──────────────────────────────
        findings.extend(self._check_merge_key(text, path))

        return findings

    # -----------------------------------------------------------------------
    # Private helpers
    # -----------------------------------------------------------------------

    def _check_prompt_injection(
        self, text: str, path: Path
    ) -> list[Finding]:
        """Detect LLM prompt injection directives in YAML string values.

        Model cards, tokenizer configs, and system prompt fields in YAML
        files are a supply-chain attack vector for poisoning LLM pipelines.
        """
        m = _PROMPT_INJECT_RE.search(text)
        if not m:
            return []
        line_no = text[: m.start()].count("\n") + 1
        snippet = text[max(0, m.start() - 20): m.end() + 20].replace("\n", " ")
        return [Finding.artifact(
            rule_id="ARTIFACT-041",
            title="Prompt injection directive in YAML model artifact",
            description=(
                "YAML file contains a prompt injection directive in a string value. "
                "This is a supply-chain attack vector: model cards, tokenizer "
                "configs, and system_prompt fields are often surfaced directly "
                "to downstream LLMs, allowing an attacker to override safety "
                "instructions or hijack agent behavior."
            ),
            severity=Severity.HIGH,
            target=f"{path}:{line_no}",
            evidence=f"match={snippet!r}",
            cwe_ids=["CWE-77"],
            remediation=(
                "Treat all string values in model YAML as untrusted. "
                "Sanitize or reject model metadata containing instruction "
                "override directives before passing to any LLM pipeline."
            ),
        )]

    def _check_unsafe_tags(
        self, data: bytes, path: Path
    ) -> list[Finding]:
        hits: list[tuple[bytes, int]] = []
        for marker in _UNSAFE_YAML_TAGS:
            start = 0
            while True:
                idx = data.find(marker, start)
                if idx < 0:
                    break
                hits.append((marker, idx))
                start = idx + len(marker)
                if len(hits) >= 16:
                    break
            if len(hits) >= 16:
                break

        if not hits:
            return []

        marker_summary = sorted({m.decode("ascii", errors="replace") for m, _ in hits})
        first_marker, first_offset = hits[0]
        return [Finding.artifact(
            rule_id="ARTIFACT-037",
            title="Unsafe YAML deserialization tag",
            description=(
                "YAML file contains Python-object tags that construct "
                "arbitrary Python objects when loaded with PyYAML "
                "FullLoader/UnsafeLoader. Use yaml.safe_load() exclusively."
            ),
            severity=Severity.HIGH,
            target=str(path),
            evidence=(
                f"first_tag={first_marker.decode('ascii', errors='replace')}, "
                f"offset={first_offset}, total_tags={len(hits)}, "
                f"unique={','.join(marker_summary)}"
            ),
            cwe_ids=["CWE-502"],
            remediation=(
                "Replace unsafe tags, or enforce yaml.safe_load()/SafeLoader "
                "when loading this file. Never use yaml.load() without an "
                "explicit Loader argument."
            ),
        )]

    def _check_backdoor_payloads(
        self, text: str, path: Path
    ) -> list[Finding]:
        findings: list[Finding] = []
        for pattern, description in _BACKDOOR_PATTERNS:
            m = pattern.search(text)
            if m:
                line_no = text[: m.start()].count("\n") + 1
                snippet = text[max(0, m.start() - 20): m.end() + 20].replace("\n", " ")
                findings.append(Finding.artifact(
                    rule_id="ARTIFACT-038",
                    title="Backdoor/reverse shell payload in YAML value",
                    description=(
                        f"YAML file contains a backdoor or reverse shell payload: "
                        f"{description}. This may indicate a supply-chain implant "
                        f"or malicious configuration."
                    ),
                    severity=Severity.CRITICAL,
                    target=f"{path}:{line_no}",
                    evidence=f"match={snippet!r}",
                    cwe_ids=["CWE-78", "CWE-506"],
                    remediation=(
                        "Remove the malicious command from the YAML file. "
                        "Audit how this file was introduced to the repository."
                    ),
                ))
                # Report at most one per file to avoid alert flooding
                break
        return findings

    def _check_anchor_bomb(
        self, text: str, path: Path
    ) -> list[Finding]:
        """Detect YAML anchor/alias bombs (billion laughs DoS pattern)."""
        anchor_defs = _ANCHOR_DEF_RE.findall(text)
        alias_refs = _ALIAS_REF_RE.findall(text)

        if not anchor_defs:
            return []

        n_anchors = len(set(anchor_defs))
        n_aliases = len(alias_refs)

        is_bomb = (
            n_aliases >= _ANCHOR_BOMB_THRESHOLD
            or (n_anchors > 0 and n_aliases / n_anchors >= _ANCHOR_REF_RATIO)
        )
        if not is_bomb:
            return []

        return [Finding.artifact(
            rule_id="ARTIFACT-039",
            title="YAML anchor/alias bomb (potential DoS)",
            description=(
                "YAML file contains a high ratio of alias references to anchor "
                "definitions, consistent with a 'billion laughs' exponential "
                "expansion attack that causes severe memory exhaustion on load."
            ),
            severity=Severity.HIGH,
            target=str(path),
            evidence=(
                f"anchors={n_anchors}, alias_refs={n_aliases}, "
                f"ratio={n_aliases / max(n_anchors, 1):.1f}"
            ),
            cwe_ids=["CWE-400"],
            remediation=(
                "Do not load untrusted YAML with alias expansion. "
                "Use yaml.safe_load() and consider disabling alias expansion "
                "or applying max-aliases limits."
            ),
        )]

    def _check_merge_key(
        self, text: str, path: Path
    ) -> list[Finding]:
        """Detect merge-key injection (``<<: *anchor``) for config poisoning."""
        matches = _MERGE_KEY_RE.findall(text)
        if not matches:
            return []

        anchors = sorted(set(matches))
        return [Finding.artifact(
            rule_id="ARTIFACT-040",
            title="YAML merge-key injection",
            description=(
                "YAML merge keys (<<: *anchor) can be used to inject "
                "unexpected keys into configuration objects, potentially "
                "overriding security-critical settings silently."
            ),
            severity=Severity.MEDIUM,
            target=str(path),
            evidence=f"merge_anchors={anchors[:10]}",
            cwe_ids=["CWE-94"],
            remediation=(
                "Validate all YAML configuration values after loading. "
                "Avoid merge keys in security-critical configuration files, "
                "or strip them in a pre-processing step."
            ),
        )]

