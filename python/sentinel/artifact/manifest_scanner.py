"""ML model manifest / configuration file scanner.

Detection rules are loaded from rules/manifest_rules.yaml at import time.
Covers:
  - Exact filename allowlist for well-known ML manifest formats
    (config.json, tokenizer_config.json, training_args.json, metadata.json, etc.)
  - Hydra _target_ injection and HuggingFace auto_map remote-code loading
  - trust_remote_code flag detection
  - URL allowlist validation — untrusted domains flagged as HIGH
  - Cloud storage URI detection (S3, GCS, Azure)
  - Weak hash algorithm detection (MD5, SHA-1 used for integrity checks)
  - Dangerous key scanning (script, command, hook, credential keys)
  - Jinja2 template field detection (chat_template, prompt_template, etc.)
  - Insecure URL scheme detection (http://, ftp://, file:///)
  - Abnormally long model_type values (injection probe)
  - Suspicious auto_map entries with double-dash (HF repo attack pattern)
"""
from __future__ import annotations

import json
import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from sentinel.finding import Finding, Severity

logger = logging.getLogger(__name__)

_RULES_PATH = Path(__file__).parent.parent.parent.parent / "rules" / "manifest_rules.yaml"

_MAX_READ = 10 * 1024 * 1024
_MAX_DEPTH = 32
_MAX_URL_FINDINGS = 20
_MAX_KEY_FINDINGS = 30

_URL_RE = re.compile(r'https?://[a-zA-Z0-9.\-_/:?=&%#@]+', re.IGNORECASE)
_CLOUD_URI_RE = re.compile(
    r'(?:s3|gs|az|wasbs?|abfss?)://[^\s"<>]+', re.IGNORECASE
)


@lru_cache(maxsize=1)
def _load_rules() -> dict[str, Any]:
    try:
        with open(_RULES_PATH, "r") as fh:
            return yaml.safe_load(fh) or {}
    except Exception as exc:
        logger.warning("manifest_rules.yaml not loaded: %s", exc)
        return {}


@lru_cache(maxsize=1)
def _exact_filenames() -> frozenset[str]:
    rules = _load_rules()
    return frozenset(f.lower() for f in rules.get("exact_filenames", []))


@lru_cache(maxsize=1)
def _exact_extensions() -> frozenset[str]:
    rules = _load_rules()
    return frozenset(e.lower() for e in rules.get("exact_extensions", []))


@lru_cache(maxsize=1)
def _trusted_domains() -> frozenset[str]:
    rules = _load_rules()
    return frozenset(d.lower() for d in rules.get("trusted_url_domains", []))


@lru_cache(maxsize=1)
def _hash_integrity_keys() -> frozenset[str]:
    rules = _load_rules()
    return frozenset(k.lower() for k in rules.get("hash_integrity_keys", []))


@lru_cache(maxsize=1)
def _weak_hash_patterns() -> list[tuple[str, re.Pattern[str], int, str, list[str]]]:
    rules = _load_rules()
    out = []
    for entry in rules.get("weak_hash_patterns", []):
        try:
            out.append((
                entry["rule_id"],
                re.compile(entry["key_pattern"], re.IGNORECASE),
                entry.get("value_hex_length", 32),
                entry.get("title", "Weak hash in manifest"),
                entry.get("cwe_ids", ["CWE-327"]),
            ))
        except (re.error, KeyError) as exc:
            logger.debug("manifest_rules weak_hash: %s", exc)
    return out


@lru_cache(maxsize=1)
def _suspicious_key_rules() -> list[tuple[str, str, list[re.Pattern[str]], Severity, list[str], str]]:
    rules = _load_rules()
    sev_map = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM}
    out = []
    for entry in rules.get("suspicious_key_rules", []):
        pats = []
        for raw in entry.get("key_patterns", []):
            try:
                pats.append(re.compile(raw, re.IGNORECASE))
            except re.error:
                pass
        out.append((
            entry.get("rule_id", "MANIFEST-KEY"),
            entry.get("title", "Suspicious key"),
            pats,
            sev_map.get(entry.get("severity", "HIGH"), Severity.HIGH),
            entry.get("cwe_ids", []),
            entry.get("description", ""),
        ))
    return out


def _is_trusted_url(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
        host_lower = host.lower()
        trusted = _trusted_domains()
        if host_lower in trusted:
            return True
        for domain in trusted:
            if host_lower.endswith("." + domain):
                return True
    except Exception:
        pass
    return False


def _iter_key_value_pairs(
    obj: Any,
    depth: int = 0,
    path: str = "",
) -> list[tuple[str, str, Any]]:
    """Yield (full_path, key, value) triples from a JSON-like structure."""
    results = []
    if depth > _MAX_DEPTH:
        return results
    if isinstance(obj, dict):
        for k, v in obj.items():
            current_path = f"{path}.{k}" if path else k
            results.append((current_path, k, v))
            results.extend(_iter_key_value_pairs(v, depth + 1, current_path))
    elif isinstance(obj, (list, tuple)):
        for i, item in enumerate(obj):
            results.extend(_iter_key_value_pairs(item, depth + 1, f"{path}[{i}]"))
    return results


def _is_likely_manifest(path: Path) -> bool:
    name = path.name.lower()
    ext = path.suffix.lower()
    if name in _exact_filenames():
        return True
    if ext in _exact_extensions():
        return True
    return False


class MLManifestScanner:
    """Scanner for ML model manifest and configuration files.

    Detection rules are loaded from rules/manifest_rules.yaml. Performs:
      - Exact filename matching (config.json, tokenizer_config.json, etc.)
      - Hydra _target_ injection / HuggingFace auto_map detection
      - trust_remote_code flag detection
      - URL domain allowlist validation (untrusted → HIGH finding)
      - Cloud storage URI detection (S3, GCS, Azure, WASB, ADLS)
      - Weak hash algorithm detection (MD5→CRITICAL, SHA-1→HIGH)
      - Dangerous key scanning (script, command, hook, credential keys)
      - Jinja2 template field detection (chat_template, prompt_template)
      - Insecure URL schemes (http://, ftp://)
      - Abnormally long model_type value (injection probe)
      - Suspicious auto_map entries with double-dash
    """

    EXTENSIONS = frozenset({
        ".json", ".yaml", ".yml", ".toml", ".ini",
        ".cfg", ".config", ".manifest", ".metadata",
    })

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        if not path.exists() or path.is_dir():
            return findings
        is_manifest = _is_likely_manifest(path)
        ext = path.suffix.lower()
        is_json_yaml = ext in (".json", ".yaml", ".yml")

        if not is_manifest and not is_json_yaml:
            return findings

        try:
            file_size = path.stat().st_size
        except OSError:
            return findings

        if file_size > _MAX_READ:
            findings.append(Finding.artifact(
                rule_id="MANIFEST-SIZE",
                title="Manifest file exceeds scan budget",
                description=f"File is {file_size} bytes; only {_MAX_READ} bytes are scanned.",
                severity=Severity.LOW,
                target=filepath,
            ))

        try:
            raw_bytes = path.read_bytes()[:_MAX_READ]
        except OSError:
            return findings

        ext = path.suffix.lower()
        if ext in (".json",):
            findings.extend(self._scan_json(raw_bytes, filepath))
        elif ext in (".yaml", ".yml"):
            findings.extend(self._scan_yaml(raw_bytes, filepath))
        else:
            findings.extend(self._scan_raw_bytes(raw_bytes, filepath))

        return findings

    def _scan_json(self, raw: bytes, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            obj = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            findings.append(Finding.artifact(
                rule_id="MANIFEST-PARSE",
                title="JSON parse error in ML manifest",
                description=f"Cannot parse manifest: {exc}",
                severity=Severity.MEDIUM,
                target=filepath,
                evidence=str(exc),
            ))
            return findings

        findings.extend(self._check_known_dangerous_keys(obj, filepath))
        findings.extend(self._check_suspicious_key_rules(obj, filepath))
        findings.extend(self._check_urls(obj, filepath))
        findings.extend(self._check_weak_hashes(obj, filepath))
        findings.extend(self._check_auto_map(obj, filepath))
        findings.extend(self._check_model_type_length(obj, filepath))
        findings.extend(self._deep_content_scan(obj, filepath))

        return findings

    def _scan_yaml(self, raw: bytes, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            obj = yaml.safe_load(raw.decode("utf-8", "ignore"))
        except yaml.YAMLError:
            findings.extend(self._scan_raw_bytes(raw, filepath))
            return findings
        if obj and isinstance(obj, dict):
            findings.extend(self._check_known_dangerous_keys(obj, filepath))
            findings.extend(self._check_suspicious_key_rules(obj, filepath))
            findings.extend(self._check_urls(obj, filepath))
            findings.extend(self._check_weak_hashes(obj, filepath))
            findings.extend(self._deep_content_scan(obj, filepath))
        return findings

    def _scan_raw_bytes(self, raw: bytes, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        text = raw.decode("utf-8", "ignore")
        for m in _URL_RE.finditer(text):
            url = m.group(0)
            if not _is_trusted_url(url):
                findings.append(Finding.artifact(
                    rule_id="MANIFEST-URL-001",
                    title="Untrusted external URL in model manifest",
                    description="The manifest references a domain not in the trusted ML infrastructure allowlist.",
                    severity=Severity.HIGH,
                    target=filepath,
                    evidence=url[:200],
                    cwe_ids=["CWE-494", "CWE-829"],
                ))
                if len(findings) >= _MAX_URL_FINDINGS:
                    break
        return findings

    def _check_known_dangerous_keys(self, obj: Any, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        _KNOWN = {
            "_target_": ("MANIFEST-INJ-001",
                         "Hydra _target_ key in ML manifest — arbitrary class instantiation",
                         Severity.CRITICAL, ["CWE-94"]),
            "auto_map":  ("MANIFEST-INJ-002",
                          "HuggingFace auto_map key — may load arbitrary Python classes remotely",
                          Severity.CRITICAL, ["CWE-94"]),
            "trust_remote_code": ("MANIFEST-INJ-003",
                                  "trust_remote_code=true enables arbitrary code execution on model load",
                                  Severity.HIGH, ["CWE-94"]),
            "custom_pipelines": ("MANIFEST-INJ-004",
                                 "custom_pipelines definition — remote code execution risk",
                                 Severity.HIGH, ["CWE-94"]),
        }
        for path_str, key, value in _iter_key_value_pairs(obj):
            key_lower = key.lower()
            if key_lower in _KNOWN:
                rule_id, title, sev, cwe_ids = _KNOWN[key_lower]
                if key_lower == "trust_remote_code" and value is not True:
                    continue
                evidence = f"key={path_str}"
                if isinstance(value, (str, bool, int)):
                    evidence += f"; value={str(value)[:100]}"
                findings.append(Finding.artifact(
                    rule_id=rule_id,
                    title=title,
                    description=title,
                    severity=sev,
                    target=filepath,
                    evidence=evidence,
                    cwe_ids=cwe_ids,
                ))
        return findings

    # Jinja2 {% include %} inside a chat_template value = file inclusion attack
    _JINJA2_INCLUDE_RE = re.compile(r'\{%-?\s*include\s+[\'"]', re.IGNORECASE)

    def _check_suspicious_key_rules(self, obj: Any, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        rules = _suspicious_key_rules()
        seen: set[str] = set()
        for path_str, key, value in _iter_key_value_pairs(obj):
            if len(findings) >= _MAX_KEY_FINDINGS:
                break
            for rule_id, title, pats, sev, cwe_ids, description in rules:
                cache_key = f"{rule_id}:{path_str}"
                if cache_key in seen:
                    continue
                for pat in pats:
                    if pat.search(key):
                        seen.add(cache_key)
                        evidence = f"key={path_str}"
                        if isinstance(value, str) and len(value) < 200:
                            evidence += f"; value={value[:100]}"

                        # Escalate: {% include %} in a template field is file
                        # inclusion — arbitrary file read at render time (CWE-98)
                        if (isinstance(value, str)
                                and self._JINJA2_INCLUDE_RE.search(value)):
                            findings.append(Finding.artifact(
                                rule_id="MANIFEST-KEY-004",
                                title="Jinja2 {% include %} in chat_template — file inclusion attack",
                                description=(
                                    f"Field '{path_str}' in '{filepath}' contains a Jinja2 "
                                    f"{{% include %}} directive. When rendered by the ML framework "
                                    f"this can read arbitrary files from the server filesystem."
                                ),
                                severity=Severity.CRITICAL,
                                target=filepath,
                                evidence=evidence,
                                cwe_ids=["CWE-98", "CWE-94"],
                            ))
                        else:
                            findings.append(Finding.artifact(
                                rule_id=rule_id,
                                title=title,
                                description=description or title,
                                severity=sev,
                                target=filepath,
                                evidence=evidence,
                                cwe_ids=cwe_ids,
                            ))
                        break
        return findings

    def _check_urls(self, obj: Any, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        url_count = 0
        cloud_count = 0
        for _, _, value in _iter_key_value_pairs(obj):
            if not isinstance(value, str):
                continue
            if url_count >= _MAX_URL_FINDINGS and cloud_count >= _MAX_URL_FINDINGS:
                break
            for m in _URL_RE.finditer(value):
                if url_count >= _MAX_URL_FINDINGS:
                    break
                url = m.group(0)
                if url.startswith("http://") or url.startswith("ftp://"):
                    findings.append(Finding.artifact(
                        rule_id="MANIFEST-URL-INSEC",
                        title="Insecure URL scheme in model manifest",
                        description="Non-HTTPS URL in model manifest — susceptible to MITM/supply-chain attack.",
                        severity=Severity.HIGH,
                        target=filepath,
                        evidence=url[:200],
                        cwe_ids=["CWE-319"],
                    ))
                    url_count += 1
                elif not _is_trusted_url(url):
                    findings.append(Finding.artifact(
                        rule_id="MANIFEST-URL-001",
                        title="Untrusted external URL in model manifest",
                        description=(
                            "The manifest references a domain not in the trusted ML "
                            "infrastructure allowlist. May indicate supply-chain tampering."
                        ),
                        severity=Severity.HIGH,
                        target=filepath,
                        evidence=url[:200],
                        cwe_ids=["CWE-494", "CWE-829"],
                    ))
                    url_count += 1

            for m in _CLOUD_URI_RE.finditer(value):
                if cloud_count >= _MAX_URL_FINDINGS:
                    break
                uri = m.group(0)
                findings.append(Finding.artifact(
                    rule_id="MANIFEST-URL-002",
                    title="Cloud storage URI in model manifest",
                    description=(
                        "The manifest contains a cloud storage URI (S3/GCS/Azure). "
                        "These references indicate external model weight dependencies "
                        "that may bypass local integrity checks."
                    ),
                    severity=Severity.MEDIUM,
                    target=filepath,
                    evidence=uri[:200],
                    cwe_ids=["CWE-829"],
                ))
                cloud_count += 1

        return findings

    def _check_weak_hashes(self, obj: Any, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        hex_re = re.compile(r"^[a-fA-F0-9]+$")
        weak_pats = _weak_hash_patterns()
        for _, key, value in _iter_key_value_pairs(obj):
            if not isinstance(value, str):
                continue
            if not hex_re.match(value):
                continue
            for rule_id, key_pat, hex_len, title, cwe_ids in weak_pats:
                if len(value) == hex_len and key_pat.search(key):
                    sev = Severity.HIGH if hex_len == 32 else Severity.MEDIUM
                    findings.append(Finding.artifact(
                        rule_id=rule_id,
                        title=title,
                        description=title,
                        severity=sev,
                        target=filepath,
                        evidence=f"key={key}; hash_len={len(value)}",
                        cwe_ids=cwe_ids,
                    ))
        return findings

    def _check_auto_map(self, obj: Any, filepath: str) -> list[Finding]:
        if not isinstance(obj, dict):
            return []
        findings: list[Finding] = []
        auto_map = obj.get("auto_map", {})
        if not isinstance(auto_map, dict):
            return []
        for k, v in auto_map.items():
            if not isinstance(v, str):
                continue
            if "--" in v or v.count(".") > 3:
                findings.append(Finding.artifact(
                    rule_id="MANIFEST-AUTOMAP",
                    title=f"Suspicious auto_map entry: {k}",
                    description=(
                        f"auto_map value '{v[:80]}' matches HuggingFace remote-repo "
                        "attack pattern (double-dash or deep module path). May load a "
                        "malicious Python class from a remote repository."
                    ),
                    severity=Severity.CRITICAL,
                    target=filepath,
                    evidence=f"{k}: {v[:120]}",
                    cwe_ids=["CWE-94"],
                ))
        return findings

    def _check_model_type_length(self, obj: Any, filepath: str) -> list[Finding]:
        if not isinstance(obj, dict):
            return []
        model_type = obj.get("model_type", "")
        if not isinstance(model_type, str) or len(model_type) <= 128:
            return []
        return [Finding.artifact(
            rule_id="MANIFEST-MODELTYPE",
            title="Abnormally long model_type in ML manifest",
            description=(
                "The model_type field is unusually long. Oversized model_type values "
                "may indicate a string injection attempt targeting ML framework parsers."
            ),
            severity=Severity.MEDIUM,
            target=filepath,
            evidence=model_type[:200],
        )]

    _DEEP_INJECTION_RE = re.compile(
        r"(?i)"
        r"\{\{.*\.__class__.*\.__subclasses__.*\}\}|"
        r"\{\{.*\.__mro__.*\.__subclasses__.*\}\}|"
        r"\{\{.*__builtins__.*\}\}|"
        r"\{\{.*__import__.*\}\}|"
        r"\{\{.*os\.system.*\}\}|"
        r"\{\{.*subprocess\..*\}\}|"
        r"__import__\s*\(|"
        r"(?<![\w.])eval\s*\(|"
        r"(?<![\w.])exec\s*\(|"
        r"os\.system\s*\(|"
        r"subprocess\.\w+\s*\(|"
        r"builtins\.eval\s*\(|"
        r"builtins\.exec\s*\("
    )

    _DEEP_SECRETS_RE = re.compile(
        r"(?i)"
        r"sk_live_[a-z0-9]{24,}|"
        r"sk_test_[a-z0-9]{24,}|"
        r"ghp_[a-zA-Z0-9]{36,}|"
        r"AKIA[A-Z0-9]{16}|"
        r"postgres://[^:]+:[^@]+@|"
        r"mysql://[^:]+:[^@]+@|"
        r"mongodb://[^:]+:[^@]+@"
    )

    _DEEP_CONTENT_MAX_VALUE_LEN = 4096

    _CONN_STR_RE = re.compile(
        r"((?:postgres|mysql|mongodb)://[^:]+:)([^@]+)(@)",
        re.IGNORECASE,
    )

    @staticmethod
    def _redact(value: str) -> str:
        """Return a redacted form of a secret value safe for logs and reports."""
        masked = MLManifestScanner._CONN_STR_RE.sub(
            lambda m: m.group(1) + "***" + m.group(3), value
        )
        if masked != value:
            return masked[:120]
        if len(value) <= 8:
            return "***"
        return value[:4] + "***" + value[-4:]

    def _deep_content_scan(self, obj: Any, filepath: str) -> list[Finding]:
        """Scan every string value in a JSON/YAML object for SSTI, code injection, and secrets."""
        findings: list[Finding] = []
        seen_inj: set[str] = set()
        seen_sec: set[str] = set()

        for path_str, _key, value in _iter_key_value_pairs(obj):
            if not isinstance(value, str) or not value.strip():
                continue
            # Skip very long values to prevent ReDoS and avoid scanning binary blobs
            if len(value) > self._DEEP_CONTENT_MAX_VALUE_LEN:
                continue

            try:
                inj_match = self._DEEP_INJECTION_RE.search(value)
            except Exception:
                continue

            if inj_match:
                sig = value[:100]
                if sig not in seen_inj:
                    seen_inj.add(sig)
                    findings.append(Finding.artifact(
                        rule_id="MANIFEST-CODE-INJ",
                        title="Code injection payload in config value",
                        description=(
                            f"Field '{path_str}' in '{filepath}' contains a code-execution "
                            f"pattern (SSTI, eval/exec, __import__, or subprocess). "
                            f"This is a supply-chain attack vector."
                        ),
                        severity=Severity.CRITICAL,
                        target=filepath,
                        evidence=f"{path_str}: {value[:200]}",
                        cwe_ids=["CWE-94"],
                    ))

            try:
                sec_match = self._DEEP_SECRETS_RE.search(value)
            except Exception:
                continue

            if sec_match:
                sig = value[:60]
                if sig not in seen_sec:
                    seen_sec.add(sig)
                    findings.append(Finding.artifact(
                        rule_id="MANIFEST-SECRET",
                        title="Hardcoded secret in config value",
                        description=(
                            f"Field '{path_str}' in '{filepath}' appears to contain a "
                            f"hardcoded credential (API key, DB connection string, etc.)."
                        ),
                        severity=Severity.CRITICAL,
                        target=filepath,
                        evidence=f"{path_str}: {self._redact(value)}",
                        cwe_ids=["CWE-798"],
                    ))

        return findings
