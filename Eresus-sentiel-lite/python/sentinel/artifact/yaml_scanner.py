"""YAML artifact scanner.

Scans standalone ``.yaml``/``.yml`` files for unsafe deserialization
tags (``!!python/object/*``, ``!!python/name:``, full URI form, etc.)
that resolve to arbitrary Python object construction when loaded with
PyYAML's ``FullLoader`` or ``UnsafeLoader``.

Rule ID: ``ARTIFACT-037`` — unsafe YAML deserialization tag.
"""

from __future__ import annotations

from pathlib import Path

from sentinel.finding import Finding, Severity


# Shared with pickle_scanner._YAML_MARKERS; kept here too so a standalone
# YAML file can be scanned without loading the full pickle analyzer.
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

_MAX_SCAN_BYTES = 32 * 1024 * 1024  # 32 MB cap — YAML files should be small


class YamlScanner:
    """Detect unsafe Python-object YAML tags in ``.yaml``/``.yml`` files."""

    def scan_file(self, filepath: str) -> list[Finding]:
        path = Path(filepath)
        try:
            data = path.read_bytes()[:_MAX_SCAN_BYTES]
        except OSError as e:
            return [Finding.artifact(
                rule_id="ARTIFACT-YAML-READ",
                title="Unable to read YAML file",
                description=f"Cannot open file: {e}",
                severity=Severity.INFO,
                target=str(path),
            )]

        findings: list[Finding] = []
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
            return findings

        marker_summary = sorted({m.decode("ascii", errors="replace") for m, _ in hits})
        first_marker, first_offset = hits[0]
        findings.append(Finding.artifact(
            rule_id="ARTIFACT-037",
            title="Unsafe YAML deserialization tag",
            description=(
                "YAML file contains Python-object tags that construct "
                "arbitrary Python objects when loaded with PyYAML "
                "FullLoader/UnsafeLoader. Use SafeLoader or "
                "yaml.safe_load() exclusively when parsing this file."
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
        ))
        return findings
