"""Rule inventory and audit helpers.

This module is the canonical read-only view over Sentinel's YAML rule roots.
It intentionally keeps CLI formatting out of the loader so other tools can
reuse the same inventory without scraping ``sentinel rules list`` output.
"""

from __future__ import annotations

import os
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

RULE_INVENTORY_SCHEMA_VERSION = "rules.inventory.v1"
RULE_RECORD_SCHEMA_VERSION = "rules.record.v1"

_KNOWN_SEVERITIES = {"critical", "high", "medium", "low", "info", "unknown"}


@dataclass(frozen=True)
class RuleRoot:
    path: Path
    kind: str
    priority: int
    source: str


def rule_roots(cwd: Path | None = None) -> list[RuleRoot]:
    """Return rule roots in deterministic precedence order."""
    cwd = cwd or Path.cwd()
    package_root = Path(__file__).resolve().parent
    roots: list[RuleRoot] = []

    priority = 0
    env_dirs = []
    for env_name in ("ERESUS_RULES_DIR", "LLMSECOPS_RULES_DIR"):
        env_value = os.environ.get(env_name)
        if env_value:
            env_dirs.append((env_name, env_value))

    packs = os.environ.get("ERESUS_RULE_PACKS", "")
    for idx, item in enumerate(p.strip() for p in packs.split(os.pathsep) if p.strip()):
        roots.append(RuleRoot(Path(item), "custom_pack", priority + idx, "ERESUS_RULE_PACKS"))
    priority += len(roots)

    for env_name, env_value in env_dirs:
        roots.append(RuleRoot(Path(env_value), "env_rules", priority, env_name))
        priority += 1

    roots.extend([
        RuleRoot(cwd / "rules", "workspace_rules", priority, "cwd/rules"),
        RuleRoot(cwd / "config", "workspace_config", priority + 1, "cwd/config"),
        RuleRoot(package_root / "rules", "package_rules", priority + 2, "package/rules"),
        RuleRoot(package_root / "config", "package_config", priority + 3, "package/config"),
    ])
    # Deduplicate roots that resolve to the same real filesystem path
    # (e.g. python/sentinel/rules is a symlink to ../../rules — avoid double-loading)
    seen_real: set[Path] = set()
    deduped: list[RuleRoot] = []
    for root in roots:
        try:
            real = root.path.resolve()
        except OSError:
            real = root.path
        if real not in seen_real:
            seen_real.add(real)
            deduped.append(root)
    return deduped


def rule_inventory(cwd: Path | None = None) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for root in rule_roots(cwd):
        if not root.path.exists():
            continue
        for source, data in _load_rule_documents(root.path):
            for record in _extract_rule_records(data, source, root):
                key = (record["id"], record["source"])
                if key in seen:
                    continue
                seen.add(key)
                entries.append(record)

    entries.extend(_builtin_rule_records())
    return sorted(entries, key=lambda item: (item["domain"], item["id"], item["source"]))


def audit_rule_inventory(entries: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    entries = entries if entries is not None else rule_inventory()
    by_id: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        by_id.setdefault(entry["id"], []).append(entry)

    duplicate_rule_ids = [
        {
            "id": rule_id,
            "count": len(records),
            "sources": sorted({r["source"] for r in records}),
        }
        for rule_id, records in sorted(by_id.items())
        if len(records) > 1
    ]

    invalid_regexes = []
    redos_warnings = []
    schema_warnings = []
    for entry in entries:
        severity = str(entry.get("severity", "unknown")).lower()
        if severity not in _KNOWN_SEVERITIES:
            schema_warnings.append({
                "id": entry["id"],
                "source": entry["source"],
                "field": "severity",
                "value": entry.get("severity"),
                "message": "unknown severity label",
            })
        if not entry.get("description") and not entry.get("title"):
            schema_warnings.append({
                "id": entry["id"],
                "source": entry["source"],
                "field": "description",
                "message": "missing title and description",
            })
        for pattern in regex_candidates(entry.get("raw", {})):
            try:
                re.compile(pattern)
            except re.error as exc:
                invalid_regexes.append({
                    "id": entry["id"],
                    "source": entry["source"],
                    "pattern": pattern[:240],
                    "error": str(exc),
                })
                continue
            if _looks_redos_risky(pattern):
                redos_warnings.append({
                    "id": entry["id"],
                    "source": entry["source"],
                    "pattern": pattern[:240],
                    "message": "nested or repeated wildcard quantifier",
                })

    roots = [
        {
            "path": _display_path(root.path),
            "kind": root.kind,
            "priority": root.priority,
            "source": root.source,
            "exists": root.path.exists(),
        }
        for root in rule_roots()
    ]

    return {
        "schema_version": RULE_INVENTORY_SCHEMA_VERSION,
        "total": len(entries),
        "unique_rule_ids": len(by_id),
        "duplicate_rule_id_count": len(duplicate_rule_ids),
        "duplicate_rule_ids": duplicate_rule_ids,
        "invalid_regex_count": len(invalid_regexes),
        "invalid_regexes": invalid_regexes,
        "redos_warning_count": len(redos_warnings),
        "redos_warnings": redos_warnings,
        "schema_warning_count": len(schema_warnings),
        "schema_warnings": schema_warnings,
        "roots": roots,
        "status": "error" if invalid_regexes else ("warn" if duplicate_rule_ids or schema_warnings else "ok"),
    }


def regex_candidates(rule: dict[str, Any]) -> list[str]:
    patterns: list[str] = []
    for key, value in rule.items():
        if key in {"pattern", "regex"} and isinstance(value, str):
            patterns.append(value)
        elif key in {"patterns", "regexes"} and isinstance(value, list):
            patterns.extend(item for item in value if isinstance(item, str))
    return patterns


def public_rule_record(record: dict[str, Any]) -> dict[str, Any]:
    public = {k: v for k, v in record.items() if k != "raw"}
    public["schema_version"] = RULE_RECORD_SCHEMA_VERSION
    return public


def _load_rule_documents(root: Path) -> list[tuple[Path, Any]]:
    if root.is_file() and root.suffix == ".zip":
        return _load_zip_documents(root)
    if root.is_file() and root.suffix.lower() in {".yaml", ".yml"}:
        return [(root, _safe_load(root))]
    if not root.is_dir():
        return []
    documents = []
    for path in sorted([*root.rglob("*.yaml"), *root.rglob("*.yml")]):
        documents.append((path, _safe_load(path)))
    return documents


def _load_zip_documents(path: Path) -> list[tuple[Path, Any]]:
    documents = []
    try:
        with zipfile.ZipFile(path) as zf:
            for name in sorted(zf.namelist()):
                if not name.lower().endswith((".yaml", ".yml")):
                    continue
                with zf.open(name) as fh:
                    documents.append((Path(f"{path}!{name}"), yaml.safe_load(fh) or {}))
    except (OSError, zipfile.BadZipFile, yaml.YAMLError):
        return []
    return documents


def _safe_load(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


def _extract_rule_records(
    data: Any,
    source: Path,
    root: RuleRoot,
    group: str | None = None,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if isinstance(data, list):
        for item in data:
            records.extend(_extract_rule_records(item, source, root, group=group))
        return records

    if not isinstance(data, dict):
        return records

    rule_id = data.get("id") or data.get("rule_id")
    if rule_id:
        description = str(data.get("description") or data.get("name") or data.get("title") or "")
        title = str(data.get("title") or data.get("name") or description[:80])
        records.append({
            "id": str(rule_id),
            "domain": str(data.get("domain") or data.get("category") or group or source.stem),
            "severity": str(data.get("severity") or "unknown"),
            "title": title[:120],
            "description": description[:400],
            "remediation": str(data.get("remediation") or data.get("fix") or data.get("fix_hint") or ""),
            "source": _display_path(source),
            "source_root": _display_path(root.path),
            "source_kind": root.kind,
            "source_priority": root.priority,
            "raw": data,
        })

    for key, value in data.items():
        if isinstance(value, (dict, list)):
            records.extend(_extract_rule_records(value, source, root, group=str(key)))
    return records


def _builtin_rule_records() -> list[dict[str, Any]]:
    try:
        from sentinel.artifact.pickle.findings import DANGEROUS_GLOBAL_FINDING, DANGEROUS_IMPORT_FINDING
    except Exception:
        return []

    records = []
    for finding in (DANGEROUS_IMPORT_FINDING, DANGEROUS_GLOBAL_FINDING):
        records.append({
            "id": finding.rule_id,
            "domain": "artifact.pickle",
            "severity": "critical",
            "title": finding.title,
            "description": finding.description,
            "remediation": getattr(finding, "remediation", ""),
            "source": "python/sentinel/artifact/pickle/findings.py",
            "source_root": "builtins",
            "source_kind": "builtin",
            "source_priority": 999,
            "raw": {},
        })
    return records


def _looks_redos_risky(pattern: str) -> bool:
    return bool(
        re.search(r"\([^)]*[+*][^)]*\)\s*[+*{]", pattern)
        or re.search(r"\.\*\s*[+*{]", pattern)
    )


def _display_path(path: Path) -> str:
    text = str(path)
    if "!" in text:
        zip_path, member = text.split("!", 1)
        return f"{_display_path(Path(zip_path))}!{member}"
    try:
        return str(path.relative_to(Path.cwd()))
    except ValueError:
        return str(path)
