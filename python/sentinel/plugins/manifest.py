from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

SCHEMA_VERSION = "sentinel.plugin.v1"
MAX_MANIFEST_BYTES = 1024 * 1024
SUPPORTED_SUFFIXES = {".json", ".yaml", ".yml", ".toml", ".sentinel", ".yar", ".yara"}
MANIFEST_FILENAMES = {
    "sentinel.plugin.json",
    "sentinel.plugin.yaml",
    "sentinel.plugin.yml",
    "sentinel.plugin.toml",
    "sentinel.rulepack.yaml",
    "sentinel.rulepack.yml",
}
ALLOWED_KINDS = {"scanner", "rulepack", "redteam", "adapter", "reporter", "yara"}
ALLOWED_PERMISSIONS = {
    "scan:file-read",
    "scan:metadata",
    "scan:artifact",
    "scan:source",
    "redteam:generate",
    "report:write",
    "network:none",
}
DANGEROUS_PERMISSION_PREFIXES = (
    "shell",
    "process",
    "exec",
    "filesystem:write",
    "filesystem:delete",
    "secrets:",
    "network:any",
)
ID_RE = re.compile(r"^[a-z][a-z0-9_.-]{2,80}$")
YARA_RULE_RE = re.compile(r"\brule\s+([A-Za-z_][A-Za-z0-9_]*)\b")


@dataclass(frozen=True)
class PluginManifestIssue:
    severity: str
    code: str
    message: str
    path: str = ""


@dataclass(frozen=True)
class PluginManifest:
    schema_version: str
    plugin_id: str
    name: str
    version: str
    kind: str
    description: str = ""
    entrypoint: str = ""
    rules: tuple[str, ...] = ()
    formats: tuple[str, ...] = ()
    permissions: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    source_path: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


def load_manifest(path: str | Path, workspace_root: str | Path | None = None) -> PluginManifest:
    source = _safe_manifest_path(path, workspace_root)
    text = _read_bounded_text(source)
    data = _parse_manifest(source, text)
    return _coerce_manifest(data, source)


def validate_manifest(manifest: PluginManifest) -> list[PluginManifestIssue]:
    issues: list[PluginManifestIssue] = []
    if manifest.schema_version != SCHEMA_VERSION:
        issues.append(PluginManifestIssue("high", "PLUGIN-SCHEMA-001", f"Unsupported schema version: {manifest.schema_version}", manifest.source_path))
    if not ID_RE.match(manifest.plugin_id):
        issues.append(PluginManifestIssue("high", "PLUGIN-ID-001", "Plugin id must be 3-81 lowercase letters, digits, dot, dash, or underscore and start with a letter", manifest.source_path))
    if manifest.kind not in ALLOWED_KINDS:
        issues.append(PluginManifestIssue("high", "PLUGIN-KIND-001", f"Unsupported plugin kind: {manifest.kind}", manifest.source_path))
    if not manifest.name.strip():
        issues.append(PluginManifestIssue("medium", "PLUGIN-NAME-001", "Plugin name is required", manifest.source_path))
    if not manifest.version.strip():
        issues.append(PluginManifestIssue("medium", "PLUGIN-VERSION-001", "Plugin version is required", manifest.source_path))
    for permission in manifest.permissions:
        if any(permission == prefix or permission.startswith(f"{prefix}:") for prefix in DANGEROUS_PERMISSION_PREFIXES):
            issues.append(PluginManifestIssue("critical", "PLUGIN-PERM-001", f"Dangerous permission is not allowed in manifests: {permission}", manifest.source_path))
        elif permission not in ALLOWED_PERMISSIONS:
            issues.append(PluginManifestIssue("medium", "PLUGIN-PERM-002", f"Unknown permission: {permission}", manifest.source_path))
    if manifest.entrypoint and _looks_executable(manifest.entrypoint):
        issues.append(PluginManifestIssue("critical", "PLUGIN-ENTRYPOINT-001", "Manifest entrypoint must be a Python entry point or package reference, not a shell command", manifest.source_path))
    if manifest.kind in {"scanner", "adapter", "reporter"} and not manifest.entrypoint:
        issues.append(PluginManifestIssue("medium", "PLUGIN-ENTRYPOINT-002", f"{manifest.kind} manifests should declare an entrypoint", manifest.source_path))
    if manifest.kind in {"rulepack", "yara"} and not manifest.rules:
        issues.append(PluginManifestIssue("medium", "PLUGIN-RULES-001", "Rule pack manifests should declare at least one rule", manifest.source_path))
    return issues


def validate_manifest_file(path: str | Path, workspace_root: str | Path | None = None) -> tuple[PluginManifest | None, list[PluginManifestIssue]]:
    try:
        manifest = load_manifest(path, workspace_root=workspace_root)
    except ValueError as exc:
        return None, [PluginManifestIssue("high", "PLUGIN-LOAD-001", str(exc), str(path))]
    issues = validate_manifest(manifest)
    return manifest, issues


def discover_manifests(root: str | Path) -> list[PluginManifest]:
    base = Path(root).resolve()
    manifests: list[PluginManifest] = []
    if not base.exists():
        return manifests
    for path in base.rglob("*"):
        if not path.is_file():
            continue
        if path.name.lower() in MANIFEST_FILENAMES or path.suffix.lower() in {".sentinel", ".yar", ".yara"}:
            manifest, issues = validate_manifest_file(path, workspace_root=base)
            if manifest and not any(issue.severity in {"critical", "high"} for issue in issues):
                manifests.append(manifest)
    return manifests


def manifest_to_dict(manifest: PluginManifest, issues: list[PluginManifestIssue] | None = None) -> dict[str, Any]:
    return {
        "schema_version": manifest.schema_version,
        "id": manifest.plugin_id,
        "name": manifest.name,
        "version": manifest.version,
        "kind": manifest.kind,
        "description": manifest.description,
        "entrypoint": manifest.entrypoint,
        "rules": list(manifest.rules),
        "formats": list(manifest.formats),
        "permissions": list(manifest.permissions),
        "tags": list(manifest.tags),
        "source_path": manifest.source_path,
        "issues": [issue.__dict__ for issue in (issues or [])],
    }


def _safe_manifest_path(path: str | Path, workspace_root: str | Path | None) -> Path:
    source = Path(path).expanduser().resolve()
    if workspace_root is not None:
        root = Path(workspace_root).expanduser().resolve()
        try:
            source.relative_to(root)
        except ValueError:
            raise ValueError(f"Manifest path escapes workspace root: {path}")
    if not source.is_file():
        raise ValueError(f"Manifest file not found: {path}")
    if source.suffix.lower() not in SUPPORTED_SUFFIXES:
        raise ValueError(f"Unsupported manifest format: {source.suffix}")
    return source


def _read_bounded_text(path: Path) -> str:
    size = path.stat().st_size
    if size > MAX_MANIFEST_BYTES:
        raise ValueError(f"Manifest exceeds {MAX_MANIFEST_BYTES} bytes: {path}")
    return path.read_text(encoding="utf-8", errors="replace")


def _parse_manifest(path: Path, text: str) -> dict[str, Any]:
    suffix = path.suffix.lower()
    if suffix in {".yar", ".yara"}:
        rules = YARA_RULE_RE.findall(text)
        return {
            "schema_version": SCHEMA_VERSION,
            "id": _normalize_id(path.stem),
            "name": path.stem,
            "version": "0.1.0",
            "kind": "yara",
            "rules": rules,
            "permissions": ["scan:file-read", "network:none"],
            "formats": [".yar", ".yara"],
        }
    if suffix == ".json":
        data = json.loads(text)
    elif suffix in {".yaml", ".yml", ".sentinel"}:
        data = yaml.safe_load(text)
    elif suffix == ".toml":
        data = _parse_toml(text)
    else:
        raise ValueError(f"Unsupported manifest format: {suffix}")
    if not isinstance(data, dict):
        raise ValueError("Manifest root must be an object")
    return data


def _parse_toml(text: str) -> dict[str, Any]:
    try:
        import tomllib
        return tomllib.loads(text)
    except ModuleNotFoundError:
        return _parse_basic_toml(text)


def _parse_basic_toml(text: str) -> dict[str, Any]:
    data: dict[str, Any] = {}
    current = data
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            current = data.setdefault(section, {})
            continue
        if "=" not in line:
            continue
        key, raw_value = [part.strip() for part in line.split("=", 1)]
        current[key] = _parse_basic_toml_value(raw_value)
    return data


def _parse_basic_toml_value(raw_value: str) -> Any:
    value = raw_value.strip().rstrip(",")
    if value.startswith(("\"", "'")) and value.endswith(("\"", "'")):
        return value[1:-1]
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [_parse_basic_toml_value(part.strip()) for part in inner.split(",")]
    if value.lower() in {"true", "false"}:
        return value.lower() == "true"
    return value


def _coerce_manifest(data: dict[str, Any], path: Path) -> PluginManifest:
    plugin_block = data.get("plugin") if isinstance(data.get("plugin"), dict) else {}
    merged = {**data, **plugin_block}
    plugin_id = str(merged.get("id") or merged.get("plugin_id") or _normalize_id(path.stem))
    return PluginManifest(
        schema_version=str(merged.get("schema_version") or SCHEMA_VERSION),
        plugin_id=plugin_id,
        name=str(merged.get("name") or plugin_id),
        version=str(merged.get("version") or "0.1.0"),
        kind=str(merged.get("kind") or "rulepack"),
        description=str(merged.get("description") or ""),
        entrypoint=str(merged.get("entrypoint") or ""),
        rules=tuple(str(item) for item in _list_value(merged.get("rules"))),
        formats=tuple(str(item) for item in _list_value(merged.get("formats"))),
        permissions=tuple(str(item) for item in _list_value(merged.get("permissions"))),
        tags=tuple(str(item) for item in _list_value(merged.get("tags"))),
        source_path=str(path),
        raw=data,
    )


def _list_value(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _normalize_id(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_.-]+", "-", value.strip().lower()).strip("-._")
    if not cleaned or not cleaned[0].isalpha():
        cleaned = f"plugin-{cleaned or 'pack'}"
    return cleaned[:80]


def _looks_executable(value: str) -> bool:
    lowered = value.strip().lower()
    if not lowered:
        return False
    dangerous = (";", "&&", "||", "|", "`", "$(", "\n", "\r")
    if any(token in lowered for token in dangerous):
        return True
    first = lowered.split()[0]
    return first in {"sh", "bash", "zsh", "fish", "python", "python3", "node", "ruby", "perl", "powershell", "pwsh", "cmd.exe"}
