"""Scanner plugin SDK primitives."""

from __future__ import annotations

import json
import re
import zipfile
from dataclasses import dataclass, field
from importlib.metadata import entry_points
from pathlib import Path

from sentinel.finding import Finding

PLUGIN_SDK_SCHEMA_VERSION = "sentinel.plugin-sdk.v1"


@dataclass(frozen=True)
class ScannerPluginSpec:
    name: str
    version: str = "0.1.0"
    supported_extensions: tuple[str, ...] = ()
    metadata: dict[str, str] = field(default_factory=dict)


class BaseScannerPlugin:
    spec = ScannerPluginSpec(name="unnamed")

    def scan_path(self, path: str | Path) -> list[Finding]:
        raise NotImplementedError


class BaseScanner(BaseScannerPlugin):
    """Public scanner plugin base class for external packages."""


def discover_scanner_plugins(group: str = "sentinel.scanners") -> list[object]:
    """Load scanner plugin entry points."""
    found = entry_points()
    if hasattr(found, "select"):
        selected = found.select(group=group)
    else:
        selected = found.get(group, [])
    return [entry_point.load() for entry_point in selected]


def scaffold_plugin(name: str, output_dir: str | Path) -> dict[str, str]:
    """Create a minimal scanner plugin package scaffold."""
    package = _package_name(name)
    root = Path(output_dir) / package
    src = root / "src" / package
    src.mkdir(parents=True, exist_ok=True)
    (root / "README.md").write_text(
        f"# {name}\n\nEresus Sentinel scanner plugin scaffold.\n",
        encoding="utf-8",
    )
    (root / "pyproject.toml").write_text(
        "\n".join([
            "[project]",
            f"name = \"{package}\"",
            "version = \"0.1.0\"",
            "requires-python = \">=3.10\"",
            "dependencies = [\"eresus-sentinel\"]",
            "",
            "[project.entry-points.\"sentinel.scanners\"]",
            f"{package} = \"{package}:Plugin\"",
            "",
        ]),
        encoding="utf-8",
    )
    (src / "__init__.py").write_text(
        "\n".join([
            "from sentinel.plugin_sdk import BaseScanner, ScannerPluginSpec",
            "",
            "",
            "class Plugin(BaseScanner):",
            f"    spec = ScannerPluginSpec(name=\"{package}\", supported_extensions=(\".bin\",))",
            "",
            "    def scan_path(self, path):",
            "        return []",
            "",
        ]),
        encoding="utf-8",
    )
    return {
        "schema_version": PLUGIN_SDK_SCHEMA_VERSION,
        "name": name,
        "package": package,
        "path": str(root),
        "entry_point_group": "sentinel.scanners",
    }


def install_plugin_pack(pack_path: str | Path, install_root: str | Path | None = None) -> dict[str, str]:
    """Safely extract a plugin pack ZIP into the local Sentinel plugin directory."""
    pack = Path(pack_path)
    root = Path(install_root) if install_root else Path.home() / ".sentinel" / "plugins"
    target = root / _package_name(pack.stem)
    root.mkdir(parents=True, exist_ok=True)
    if not zipfile.is_zipfile(pack):
        raise ValueError(f"plugin pack must be a zip file: {pack}")
    target.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(pack) as archive:
        for member in archive.infolist():
            dest = (target / member.filename).resolve()
            if not str(dest).startswith(str(target.resolve())):
                raise ValueError(f"unsafe plugin pack member: {member.filename}")
            if member.is_dir():
                dest.mkdir(parents=True, exist_ok=True)
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(archive.read(member))
    manifest = {
        "schema_version": PLUGIN_SDK_SCHEMA_VERSION,
        "pack": str(pack),
        "installed_path": str(target),
    }
    (target / "sentinel-plugin-install.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def plugin_authoring_guide() -> str:
    return (
        "Create a package with an entry point in the sentinel.scanners group. "
        "Subclass sentinel.plugin_sdk.BaseScanner and return sentinel.finding.Finding objects from scan_path()."
    )


def _package_name(name: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_]+", "_", name.strip().lower()).strip("_")
    return cleaned or "sentinel_plugin"
