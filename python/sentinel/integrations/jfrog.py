"""
JFrog Artifactory integration — scan models stored in Artifactory.

Provides functions to list, download, and scan model artifacts from
JFrog Artifactory repositories.
"""

from __future__ import annotations

import logging
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from sentinel.finding import Finding

_log = logging.getLogger("sentinel.integrations.jfrog")


@dataclass
class ArtifactoryConfig:
    url: str
    repo: str
    token: str = ""
    username: str = ""
    password: str = ""
    verify_ssl: bool = True

    @classmethod
    def from_env(cls) -> "ArtifactoryConfig":
        return cls(
            url=os.environ.get("JFROG_URL", "").rstrip("/"),
            repo=os.environ.get("JFROG_REPO", ""),
            token=os.environ.get("JFROG_TOKEN", ""),
            username=os.environ.get("JFROG_USERNAME", ""),
            password=os.environ.get("JFROG_PASSWORD", ""),
        )


@dataclass
class ArtifactInfo:
    path: str
    size: int
    sha256: str
    created: str


class JFrogScanner:
    """Scan model artifacts stored in JFrog Artifactory."""

    MODEL_EXTENSIONS = frozenset({
        ".pkl", ".pickle", ".pt", ".pth", ".bin", ".safetensors",
        ".onnx", ".h5", ".hdf5", ".keras", ".pb", ".tflite",
        ".gguf", ".joblib", ".npy", ".npz",
    })

    def __init__(self, config: Optional[ArtifactoryConfig] = None):
        self._config = config or ArtifactoryConfig.from_env()
        if not self._config.url:
            _log.warning("JFrog URL not configured — set JFROG_URL env var")

    def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self._config.token:
            headers["Authorization"] = f"Bearer {self._config.token}"
        return headers

    async def list_models(self, path: str = "") -> list[ArtifactInfo]:
        """List model artifacts in the repository."""
        try:
            import httpx
        except ImportError:
            _log.error("httpx required for JFrog integration")
            return []

        url = f"{self._config.url}/api/storage/{self._config.repo}/{path}"
        try:
            async with httpx.AsyncClient(verify=self._config.verify_ssl) as client:
                resp = await client.get(url, headers=self._headers())
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            _log.error("Failed to list artifacts: %s", exc)
            return []

        artifacts = []
        for child in data.get("children", []):
            if child.get("folder", False):
                continue
            child_path = f"{path}/{child['uri'].lstrip('/')}" if path else child["uri"].lstrip("/")
            ext = Path(child_path).suffix.lower()
            if ext in self.MODEL_EXTENSIONS:
                artifacts.append(ArtifactInfo(
                    path=child_path,
                    size=child.get("size", 0),
                    sha256=child.get("checksums", {}).get("sha256", ""),
                    created=child.get("created", ""),
                ))
        return artifacts

    async def download_and_scan(self, artifact_path: str) -> list[Finding]:
        """Download an artifact to a temp file and scan it."""
        try:
            import httpx
        except ImportError:
            _log.error("httpx required for JFrog integration")
            return []

        url = f"{self._config.url}/{self._config.repo}/{artifact_path}"
        try:
            async with httpx.AsyncClient(verify=self._config.verify_ssl) as client:
                resp = await client.get(url, headers=self._headers())
                resp.raise_for_status()
                data = resp.content
        except Exception as exc:
            _log.error("Failed to download %s: %s", artifact_path, exc)
            return []

        ext = Path(artifact_path).suffix
        with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as f:
            f.write(data)
            tmp_path = f.name

        try:
            from sentinel.artifact.format_middleware import scan_file
            return scan_file(tmp_path)
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
