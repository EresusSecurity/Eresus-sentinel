"""
MLflow integration — scan models in MLflow Model Registry.

Lists registered models, downloads artifacts, and scans them for security issues.
"""

from __future__ import annotations

import logging
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from sentinel.finding import Finding

_log = logging.getLogger("sentinel.integrations.mlflow_integration")


@dataclass
class MLflowConfig:
    tracking_uri: str = ""
    registry_uri: str = ""
    token: str = ""

    @classmethod
    def from_env(cls) -> "MLflowConfig":
        return cls(
            tracking_uri=os.environ.get("MLFLOW_TRACKING_URI", ""),
            registry_uri=os.environ.get("MLFLOW_REGISTRY_URI", ""),
            token=os.environ.get("MLFLOW_TRACKING_TOKEN", ""),
        )


@dataclass
class ModelVersion:
    name: str
    version: str
    source: str
    run_id: str = ""
    status: str = ""
    tags: dict = None  # type: ignore[assignment]

    def __post_init__(self):
        if self.tags is None:
            self.tags = {}


class MLflowScanner:
    """Scan models registered in MLflow."""

    def __init__(self, config: Optional[MLflowConfig] = None):
        self._config = config or MLflowConfig.from_env()

    def list_models(self) -> list[ModelVersion]:
        """List all registered model versions."""
        try:
            import mlflow
            from mlflow.tracking import MlflowClient
        except ImportError:
            _log.error("mlflow package required for MLflow integration")
            return []

        if self._config.tracking_uri:
            mlflow.set_tracking_uri(self._config.tracking_uri)

        client = MlflowClient()
        versions = []
        try:
            for rm in client.search_registered_models():
                for mv in client.search_model_versions(f"name='{rm.name}'"):
                    versions.append(ModelVersion(
                        name=mv.name,
                        version=mv.version,
                        source=mv.source,
                        run_id=mv.run_id,
                        status=mv.status,
                        tags=dict(mv.tags) if mv.tags else {},
                    ))
        except Exception as exc:
            _log.error("Failed to list MLflow models: %s", exc)
        return versions

    def scan_model(self, model_version: ModelVersion) -> list[Finding]:
        """Download and scan a specific model version."""
        try:
            import mlflow
        except ImportError:
            _log.error("mlflow package required")
            return []

        if self._config.tracking_uri:
            mlflow.set_tracking_uri(self._config.tracking_uri)

        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                local_path = mlflow.artifacts.download_artifacts(
                    artifact_uri=model_version.source,
                    dst_path=tmpdir,
                )
            except Exception as exc:
                _log.error("Failed to download model %s v%s: %s",
                           model_version.name, model_version.version, exc)
                return []

            from sentinel.artifact.format_middleware import scan_file
            findings: list[Finding] = []
            path = Path(local_path)
            if path.is_dir():
                for f in path.rglob("*"):
                    if f.is_file():
                        findings.extend(scan_file(str(f)))
            else:
                findings.extend(scan_file(local_path))
            return findings

    def scan_all(self) -> dict[str, list[Finding]]:
        """Scan all registered models. Returns {model_name/version: findings}."""
        results: dict[str, list[Finding]] = {}
        for mv in self.list_models():
            key = f"{mv.name}/v{mv.version}"
            _log.info("Scanning MLflow model: %s", key)
            results[key] = self.scan_model(mv)
        return results
