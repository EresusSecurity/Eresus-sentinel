"""SBOM generation + License checking + Remote source scanning."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from sentinel.finding import Finding, Severity

logger = logging.getLogger(__name__)


# ── SBOM Models ──────────────────────────────────────────────────────

@dataclass
class SBOMComponent:
    type: str = "library"
    name: str = ""
    version: str = ""
    bom_ref: str = ""
    description: str = ""
    hashes: list[dict] = field(default_factory=list)
    properties: list[dict] = field(default_factory=list)

@dataclass
class SBOMVulnerability:
    id: str = ""
    description: str = ""
    severity: str = ""
    affects: list[str] = field(default_factory=list)


class SBOMGenerator:
    """CycloneDX 1.5 SBOM generation for ML models."""

    def scan_and_generate(self, target_path: str, findings: list[Finding] | None = None) -> dict:
        path = Path(target_path)
        components = []
        if path.is_file():
            components.append(self._file_to_component(path))
        elif path.is_dir():
            for f in path.rglob("*"):
                if f.is_file() and f.suffix.lower() in (
                    ".pt", ".pth", ".pkl", ".safetensors", ".onnx", ".h5", ".keras",
                    ".pb", ".tflite", ".gguf", ".bin", ".cbm", ".lgb", ".xgb",
                ):
                    components.append(self._file_to_component(f))

        vulns = []
        if findings:
            for f in findings:
                if f.severity in (Severity.HIGH, Severity.CRITICAL):
                    vulns.append({"id": f.rule_id, "description": f.description[:200], "severity": f.severity.value})

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": [{"vendor": "Eresus Security", "name": "eresus-sentinel", "version": "0.1.0"}],
                "component": {"type": "application", "name": "ml-model-scan", "version": "1.0"},
            },
            "components": [asdict(c) for c in components],
            "vulnerabilities": vulns,
        }

    def _file_to_component(self, path: Path) -> SBOMComponent:
        file_hash = ""
        try:
            data = path.read_bytes()
            file_hash = hashlib.sha256(data).hexdigest()
        except OSError:
            pass
        return SBOMComponent(
            type="data", name=path.name, version="1.0",
            bom_ref=f"model-{path.stem}",
            description=f"ML model file ({path.suffix})",
            hashes=[{"alg": "SHA-256", "content": file_hash}] if file_hash else [],
            properties=[
                {"name": "file:size", "value": str(path.stat().st_size)},
                {"name": "file:format", "value": path.suffix.lower()},
            ],
        )

    def write_json(self, sbom: dict, output_path: str) -> None:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sbom, f, indent=2, default=str)


# ── License Checking ─────────────────────────────────────────────────

class LicenseCategory(str, Enum):
    PERMISSIVE = "permissive"
    COPYLEFT = "copyleft"
    RESTRICTIVE = "restrictive"
    UNKNOWN = "unknown"

LICENSE_TAXONOMY = {
    "MIT": LicenseCategory.PERMISSIVE,
    "Apache-2.0": LicenseCategory.PERMISSIVE,
    "BSD-2-Clause": LicenseCategory.PERMISSIVE,
    "BSD-3-Clause": LicenseCategory.PERMISSIVE,
    "ISC": LicenseCategory.PERMISSIVE,
    "Unlicense": LicenseCategory.PERMISSIVE,
    "CC0-1.0": LicenseCategory.PERMISSIVE,
    "GPL-2.0": LicenseCategory.COPYLEFT,
    "GPL-3.0": LicenseCategory.COPYLEFT,
    "LGPL-2.1": LicenseCategory.COPYLEFT,
    "LGPL-3.0": LicenseCategory.COPYLEFT,
    "AGPL-3.0": LicenseCategory.COPYLEFT,
    "MPL-2.0": LicenseCategory.COPYLEFT,
    "CC-BY-4.0": LicenseCategory.PERMISSIVE,
    "CC-BY-SA-4.0": LicenseCategory.COPYLEFT,
    "CC-BY-NC-4.0": LicenseCategory.RESTRICTIVE,
    "CC-BY-NC-SA-4.0": LicenseCategory.RESTRICTIVE,
    "CC-BY-NC-ND-4.0": LicenseCategory.RESTRICTIVE,
}

BLOCKED_LICENSES = {"CC-BY-NC-4.0", "CC-BY-NC-SA-4.0", "CC-BY-NC-ND-4.0", "AGPL-3.0"}
WARN_LICENSES = {"GPL-2.0", "GPL-3.0", "LGPL-2.1", "LGPL-3.0", "MPL-2.0", "CC-BY-SA-4.0"}


class LicenseChecker:
    """License detection and compliance checking for ML models."""

    def __init__(self, allowed: set[str] | None = None, blocked: set[str] | None = None):
        self.blocked = blocked or BLOCKED_LICENSES
        self.allowed = allowed

    def check_directory(self, dirpath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(dirpath)
        license_file = None
        for name in ["LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "license"]:
            candidate = path / name
            if candidate.exists():
                license_file = candidate
                break

        if license_file is None:
            findings.append(Finding.supply_chain(
                rule_id="LICENSE-001", title="No license file found",
                description="Model directory has no LICENSE file — license unknown",
                severity=Severity.MEDIUM, target=dirpath,
            ))
            return findings

        text = license_file.read_text(encoding="utf-8", errors="replace")
        detected = self._detect_license(text)
        if detected == "UNKNOWN":
            findings.append(Finding.supply_chain(
                rule_id="LICENSE-002", title="Unrecognized license",
                description="Could not identify license type",
                severity=Severity.MEDIUM, target=dirpath,
            ))
        elif detected in self.blocked:
            findings.append(Finding.supply_chain(
                rule_id="LICENSE-003", title=f"Blocked license: {detected}",
                description=f"License {detected} is on blocked list",
                severity=Severity.HIGH, target=dirpath, evidence=detected,
            ))
        elif detected in WARN_LICENSES:
            findings.append(Finding.supply_chain(
                rule_id="LICENSE-004", title=f"Copyleft license: {detected}",
                description=f"License {detected} has copyleft obligations",
                severity=Severity.LOW, target=dirpath, evidence=detected,
            ))
        return findings

    def _detect_license(self, text: str) -> str:
        text_lower = text.lower()
        patterns = [
            ("Apache-2.0", "apache license"),
            ("MIT", "permission is hereby granted, free of charge"),
            ("GPL-3.0", "gnu general public license.*version 3"),
            ("GPL-2.0", "gnu general public license.*version 2"),
            ("BSD-3-Clause", "redistribution and use in source and binary forms"),
            ("AGPL-3.0", "gnu affero general public license"),
            ("CC-BY-NC-4.0", "creative commons.*noncommercial"),
            ("CC-BY-SA-4.0", "creative commons.*sharealike"),
            ("CC-BY-4.0", "creative commons.*attribution 4.0"),
            ("Unlicense", "this is free and unencumbered software"),
        ]
        import re
        for spdx, pattern in patterns:
            if re.search(pattern, text_lower):
                return spdx
        return "UNKNOWN"


# ── Remote Source Scanning ───────────────────────────────────────────

@dataclass
class RemoteModel:
    id: str
    name: str
    format: str = ""
    size: int = 0
    last_modified: str = ""
    metadata: dict = field(default_factory=dict)


class RemoteSource:
    """Abstract base for remote model sources."""

    def list_models(self, prefix: str = "") -> list[RemoteModel]:
        raise NotImplementedError

    def download_model(self, model_id: str, dest_dir: str) -> Path:
        raise NotImplementedError

    def scan_remote(self, model_id: str, scan_fn) -> list[Finding]:
        with tempfile.TemporaryDirectory() as tmpdir:
            local_path = self.download_model(model_id, tmpdir)
            return scan_fn(str(local_path))


class S3Source(RemoteSource):
    """AWS S3 model source."""

    def __init__(self, bucket: str, prefix: str = "", region: str = "us-east-1"):
        self.bucket = bucket
        self.prefix = prefix
        self.region = region
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                import boto3
                self._client = boto3.client("s3", region_name=self.region)
            except ImportError:
                raise RuntimeError("boto3 required: pip install boto3")
        return self._client

    MODEL_EXTENSIONS = {".pt", ".pth", ".pkl", ".safetensors", ".onnx", ".h5", ".bin", ".gguf", ".cbm"}

    def list_models(self, prefix: str = "") -> list[RemoteModel]:
        client = self._get_client()
        models = []
        paginator = client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix or self.prefix):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                ext = Path(key).suffix.lower()
                if ext in self.MODEL_EXTENSIONS:
                    models.append(RemoteModel(
                        id=key, name=Path(key).name, format=ext,
                        size=obj.get("Size", 0),
                        last_modified=str(obj.get("LastModified", "")),
                    ))
        return models

    def download_model(self, model_id: str, dest_dir: str) -> Path:
        client = self._get_client()
        dest = Path(dest_dir) / Path(model_id).name
        client.download_file(self.bucket, model_id, str(dest))
        return dest


class GCSSource(RemoteSource):
    """Google Cloud Storage model source."""

    def __init__(self, bucket: str, prefix: str = ""):
        self.bucket = bucket
        self.prefix = prefix

    def list_models(self, prefix: str = "") -> list[RemoteModel]:
        try:
            from google.cloud import storage
        except ImportError:
            raise RuntimeError("google-cloud-storage required")
        client = storage.Client()
        bucket = client.bucket(self.bucket)
        models = []
        for blob in bucket.list_blobs(prefix=prefix or self.prefix):
            ext = Path(blob.name).suffix.lower()
            if ext in S3Source.MODEL_EXTENSIONS:
                models.append(RemoteModel(id=blob.name, name=Path(blob.name).name, format=ext, size=blob.size or 0))
        return models

    def download_model(self, model_id: str, dest_dir: str) -> Path:
        from google.cloud import storage
        client = storage.Client()
        bucket = client.bucket(self.bucket)
        blob = bucket.blob(model_id)
        dest = Path(dest_dir) / Path(model_id).name
        blob.download_to_filename(str(dest))
        return dest


class MLflowSource(RemoteSource):
    """MLflow Model Registry source."""

    def __init__(self, tracking_uri: str = ""):
        self.tracking_uri = tracking_uri

    def list_models(self, prefix: str = "") -> list[RemoteModel]:
        try:
            import mlflow
        except ImportError:
            raise RuntimeError("mlflow required")
        if self.tracking_uri:
            mlflow.set_tracking_uri(self.tracking_uri)
        client = mlflow.tracking.MlflowClient()
        models = []
        for rm in client.search_registered_models():
            models.append(RemoteModel(id=rm.name, name=rm.name, metadata={"description": rm.description or ""}))
        return models

    def download_model(self, model_id: str, dest_dir: str) -> Path:
        import mlflow
        if self.tracking_uri:
            mlflow.set_tracking_uri(self.tracking_uri)
        dest = Path(dest_dir) / model_id
        mlflow.artifacts.download_artifacts(artifact_uri=f"models:/{model_id}/latest", dst_path=str(dest))
        return dest


class JFrogSource(RemoteSource):
    """JFrog Artifactory source."""

    def __init__(self, url: str, repo: str, token: str = ""):
        self.url = url.rstrip("/")
        self.repo = repo
        self.token = token or os.environ.get("JFROG_TOKEN", "")

    def list_models(self, prefix: str = "") -> list[RemoteModel]:
        import urllib.parse
        import urllib.request
        aql = f'items.find({{"repo":"{self.repo}","path":{{"$match":"{prefix}*"}}}})'
        req = urllib.request.Request(
            f"{self.url}/api/search/aql", data=aql.encode(),
            headers={"Content-Type": "text/plain", "Authorization": f"Bearer {self.token}"},
        )
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read())
        models = []
        for r in data.get("results", []):
            name = r.get("name", "")
            ext = Path(name).suffix.lower()
            if ext in S3Source.MODEL_EXTENSIONS:
                models.append(RemoteModel(id=f"{r.get('path','')}/{name}", name=name, format=ext, size=r.get("size", 0)))
        return models

    def download_model(self, model_id: str, dest_dir: str) -> Path:
        import urllib.request
        dest = Path(dest_dir) / Path(model_id).name
        req = urllib.request.Request(
            f"{self.url}/{self.repo}/{model_id}",
            headers={"Authorization": f"Bearer {self.token}"},
        )
        with urllib.request.urlopen(req) as resp:
            dest.write_bytes(resp.read())
        return dest
