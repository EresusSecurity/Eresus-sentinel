"""Remote artifact registry scanner.

Scans AI/ML models stored in remote registries:
  - AWS S3 buckets
  - Google Cloud Storage buckets
  - DVC remote stores (S3/GCS/Azure/SSH)
  - MLflow Model Registry (via existing integration)
  - JFrog Artifactory (via existing integration)

Downloads to a temp dir, runs the standard artifact scan pipeline,
then removes the temp files.
"""
from __future__ import annotations

import logging
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_MODEL_EXTENSIONS = {
    ".pkl", ".pickle", ".pt", ".pth", ".safetensors", ".gguf",
    ".bin", ".onnx", ".h5", ".keras", ".tflite", ".ckpt",
    ".joblib", ".npy", ".npz", ".pb", ".mlmodel",
}


@dataclass
class RemoteScanResult:
    registry: str
    uri: str
    scanned_files: int
    findings: list
    errors: list[str] = field(default_factory=list)
    total_bytes: int = 0


class RemoteArtifactScanner:
    """Unified scanner for remote AI model registries.

    Args:
        max_file_size: Skip individual files larger than this (bytes). Default 2 GB.
        extensions: Model file extensions to download and scan.
        dry_run: List files without downloading/scanning.
        timeout: Per-file download timeout seconds.
    """

    def __init__(
        self,
        max_file_size: int = 2 * 1024 ** 3,
        extensions: Optional[set[str]] = None,
        dry_run: bool = False,
        timeout: int = 120,
    ) -> None:
        self._max_size = max_file_size
        self._extensions = extensions or _MODEL_EXTENSIONS
        self._dry_run = dry_run
        self._timeout = timeout

    def scan(self, uri: str, **kwargs: Any) -> RemoteScanResult:
        """Detect registry type from URI and scan.

        URI formats:
          s3://bucket/prefix
          gs://bucket/prefix
          dvc+s3://bucket/prefix  or  .dvc file path
          mlflow://tracking-uri/model-name/version
          jfrog://server/repo/path
        """
        parsed = urlparse(uri)
        scheme = parsed.scheme.lower()

        if scheme == "s3":
            return self._scan_s3(uri, **kwargs)
        if scheme in ("gs", "gcs"):
            return self._scan_gcs(uri, **kwargs)
        if scheme in ("dvc+s3", "dvc+gs", "dvc"):
            return self._scan_dvc(uri, **kwargs)
        if scheme == "mlflow":
            return self._scan_mlflow(uri, **kwargs)
        if scheme == "jfrog":
            return self._scan_jfrog(uri, **kwargs)
        if uri.endswith(".dvc") or uri.endswith("/dvc.lock"):
            return self._scan_dvc_file(uri, **kwargs)

        return RemoteScanResult(
            registry="unknown", uri=uri,
            scanned_files=0, findings=[],
            errors=[f"Unsupported URI scheme: {scheme!r}. Supported: s3://, gs://, dvc://, mlflow://, jfrog://"],
        )

    # ── S3 ─────────────────────────────────────────────────────────

    def _scan_s3(self, uri: str, **kwargs: Any) -> RemoteScanResult:
        try:
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError
        except ImportError:
            return RemoteScanResult(
                registry="s3", uri=uri, scanned_files=0, findings=[],
                errors=["boto3 not installed — pip install boto3"],
            )

        parsed = urlparse(uri)
        bucket = parsed.netloc
        prefix = parsed.path.lstrip("/")

        profile = kwargs.get("profile")
        region = kwargs.get("region")
        session = boto3.Session(profile_name=profile, region_name=region)
        s3 = session.client("s3")

        logger.info("S3 scan: s3://%s/%s", bucket, prefix)
        findings: list = []
        errors: list[str] = []
        scanned = 0
        total_bytes = 0

        try:
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    size = obj.get("Size", 0)
                    ext = Path(key).suffix.lower()
                    if ext not in self._extensions:
                        continue
                    if size > self._max_size:
                        logger.warning("Skipping large file %s (%d bytes)", key, size)
                        continue
                    if self._dry_run:
                        logger.info("[dry-run] would scan s3://%s/%s (%d bytes)", bucket, key, size)
                        scanned += 1
                        continue
                    with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
                        tmp_path = tmp.name
                    try:
                        s3.download_file(bucket, key, tmp_path)
                        total_bytes += size
                        file_findings = self._scan_local(tmp_path, f"s3://{bucket}/{key}")
                        findings.extend(file_findings)
                        scanned += 1
                    except ClientError as exc:
                        errors.append(f"s3://{bucket}/{key}: {exc}")
                    finally:
                        try:
                            os.unlink(tmp_path)
                        except OSError:
                            pass
        except Exception as exc:
            errors.append(str(exc))

        return RemoteScanResult(
            registry="s3", uri=uri,
            scanned_files=scanned, findings=findings,
            errors=errors, total_bytes=total_bytes,
        )

    # ── GCS ────────────────────────────────────────────────────────

    def _scan_gcs(self, uri: str, **kwargs: Any) -> RemoteScanResult:
        try:
            from google.cloud import storage as gcs_storage
        except ImportError:
            return RemoteScanResult(
                registry="gcs", uri=uri, scanned_files=0, findings=[],
                errors=["google-cloud-storage not installed — pip install google-cloud-storage"],
            )

        parsed = urlparse(uri)
        bucket_name = parsed.netloc
        prefix = parsed.path.lstrip("/")

        project = kwargs.get("project")
        client = gcs_storage.Client(project=project)
        bucket = client.bucket(bucket_name)

        logger.info("GCS scan: gs://%s/%s", bucket_name, prefix)
        findings: list = []
        errors: list[str] = []
        scanned = 0
        total_bytes = 0

        try:
            for blob in client.list_blobs(bucket_name, prefix=prefix):
                ext = Path(blob.name).suffix.lower()
                if ext not in self._extensions:
                    continue
                size = blob.size or 0
                if size > self._max_size:
                    continue
                if self._dry_run:
                    scanned += 1
                    continue
                with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
                    tmp_path = tmp.name
                try:
                    blob.download_to_filename(tmp_path, timeout=self._timeout)
                    total_bytes += size
                    file_findings = self._scan_local(tmp_path, f"gs://{bucket_name}/{blob.name}")
                    findings.extend(file_findings)
                    scanned += 1
                except Exception as exc:
                    errors.append(f"gs://{bucket_name}/{blob.name}: {exc}")
                finally:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
        except Exception as exc:
            errors.append(str(exc))

        return RemoteScanResult(
            registry="gcs", uri=uri,
            scanned_files=scanned, findings=findings,
            errors=errors, total_bytes=total_bytes,
        )

    # ── DVC ────────────────────────────────────────────────────────

    def _scan_dvc(self, uri: str, **kwargs: Any) -> RemoteScanResult:
        try:
            import dvc.api
        except ImportError:
            return RemoteScanResult(
                registry="dvc", uri=uri, scanned_files=0, findings=[],
                errors=["dvc not installed — pip install dvc"],
            )
        return RemoteScanResult(
            registry="dvc", uri=uri, scanned_files=0, findings=[],
            errors=["DVC URI scanning: use sentinel artifact <local-path> after dvc pull"],
        )

    def _scan_dvc_file(self, dvc_file: str, **kwargs: Any) -> RemoteScanResult:
        """Parse .dvc file to get remote path and scan it."""
        try:
            import yaml
        except ImportError:
            import json as yaml  # type: ignore[no-redef]

        p = Path(dvc_file)
        if not p.exists():
            return RemoteScanResult(
                registry="dvc", uri=dvc_file, scanned_files=0, findings=[],
                errors=[f"DVC file not found: {dvc_file}"],
            )

        findings: list = []
        errors: list[str] = []
        scanned = 0

        try:
            with open(p) as f:
                data = yaml.safe_load(f)
            outs = data.get("outs", [])
            for out in outs:
                path = out.get("path", "")
                if path and Path(path).exists():
                    ext = Path(path).suffix.lower()
                    if ext in self._extensions:
                        file_findings = self._scan_local(path, f"dvc:{path}")
                        findings.extend(file_findings)
                        scanned += 1
                elif path:
                    errors.append(f"DVC file {path!r} not pulled — run: dvc pull {path}")
        except Exception as exc:
            errors.append(f"DVC file parse error: {exc}")

        return RemoteScanResult(
            registry="dvc", uri=dvc_file,
            scanned_files=scanned, findings=findings, errors=errors,
        )

    # ── MLflow ─────────────────────────────────────────────────────

    def _scan_mlflow(self, uri: str, **kwargs: Any) -> RemoteScanResult:
        try:
            from sentinel.integrations.mlflow_integration import MLflowConfig, MLflowScanner
        except ImportError:
            return RemoteScanResult(
                registry="mlflow", uri=uri, scanned_files=0, findings=[],
                errors=["MLflow integration not available"],
            )

        parsed = urlparse(uri)
        tracking_uri = f"http://{parsed.netloc}" if parsed.netloc else os.environ.get("MLFLOW_TRACKING_URI", "")
        model_name = parsed.path.lstrip("/").split("/")[0] if parsed.path.strip("/") else None

        config = MLflowConfig(
            tracking_uri=tracking_uri,
            token=kwargs.get("token", os.environ.get("MLFLOW_TRACKING_TOKEN", "")),
        )

        findings: list = []
        errors: list[str] = []
        scanned = 0

        try:
            scanner = MLflowScanner(config)
            scan_findings = scanner.scan(model_name=model_name)
            findings.extend(scan_findings)
            scanned = len(scan_findings)
        except Exception as exc:
            errors.append(f"MLflow scan error: {exc}")

        return RemoteScanResult(
            registry="mlflow", uri=uri,
            scanned_files=scanned, findings=findings, errors=errors,
        )

    # ── JFrog ──────────────────────────────────────────────────────

    def _scan_jfrog(self, uri: str, **kwargs: Any) -> RemoteScanResult:
        try:
            from sentinel.integrations.jfrog import JFrogScanner
        except ImportError:
            return RemoteScanResult(
                registry="jfrog", uri=uri, scanned_files=0, findings=[],
                errors=["JFrog integration not available"],
            )

        findings: list = []
        errors: list[str] = []

        try:
            scanner = JFrogScanner.from_uri(uri, **kwargs)
            scan_findings = scanner.scan()
            findings.extend(scan_findings)
        except Exception as exc:
            errors.append(f"JFrog scan error: {exc}")

        return RemoteScanResult(
            registry="jfrog", uri=uri,
            scanned_files=len(findings), findings=findings, errors=errors,
        )

    # ── Local scan delegate ────────────────────────────────────────

    def _scan_local(self, local_path: str, remote_uri: str) -> list:
        """Run standard sentinel artifact scan on a downloaded file."""
        try:
            from sentinel.artifact import run_artifact_scan
            findings = run_artifact_scan(local_path)
            for f in findings:
                f.target = remote_uri
            return findings
        except ImportError:
            pass

        try:
            from sentinel.artifact import scan_file
            findings = scan_file(local_path)
            for f in findings:
                if hasattr(f, "target"):
                    f.target = remote_uri
            return findings
        except Exception as exc:
            logger.warning("scan_local failed for %s: %s", remote_uri, exc)
            return []
