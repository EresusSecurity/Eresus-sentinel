"""Cloud target parsing for future remote scan integrations."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

CLOUD_SCAN_SCHEMA_VERSION = "sentinel.cloud-target.v1"


@dataclass(frozen=True)
class CloudTarget:
    provider: str
    uri: str
    bucket: str = ""
    path: str = ""
    auth_env: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": CLOUD_SCAN_SCHEMA_VERSION,
            "provider": self.provider,
            "uri": self.uri,
            "bucket": self.bucket,
            "path": self.path,
            "auth_env": list(self.auth_env),
        }


def parse_cloud_target(uri: str) -> CloudTarget:
    parsed = urlparse(uri)
    scheme = parsed.scheme.lower()
    path = parsed.path.lstrip("/")

    if scheme == "s3":
        return CloudTarget("s3", uri, parsed.netloc, path, ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"))
    if scheme == "gs":
        return CloudTarget("gcs", uri, parsed.netloc, path, ("GOOGLE_APPLICATION_CREDENTIALS",))
    if scheme == "mlflow":
        return CloudTarget("mlflow", uri, parsed.netloc, path, ("MLFLOW_TRACKING_URI",))
    if scheme in {"http", "https"} and "jfrog" in parsed.netloc.lower():
        return CloudTarget("jfrog", uri, parsed.netloc, path, ("JFROG_API_TOKEN",))
    if uri.endswith(".dvc"):
        return CloudTarget("dvc", uri, path=uri, auth_env=("DVC_REMOTE",))
    raise ValueError(f"Unsupported cloud target URI: {uri}")


def plan_cloud_scan(uri: str) -> dict[str, object]:
    """Return a deterministic cloud scan plan without downloading remote data."""
    import os

    target = parse_cloud_target(uri)
    auth = {name: bool(os.environ.get(name)) for name in target.auth_env}
    return {
        "schema_version": "sentinel.cloud-scan.v1",
        "summary": {
            "status": "ready" if any(auth.values()) or target.provider == "dvc" else "auth-required",
            "provider": target.provider,
            "dry_run": True,
        },
        "target": target.to_dict(),
        "auth": auth,
        "scan": {
            "mode": "remote-plan",
            "downloaded": False,
            "local_path": str(Path(target.path)) if target.provider == "dvc" else "",
        },
    }
