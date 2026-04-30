"""OCI container image scanner — detect model files, secrets, misconfigurations.

Extended capabilities
---------------------
* ``scan_registry(image_ref)`` — pull an OCI image from Docker Hub / GHCR
  and scan it locally (requires ``docker`` CLI or ``podman`` on PATH).
* ``scan_layer_models(layer_tar, target)`` — extract model files from a
  layer and run the appropriate artifact scanner (pickle / safetensors /
  gguf) on each one, yielding findings.
* Layer-level pickle scanning already reports file presence; now it also
  runs the full ``PickleScanner`` on extracted bytes.
"""
from __future__ import annotations

import io
import json
import logging
import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

from sentinel.finding import Finding, Severity

logger = logging.getLogger(__name__)

MODEL_EXTENSIONS = {
    ".pt", ".pth", ".bin", ".ckpt", ".safetensors", ".gguf", ".onnx", ".pb",
    ".tflite", ".keras", ".h5", ".hdf5", ".pkl", ".pickle", ".joblib",
    ".npy", ".npz", ".xgb", ".cbm", ".mlmodel", ".nemo", ".mar",
    ".pdmodel", ".params", ".t7", ".engine", ".plan", ".skops",
}

PICKLE_EXTENSIONS = frozenset({".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt", ".joblib"})
SAFETENSORS_EXTENSIONS = frozenset({".safetensors"})
GGUF_EXTENSIONS = frozenset({".gguf"})

# Maximum bytes to extract per model file for in-memory scanning (100 MB)
_MAX_MODEL_BYTES = 100 * 1024 * 1024

DANGEROUS_ENVS = {
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY", "HF_TOKEN", "HUGGING_FACE_HUB_TOKEN",
    "GITHUB_TOKEN", "DATABASE_URL", "REDIS_URL",
}

DANGEROUS_COMMANDS = [
    b"curl ", b"wget ", b"pip install", b"apt-get install",
    b"chmod 777", b"--trust-remote-code", b"torch.load",
    b"pickle.load", b"eval(", b"exec(",
]


def _get_pickle_scanner():
    """Lazy-import PickleScanner to avoid circular deps."""
    try:
        from sentinel.artifact.pickle.scanner import PickleScanner
        return PickleScanner()
    except Exception as e:
        logger.debug("PickleScanner unavailable: %s", e)
        return None


def _get_safetensors_scanner():
    try:
        from sentinel.artifact.safetensors_scanner import SafetensorsScanner
        return SafetensorsScanner()
    except Exception as e:
        logger.debug("SafetensorsScanner unavailable: %s", e)
        return None


def _get_gguf_scanner():
    try:
        from sentinel.artifact.gguf_analyzer import GGUFAnalyzer
        return GGUFAnalyzer()
    except Exception as e:
        logger.debug("GGUFAnalyzer unavailable: %s", e)
        return None


class OCIScanner:
    """Scan OCI/Docker container images for model security issues."""

    def __init__(self, deep_scan: bool = True, max_model_bytes: int = _MAX_MODEL_BYTES) -> None:
        """
        Args:
            deep_scan: If True, extract model files from layers and run
                       full artifact scanners (pickle/safetensors/gguf).
            max_model_bytes: Skip extraction for model files larger than
                             this value to bound memory usage.
        """
        self._deep_scan = deep_scan
        self._max_model_bytes = max_model_bytes

    # ── Public interface ──────────────────────────────────────

    def scan_file(self, filepath: str) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(filepath)
        if not path.exists():
            return findings
        if not tarfile.is_tarfile(str(path)):
            return findings
        try:
            with tarfile.open(str(path), "r:*") as tar:
                self._scan_manifest(tar, findings, filepath)
                self._scan_config(tar, findings, filepath)
                self._scan_layers(tar, findings, filepath)
        except Exception as e:
            findings.append(Finding.artifact(
                rule_id="OCI-001", title="OCI image parse error",
                description=str(e), severity=Severity.MEDIUM, target=filepath,
            ))
        return findings

    def scan_registry(self, image_ref: str) -> list[Finding]:
        """Pull *image_ref* from a registry and scan it.

        Requires either ``docker`` or ``podman`` on PATH.  The image is
        saved to a temporary tar file, scanned, then cleaned up.

        Args:
            image_ref: OCI image reference, e.g. ``"ghcr.io/org/repo:tag"``,
                       ``"huggingface/transformers-pytorch-gpu:latest"``.

        Returns:
            List of ``Finding`` objects. Returns a single error finding if
            the pull fails (e.g. no network, unauthenticated).
        """
        cli = self._detect_container_cli()
        if cli is None:
            return [Finding.artifact(
                rule_id="OCI-REG-000",
                title="No container CLI found",
                description="Neither 'docker' nor 'podman' is available on PATH. "
                            "Install one to enable registry scanning.",
                severity=Severity.INFO,
                target=image_ref,
            )]

        with tempfile.TemporaryDirectory(prefix="sentinel-oci-") as tmpdir:
            tar_path = os.path.join(tmpdir, "image.tar")
            try:
                subprocess.run(
                    [cli, "pull", image_ref],
                    check=True,
                    capture_output=True,
                    timeout=300,
                )
                subprocess.run(
                    [cli, "save", "-o", tar_path, image_ref],
                    check=True,
                    capture_output=True,
                    timeout=300,
                )
            except subprocess.CalledProcessError as exc:
                stderr = exc.stderr.decode(errors="replace")[:500] if exc.stderr else ""
                return [Finding.artifact(
                    rule_id="OCI-REG-001",
                    title=f"Failed to pull image: {image_ref}",
                    description=f"{cli} pull/save failed: {stderr}",
                    severity=Severity.INFO,
                    target=image_ref,
                )]
            except subprocess.TimeoutExpired:
                return [Finding.artifact(
                    rule_id="OCI-REG-002",
                    title=f"Timeout pulling image: {image_ref}",
                    description="docker/podman pull timed out after 300 seconds.",
                    severity=Severity.INFO,
                    target=image_ref,
                )]

            findings = self.scan_file(tar_path)
            # Replace tar_path target with image_ref in all findings
            for f in findings:
                if f.target == tar_path:
                    object.__setattr__(f, "target", image_ref) if hasattr(f, "__dataclass_fields__") else None
            return findings

    # ── Internal scanners ─────────────────────────────────────

    def _scan_manifest(self, tar: tarfile.TarFile, findings: list[Finding], target: str) -> None:
        try:
            member = tar.getmember("manifest.json")
            f = tar.extractfile(member)
            if not f:
                return
            manifest = json.loads(f.read())
            if isinstance(manifest, list):
                for entry in manifest:
                    layers = entry.get("Layers", [])
                    if len(layers) > 50:
                        findings.append(Finding.artifact(
                            rule_id="OCI-002", title="Excessive layer count",
                            description=f"{len(layers)} layers — possible layer confusion attack",
                            severity=Severity.MEDIUM, target=target,
                        ))
        except (KeyError, json.JSONDecodeError):
            pass

    def _scan_config(self, tar: tarfile.TarFile, findings: list[Finding], target: str) -> None:
        for member in tar.getmembers():
            if not member.name.endswith(".json") or member.name == "manifest.json":
                continue
            try:
                f = tar.extractfile(member)
                if not f:
                    continue
                config = json.loads(f.read())
                if not isinstance(config, dict) or "config" not in config:
                    continue
                container_cfg = config.get("config", {})
                self._check_env(container_cfg.get("Env", []), findings, target)
                self._check_user(container_cfg, findings, target)
                self._check_entrypoint(container_cfg, findings, target)
                self._check_history(config.get("history", []), findings, target)
            except (json.JSONDecodeError, OSError):
                continue

    def _check_env(self, env_list: list, findings: list[Finding], target: str) -> None:
        for env in env_list:
            if not isinstance(env, str):
                continue
            key = env.split("=", 1)[0] if "=" in env else env
            if key in DANGEROUS_ENVS:
                val = env.split("=", 1)[1] if "=" in env else ""
                findings.append(Finding.artifact(
                    rule_id="OCI-003", title=f"Secret in container env: {key}",
                    description="Hardcoded credential in container environment",
                    severity=Severity.CRITICAL, target=target,
                    evidence=f"{key}={val[:8]}...", cwe_ids=["CWE-798"],
                ))

    def _check_user(self, config: dict, findings: list[Finding], target: str) -> None:
        user = config.get("User", "")
        if not user or user == "root" or user == "0":
            findings.append(Finding.artifact(
                rule_id="OCI-004", title="Container runs as root",
                description="ML container running as root user",
                severity=Severity.MEDIUM, target=target, cwe_ids=["CWE-250"],
            ))

    def _check_entrypoint(self, config: dict, findings: list[Finding], target: str) -> None:
        for key in ("Entrypoint", "Cmd"):
            cmd = config.get(key, [])
            if isinstance(cmd, list):
                cmd_str = " ".join(cmd).encode()
            elif isinstance(cmd, str):
                cmd_str = cmd.encode()
            else:
                continue
            for pat in DANGEROUS_COMMANDS:
                if pat in cmd_str:
                    findings.append(Finding.artifact(
                        rule_id="OCI-005", title=f"Dangerous command in {key}: {pat.decode()}",
                        description="Container entrypoint/cmd contains risky operation",
                        severity=Severity.HIGH, target=target,
                        evidence=cmd_str.decode(errors="replace")[:200],
                    ))

    def _check_history(self, history: list, findings: list[Finding], target: str) -> None:
        for entry in history:
            cmd = entry.get("created_by", "")
            if not isinstance(cmd, str):
                continue
            for pat in DANGEROUS_COMMANDS:
                if pat in cmd.encode():
                    findings.append(Finding.artifact(
                        rule_id="OCI-006", title=f"Dangerous command in build history: {pat.decode()}",
                        description="Dockerfile history contains risky operation",
                        severity=Severity.MEDIUM, target=target,
                        evidence=cmd[:200],
                    ))

    def _scan_layers(self, tar: tarfile.TarFile, findings: list[Finding], target: str) -> None:
        for member in tar.getmembers():
            if not member.name.endswith("/layer.tar") and not member.name.endswith(".tar.gz"):
                continue
            try:
                layer_f = tar.extractfile(member)
                if not layer_f:
                    continue
                layer_data = layer_f.read()
                layer_io = io.BytesIO(layer_data)
                if tarfile.is_tarfile(layer_io):
                    layer_io.seek(0)
                    with tarfile.open(fileobj=layer_io, mode="r:*") as layer_tar:
                        self._scan_layer_contents(layer_tar, findings, target, member.name)
            except Exception:
                continue

    def _scan_layer_contents(
        self,
        layer_tar: tarfile.TarFile,
        findings: list[Finding],
        target: str,
        layer_name: str,
    ) -> None:
        model_files: list[str] = []
        for lm in layer_tar.getmembers():
            suffix = Path(lm.name).suffix.lower()
            if suffix in MODEL_EXTENSIONS:
                model_files.append(lm.name)
                if lm.size > 100_000_000:
                    findings.append(Finding.artifact(
                        rule_id="OCI-007", title=f"Large model in container: {lm.name}",
                        description=f"Model file {lm.size / 1e6:.0f}MB in layer {layer_name}",
                        severity=Severity.LOW, target=target,
                        evidence=lm.name,
                    ))

                # ── Deep artifact scanning ──────────────────────
                if self._deep_scan and lm.size <= self._max_model_bytes:
                    findings.extend(
                        self._deep_scan_model(layer_tar, lm, suffix, target, layer_name)
                    )
                elif suffix in PICKLE_EXTENSIONS:
                    # Even without deep scan, flag pickle presence
                    findings.append(Finding.artifact(
                        rule_id="OCI-008", title=f"Pickle file in container: {lm.name}",
                        description="Pickle file in OCI image — potential code execution vector",
                        severity=Severity.HIGH, target=target,
                        evidence=f"{layer_name}/{lm.name}", cwe_ids=["CWE-502"],
                    ))

            if lm.issym() or lm.islnk():
                link_target = lm.linkname
                if link_target.startswith("/") or ".." in link_target:
                    findings.append(Finding.artifact(
                        rule_id="OCI-009", title=f"Suspicious symlink: {lm.name} -> {link_target}",
                        description="Symlink pointing outside layer — path traversal risk",
                        severity=Severity.HIGH, target=target,
                        evidence=f"{lm.name} -> {link_target}", cwe_ids=["CWE-22"],
                    ))
            if lm.mode and (lm.mode & 0o4000 or lm.mode & 0o2000):
                findings.append(Finding.artifact(
                    rule_id="OCI-010", title=f"SUID/SGID binary: {lm.name}",
                    description="Setuid/setgid binary in container",
                    severity=Severity.HIGH, target=target,
                    evidence=f"{lm.name} mode={oct(lm.mode)}", cwe_ids=["CWE-250"],
                ))
        if model_files:
            findings.append(Finding.artifact(
                rule_id="OCI-011", title=f"Model files in container: {len(model_files)} found",
                description=f"Model files: {', '.join(model_files[:5])}",
                severity=Severity.INFO, target=target,
            ))

    def _deep_scan_model(
        self,
        layer_tar: tarfile.TarFile,
        member: tarfile.TarInfo,
        suffix: str,
        target: str,
        layer_name: str,
    ) -> list[Finding]:
        """Extract model file bytes from layer and run appropriate artifact scanner."""
        source_label = f"{target}!{layer_name}/{member.name}"
        try:
            f = layer_tar.extractfile(member)
            if f is None:
                return []
            data = f.read(self._max_model_bytes)
        except Exception as exc:
            logger.debug("Could not extract %s: %s", member.name, exc)
            return []

        findings: list[Finding] = []

        if suffix in PICKLE_EXTENSIONS:
            scanner = _get_pickle_scanner()
            if scanner:
                try:
                    findings.extend(scanner.scan_bytes(data, source=source_label))
                except Exception as exc:
                    logger.debug("PickleScanner failed on %s: %s", source_label, exc)

        elif suffix in SAFETENSORS_EXTENSIONS:
            scanner = _get_safetensors_scanner()
            if scanner:
                try:
                    findings.extend(scanner.scan_bytes(data, source=source_label))
                except Exception as exc:
                    logger.debug("SafetensorsScanner failed on %s: %s", source_label, exc)

        elif suffix in GGUF_EXTENSIONS:
            scanner = _get_gguf_scanner()
            if scanner and hasattr(scanner, "scan_bytes"):
                try:
                    findings.extend(scanner.scan_bytes(data, source=source_label))
                except Exception as exc:
                    logger.debug("GGUFAnalyzer failed on %s: %s", source_label, exc)

        return findings

    # ── Helpers ───────────────────────────────────────────────

    @staticmethod
    def _detect_container_cli() -> str | None:
        """Return 'docker' or 'podman' if available, else None."""
        for cli in ("docker", "podman"):
            if shutil.which(cli):
                return cli
        return None

