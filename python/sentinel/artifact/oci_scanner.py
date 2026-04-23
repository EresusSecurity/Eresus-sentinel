"""OCI container image scanner — detect model files, secrets, misconfigurations."""
from __future__ import annotations
import io
import json
import logging
import tarfile
from pathlib import Path
from sentinel.finding import Finding, Severity

logger = logging.getLogger(__name__)

MODEL_EXTENSIONS = {
    ".pt", ".pth", ".bin", ".ckpt", ".safetensors", ".gguf", ".onnx", ".pb",
    ".tflite", ".keras", ".h5", ".hdf5", ".pkl", ".pickle", ".joblib",
    ".npy", ".npz", ".xgb", ".cbm", ".mlmodel", ".nemo", ".mar",
    ".pdmodel", ".params", ".t7", ".engine", ".plan", ".skops",
}

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


class OCIScanner:
    """Scan OCI/Docker container images for model security issues."""

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

    def _scan_layer_contents(self, layer_tar: tarfile.TarFile, findings: list[Finding], target: str, layer_name: str) -> None:
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
            if suffix in (".pkl", ".pickle"):
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
