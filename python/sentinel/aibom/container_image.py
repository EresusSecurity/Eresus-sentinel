"""Container image input support for AIBOM scans."""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path

from sentinel.aibom.models import AIBOMResult, AIComponent, AIComponentType
from sentinel.aibom.scan_pipeline import ScanPipeline

_SOURCE_SUFFIXES = {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".java", ".rb", ".cs", ".json", ".yaml", ".yml"}
_SOURCE_NAMES = {"Dockerfile", "requirements.txt", "package.json", "pyproject.toml"}


@dataclass(frozen=True)
class ContainerBackendResult:
    backend: str
    available: bool
    inspected: bool = False
    metadata: dict | None = None
    error: str = ""


class ContainerBackend:
    """Metadata-only container backend contract."""

    name = "base"

    def __init__(self, executable: str | None) -> None:
        self.executable = executable

    @property
    def available(self) -> bool:
        return bool(self.executable)

    def inspect(self, image: str) -> ContainerBackendResult:
        raise NotImplementedError


class DockerBackend(ContainerBackend):
    name = "docker"

    def inspect(self, image: str) -> ContainerBackendResult:
        return _run_json_inspect(self.name, self.executable, [self.executable or "docker", "image", "inspect", image])


class PodmanBackend(ContainerBackend):
    name = "podman"

    def inspect(self, image: str) -> ContainerBackendResult:
        return _run_json_inspect(self.name, self.executable, [self.executable or "podman", "image", "inspect", image])


class SkopeoBackend(ContainerBackend):
    name = "skopeo"

    def inspect(self, image: str) -> ContainerBackendResult:
        image_ref = image if "://" in image else f"docker://{image}"
        return _run_json_inspect(self.name, self.executable, [self.executable or "skopeo", "inspect", "--config", image_ref])


def detect_container_runtime() -> dict[str, str | None]:
    """Return available container tooling in priority order."""
    return {
        "docker": shutil.which("docker"),
        "podman": shutil.which("podman"),
        "crane": shutil.which("crane"),
        "skopeo": shutil.which("skopeo"),
    }


def _container_backends() -> list[ContainerBackend]:
    runtime = detect_container_runtime()
    return [
        DockerBackend(runtime.get("docker")),
        PodmanBackend(runtime.get("podman")),
        SkopeoBackend(runtime.get("skopeo")),
    ]


def _run_json_inspect(backend: str, executable: str | None, command: list[str]) -> ContainerBackendResult:
    if not executable:
        return ContainerBackendResult(backend=backend, available=False)
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except Exception as exc:
        return ContainerBackendResult(backend=backend, available=True, error=str(exc))
    if completed.returncode != 0:
        return ContainerBackendResult(
            backend=backend,
            available=True,
            error=(completed.stderr or completed.stdout).strip()[:500],
        )
    try:
        parsed = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError as exc:
        return ContainerBackendResult(backend=backend, available=True, error=str(exc))
    return ContainerBackendResult(
        backend=backend,
        available=True,
        inspected=True,
        metadata=_compact_backend_metadata(parsed),
    )


def _compact_backend_metadata(data) -> dict:
    if isinstance(data, list):
        data = data[0] if data else {}
    if not isinstance(data, dict):
        return {"raw_type": type(data).__name__}
    config = data.get("Config") if isinstance(data.get("Config"), dict) else {}
    labels = config.get("Labels") if isinstance(config.get("Labels"), dict) else {}
    return {
        "id": data.get("Id") or data.get("Digest") or "",
        "architecture": data.get("Architecture") or data.get("architecture") or "",
        "os": data.get("Os") or data.get("os") or "",
        "created": data.get("Created") or data.get("created") or "",
        "labels": {str(key): str(value) for key, value in list(labels.items())[:25]},
    }


def scan_container_image(image: str, *, extraction_tier: str = "auto") -> AIBOMResult:
    """Create an AIBOM result for a local image tarball or remote image ref.

    Live pulls are intentionally not performed here. If ``image`` points to a
    local tar archive, source-like members are safely copied to a temporary
    workspace and scanned with the normal AIBOM pipeline.
    """
    result = AIBOMResult(
        metadata={
            "container_image_scan": True,
            "image": image,
            "extraction_tier": extraction_tier,
            "runtime": detect_container_runtime(),
        }
    )
    component = AIComponent(
        type=AIComponentType.CONTAINER,
        name=image,
        description=f"Container image input: {image}",
        evidence=["aibom-container-image"],
        properties={
            "image": image,
            "extraction_tier": extraction_tier,
            "source": "image-ref",
        },
        risks=["AI-serving container"] if _looks_like_ai_image(image) else [],
    )
    result.add(component)

    path = Path(image)
    if path.is_file() and tarfile.is_tarfile(path):
        extracted = _scan_local_tar(path)
        result.metadata["archive_members_scanned"] = extracted.metadata.get("archive_members_scanned", 0)
        result.metadata["extraction_status"] = "tarball-scanned"
        for item in extracted.components:
            item.properties["container_image"] = image
            result.add(item)
        result.relationships.extend(extracted.relationships)
    elif extraction_tier == "runtime":
        backend_result = _inspect_with_runtime_backend(image)
        result.metadata["runtime_backend"] = {
            "backend": backend_result.backend,
            "available": backend_result.available,
            "inspected": backend_result.inspected,
            "error": backend_result.error,
        }
        if backend_result.metadata:
            component.properties["runtime_metadata"] = backend_result.metadata
            result.metadata["extraction_status"] = "runtime-metadata"
        else:
            result.metadata["extraction_status"] = "runtime-unavailable"
    else:
        result.metadata["extraction_status"] = "metadata-only"
    return result


def _scan_local_tar(path: Path) -> AIBOMResult:
    with tempfile.TemporaryDirectory(prefix="sentinel-aibom-image-") as tmp:
        target = Path(tmp)
        copied = 0
        try:
            with tarfile.open(path) as archive:
                copied += _copy_source_members_from_tar(archive, target)
        except tarfile.TarError:
            return AIBOMResult(metadata={"archive_members_scanned": copied, "archive_error": "invalid tar"})
        result = ScanPipeline().run(target)
        result.metadata["archive_members_scanned"] = copied
        return result


def _copy_source_members_from_tar(archive: tarfile.TarFile, target: Path, *, prefix: Path | None = None) -> int:
    copied = 0
    for member in archive.getmembers():
        if not member.isfile():
            continue
        member_path = Path(member.name)
        source = archive.extractfile(member)
        if source is None:
            continue
        if _is_nested_layer(member_path):
            data = source.read(8 * 1024 * 1024)
            try:
                with tarfile.open(fileobj=io.BytesIO(data)) as nested:
                    copied += _copy_source_members_from_tar(
                        nested,
                        target,
                        prefix=(prefix or Path()) / member_path.with_suffix("").name,
                    )
            except tarfile.TarError:
                continue
            continue
        if not _is_source_like(member_path):
            continue
        relative = (prefix or Path()) / member_path
        destination = _safe_destination(target, relative)
        if destination is None:
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.read(512_000))
        copied += 1
    return copied


def _is_source_like(path: Path) -> bool:
    return path.suffix.lower() in _SOURCE_SUFFIXES or path.name in _SOURCE_NAMES


def _is_nested_layer(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith(".tar") or name.endswith(".tar.gz") or name.endswith(".tgz")


def _safe_destination(root: Path, member_path: Path) -> Path | None:
    clean_parts = [part for part in member_path.parts if part not in {"", ".", ".."}]
    if not clean_parts:
        return None
    destination = root.joinpath(*clean_parts)
    try:
        destination.resolve().relative_to(root.resolve())
    except ValueError:
        return None
    return destination


def _looks_like_ai_image(image: str) -> bool:
    lower = image.lower()
    hints = ("ollama", "vllm", "triton", "huggingface", "pytorch", "tensorflow", "tgi", "llama", "cuda")
    return any(hint in lower for hint in hints)


def _inspect_with_runtime_backend(image: str) -> ContainerBackendResult:
    for backend in _container_backends():
        if not backend.available:
            continue
        inspected = backend.inspect(image)
        if inspected.inspected or inspected.error:
            return inspected
    return ContainerBackendResult(backend="none", available=False, error="no container runtime available")
