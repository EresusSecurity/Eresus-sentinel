"""Container image input support for AIBOM scans."""

from __future__ import annotations

import shutil
import tarfile
import tempfile
from pathlib import Path

from sentinel.aibom.models import AIBOMResult, AIComponent, AIComponentType
from sentinel.aibom.scan_pipeline import ScanPipeline

_SOURCE_SUFFIXES = {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".java", ".rb", ".cs", ".json", ".yaml", ".yml"}


def detect_container_runtime() -> dict[str, str | None]:
    """Return available container tooling in priority order."""
    return {
        "docker": shutil.which("docker"),
        "podman": shutil.which("podman"),
        "crane": shutil.which("crane"),
        "skopeo": shutil.which("skopeo"),
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
        for item in extracted.components:
            item.properties["container_image"] = image
            result.add(item)
        result.relationships.extend(extracted.relationships)
    else:
        result.metadata["extraction_status"] = "runtime-required"
    return result


def _scan_local_tar(path: Path) -> AIBOMResult:
    with tempfile.TemporaryDirectory(prefix="sentinel-aibom-image-") as tmp:
        target = Path(tmp)
        copied = 0
        try:
            with tarfile.open(path) as archive:
                for member in archive.getmembers():
                    if not member.isfile():
                        continue
                    member_path = Path(member.name)
                    if member_path.suffix.lower() not in _SOURCE_SUFFIXES and member_path.name not in {"Dockerfile", "requirements.txt", "package.json"}:
                        continue
                    destination = _safe_destination(target, member_path)
                    if destination is None:
                        continue
                    source = archive.extractfile(member)
                    if source is None:
                        continue
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(source.read(512_000))
                    copied += 1
        except tarfile.TarError:
            return AIBOMResult(metadata={"archive_members_scanned": copied, "archive_error": "invalid tar"})
        result = ScanPipeline().run(target)
        result.metadata["archive_members_scanned"] = copied
        return result


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
