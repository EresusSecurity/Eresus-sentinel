"""Extract container image metadata and link AI-relevant containers to BOM."""
from __future__ import annotations

import re
from pathlib import Path

import yaml

from sentinel.aibom.models import AIComponent, AIComponentType
from sentinel.aibom.scanners.base import BaseAIBOMScanner

_FROM_RE = re.compile(r"^FROM\s+(\S+)", re.MULTILINE)
_IMAGE_RE = re.compile(r"image:\s*[\"']?(\S+)[\"']?")

_AI_IMAGE_HINTS = (
    "ollama", "vllm", "tritonserver", "text-generation-inference",
    "localai", "bentoml", "sagemaker", "huggingface", "pytorch",
    "tensorflow", "nvidia/cuda", "deepspeed", "mlflow",
)


def _is_ai_image(image: str) -> bool:
    lower = image.lower()
    return any(hint in lower for hint in _AI_IMAGE_HINTS)


class ContainerExtractor(BaseAIBOMScanner):
    name = "container-extractor"

    def scan(self, root: Path) -> list[AIComponent]:
        out: list[AIComponent] = []
        seen: set[str] = set()

        for p in self._iter_files(root, names=("Dockerfile",)):
            self._scan_dockerfile(p, seen, out)
        for p in self._iter_files(root):
            if p.name.startswith("Dockerfile."):
                self._scan_dockerfile(p, seen, out)
        for p in self._iter_files(root, names=(
            "docker-compose.yml", "docker-compose.yaml",
            "compose.yml", "compose.yaml",
        )):
            self._scan_compose(p, seen, out)
        for p in self._iter_files(root, suffixes=(".yaml", ".yml")):
            text = self._read(p)
            if "apiVersion:" in text and "kind:" in text:
                self._scan_k8s_images(p, text, seen, out)
        return out

    def _scan_dockerfile(self, p: Path, seen: set, out: list) -> None:
        text = self._read(p)
        for m in _FROM_RE.finditer(text):
            image = m.group(1).strip()
            if image in seen or image == "scratch":
                continue
            seen.add(image)
            line_no = text[:m.start()].count("\n") + 1
            props: dict = {"image": image, "source": "Dockerfile", "line": line_no}
            if ":" in image:
                parts = image.rsplit(":", 1)
                props["tag"] = parts[1]
            out.append(AIComponent(
                type=AIComponentType.CONTAINER,
                name=image[:120],
                path=str(p),
                description=f"Container image: {image}",
                evidence=["dockerfile-from"],
                properties=props,
                risks=["AI-serving container"] if _is_ai_image(image) else [],
            ))

    def _scan_compose(self, p: Path, seen: set, out: list) -> None:
        text = self._read(p)
        try:
            data = yaml.safe_load(text)
        except Exception:
            return
        if not isinstance(data, dict):
            return
        services = data.get("services", {})
        if not isinstance(services, dict):
            return
        for svc_name, svc_config in services.items():
            if not isinstance(svc_config, dict):
                continue
            image = svc_config.get("image", "")
            if not isinstance(image, str) or not image or image in seen:
                continue
            seen.add(image)
            out.append(AIComponent(
                type=AIComponentType.CONTAINER,
                name=image[:120],
                path=str(p),
                description=f"Compose service '{svc_name}': {image}",
                evidence=["docker-compose-image"],
                properties={"image": image, "service": svc_name, "source": "docker-compose"},
                risks=["AI-serving container"] if _is_ai_image(image) else [],
            ))

    def _scan_k8s_images(self, p: Path, text: str, seen: set, out: list) -> None:
        for m in _IMAGE_RE.finditer(text):
            image = m.group(1).strip().rstrip("\"'")
            if image in seen or not image:
                continue
            seen.add(image)
            if _is_ai_image(image):
                out.append(AIComponent(
                    type=AIComponentType.CONTAINER,
                    name=image[:120],
                    path=str(p),
                    description=f"K8s AI container: {image}",
                    evidence=["k8s-ai-image"],
                    properties={"image": image, "source": "k8s-manifest"},
                ))
