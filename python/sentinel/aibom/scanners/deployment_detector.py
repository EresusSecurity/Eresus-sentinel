"""Detect AI/ML deployment evidence in Kubernetes, Helm, Terraform, and cloud configs."""
from __future__ import annotations

import re
from pathlib import Path

import yaml

from sentinel.aibom.models import AIComponent, AIComponentType
from sentinel.aibom.scanners.base import BaseAIBOMScanner
from sentinel.rules import load_aibom_patterns

_TF_RESOURCE_RE = re.compile(r'resource\s+"([^"]+)"\s+"([^"]+)"', re.MULTILINE)
_K8S_WORKLOAD_KINDS = frozenset({"Deployment", "StatefulSet", "Job", "CronJob"})


class DeploymentDetector(BaseAIBOMScanner):
    name = "deployment-detector"

    def scan(self, root: Path) -> list[AIComponent]:
        out: list[AIComponent] = []
        for p in self._iter_files(root, suffixes=(".yaml", ".yml")):
            self._scan_k8s_helm(p, out)
        for p in self._iter_files(root, suffixes=(".tf",)):
            self._scan_terraform(p, out)
        for p in self._iter_files(root, names=("Dockerfile", "docker-compose.yml", "docker-compose.yaml")):
            self._scan_docker(p, out)
        return out

    def _scan_k8s_helm(self, p: Path, out: list[AIComponent]) -> None:
        text = self._read(p)
        try:
            docs = list(yaml.safe_load_all(text))
        except Exception:
            return
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            kind = doc.get("kind", "")
            if kind in _K8S_WORKLOAD_KINDS:
                self._extract_k8s_workload(p, doc, text, out)
            elif kind in ("ConfigMap", "Secret"):
                self._extract_k8s_config(p, doc, out)

    def _extract_k8s_workload(self, p: Path, doc: dict, text: str, out: list[AIComponent]) -> None:
        dep = load_aibom_patterns()["deployment"]
        spec = (doc.get("spec") or {}).get("template", {}).get("spec", {})
        for container in spec.get("containers", []):
            if not isinstance(container, dict):
                continue
            image = container.get("image", "")
            if isinstance(image, str) and self._image_is_ai(image, dep["ai_container_images"]):
                out.append(AIComponent(
                    type=AIComponentType.CONTAINER,
                    name=image[:120],
                    path=str(p),
                    description=f"AI container image: {image}",
                    evidence=["k8s-ai-image"],
                    properties={"image": image, "kind": doc.get("kind", "")},
                ))
            resources = (container.get("resources") or {}).get("limits", {})
            gpu_re = dep["gpu_re"]
            if isinstance(resources, dict) and gpu_re and any(gpu_re.search(k) for k in resources):
                out.append(AIComponent(
                    type=AIComponentType.CONFIG,
                    name=f"gpu-request:{container.get('name', 'unknown')}",
                    path=str(p),
                    description="GPU resource request in K8s workload",
                    evidence=["k8s-gpu-resource"],
                    properties={"limits": dict(resources)},
                ))

    def _extract_k8s_config(self, p: Path, doc: dict, out: list[AIComponent]) -> None:
        for section_key in ("data", "stringData"):
            data = doc.get(section_key)
            if not isinstance(data, dict):
                continue
            for k, v in data.items():
                if isinstance(v, str) and re.search(r"(?i)(openai|anthropic|model|llm|embedding)", k):
                    out.append(AIComponent(
                        type=AIComponentType.CONFIG,
                        name=f"k8s-config:{k}",
                        path=str(p),
                        description=f"AI config in {doc.get('kind', 'ConfigMap')}: {k}",
                        evidence=["k8s-ai-config"],
                        properties={"key": k, "kind": doc.get("kind", "")},
                    ))

    @staticmethod
    def _image_is_ai(image: str, ai_images: tuple) -> bool:
        lower = image.lower()
        return any(hint.lower() in lower for hint in ai_images)

    def _scan_terraform(self, p: Path, out: list[AIComponent]) -> None:
        dep = load_aibom_patterns()["deployment"]
        text = self._read(p)
        for m in _TF_RESOURCE_RE.finditer(text):
            resource_type = m.group(1)
            if resource_type in dep["terraform_ai_resources"]:
                out.append(AIComponent(
                    type=AIComponentType.CONFIG,
                    name=f"tf:{resource_type}:{m.group(2)}",
                    path=str(p),
                    description=f"Terraform AI resource: {resource_type}",
                    evidence=["terraform-ai-resource"],
                    properties={"resource_type": resource_type, "name": m.group(2)},
                ))

    def _scan_docker(self, p: Path, out: list[AIComponent]) -> None:
        dep = load_aibom_patterns()["deployment"]
        text = self._read(p)
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("FROM ") or "image:" in stripped:
                image = stripped.split()[-1] if "FROM" in stripped else stripped.split("image:")[-1].strip()
                if self._image_is_ai(image, dep["ai_container_images"]):
                    out.append(AIComponent(
                        type=AIComponentType.CONTAINER,
                        name=image[:120],
                        path=str(p),
                        description=f"AI container image: {image}",
                        evidence=["docker-ai-image"],
                        properties={"image": image},
                    ))
