"""Detect knowledge base and enrichment sources for offline BOM enrichment."""
from __future__ import annotations

import re
from pathlib import Path

from sentinel.aibom.models import AIComponent, AIComponentType
from sentinel.aibom.scanners.base import BaseAIBOMScanner

_KB_FILE_PATTERNS = {
    "model_card.md": "model-card",
    "model_card.json": "model-card-json",
    "README.md": None,
    "config.json": None,
    "tokenizer.json": "tokenizer-config",
    "tokenizer_config.json": "tokenizer-config",
    "special_tokens_map.json": "tokenizer-config",
    "generation_config.json": "generation-config",
    "adapter_config.json": "adapter-config",
    "preprocessor_config.json": "preprocessor-config",
}

_HF_MODEL_CARD_RE = re.compile(r"^---\s*\n.*?model-index:", re.DOTALL)
_LICENSE_RE = re.compile(r"license:\s*(\S+)")
_DATASET_RE = re.compile(r"datasets?:\s*\n((?:\s*-\s*.+\n)*)")


class KBEnrichmentScanner(BaseAIBOMScanner):
    name = "kb-enrichment-scanner"

    def scan(self, root: Path) -> list[AIComponent]:
        out: list[AIComponent] = []
        for p in self._iter_files(root):
            kind = _KB_FILE_PATTERNS.get(p.name)
            if kind is None and p.name not in _KB_FILE_PATTERNS:
                continue
            if p.name == "README.md":
                self._scan_model_card_readme(p, out)
            elif p.name in ("config.json", "generation_config.json"):
                self._scan_model_config(p, out)
            elif kind:
                out.append(AIComponent(
                    type=AIComponentType.CONFIG,
                    name=f"kb:{kind}:{p.name}",
                    path=str(p),
                    description=f"Knowledge base artifact: {p.name}",
                    evidence=[kind],
                    properties={"kb_type": kind},
                ))
        return out

    def _scan_model_card_readme(self, p: Path, out: list[AIComponent]) -> None:
        text = self._read(p)
        if not _HF_MODEL_CARD_RE.match(text):
            return
        props: dict = {"kb_type": "hf-model-card"}
        license_m = _LICENSE_RE.search(text[:2000])
        if license_m:
            props["license"] = license_m.group(1)
        dataset_m = _DATASET_RE.search(text[:5000])
        if dataset_m:
            datasets = [d.strip("- \n") for d in dataset_m.group(1).strip().split("\n") if d.strip()]
            props["datasets"] = datasets[:10]
        out.append(AIComponent(
            type=AIComponentType.CONFIG,
            name="kb:hf-model-card",
            path=str(p),
            description="HuggingFace model card with metadata",
            evidence=["hf-model-card"],
            properties=props,
            license=props.get("license", ""),
        ))

    def _scan_model_config(self, p: Path, out: list[AIComponent]) -> None:
        import json
        try:
            data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return
        if not isinstance(data, dict):
            return
        model_type = data.get("model_type", "")
        architectures = data.get("architectures", [])
        if model_type or architectures:
            out.append(AIComponent(
                type=AIComponentType.CONFIG,
                name=f"kb:model-config:{model_type or 'unknown'}",
                path=str(p),
                description=f"Model configuration: {model_type}",
                evidence=["model-config-json"],
                properties={
                    "model_type": model_type,
                    "architectures": architectures[:5] if isinstance(architectures, list) else [],
                    "hidden_size": data.get("hidden_size"),
                    "vocab_size": data.get("vocab_size"),
                },
            ))
