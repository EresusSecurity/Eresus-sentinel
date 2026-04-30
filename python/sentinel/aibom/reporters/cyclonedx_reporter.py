"""CycloneDX 1.6 reporter."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from sentinel.aibom.models import AIBOMResult, AIComponentType
from sentinel.aibom.reporters.base import BaseAIBOMReporter

_TYPE_MAP = {
    AIComponentType.MODEL_LLM: "machine-learning-model",
    AIComponentType.MODEL_EMBEDDING: "machine-learning-model",
    AIComponentType.MODEL_IMAGE: "machine-learning-model",
    AIComponentType.MODEL_AUDIO: "machine-learning-model",
    AIComponentType.MODEL_VIDEO: "machine-learning-model",
    AIComponentType.MODEL_VISION: "machine-learning-model",
    AIComponentType.MODEL_MULTIMODAL: "machine-learning-model",
    AIComponentType.MODEL_RERANKER: "machine-learning-model",
    AIComponentType.DATASET: "data",
    AIComponentType.CONTAINER: "container",
    AIComponentType.CONFIG: "file",
}


class CycloneDXReporter(BaseAIBOMReporter):
    name = "cyclonedx"
    extension = "json"
    spec_version = "1.6"

    def render(self, result: AIBOMResult) -> str:
        doc = {
            "bomFormat": "CycloneDX",
            "specVersion": self.spec_version,
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": [{"vendor": "Eresus", "name": "Sentinel", "version": result.version}],
            },
            "components": [self._component(c) for c in result.components],
            "dependencies": self._dependencies(result),
        }
        return json.dumps(doc, indent=2, default=str)

    @staticmethod
    def _component(c) -> dict:
        comp = {
            "bom-ref": c.id,
            "type": _TYPE_MAP.get(c.type, "application"),
            "name": c.name,
            "description": c.description,
            "properties": [
                {"name": "sentinel:type", "value": c.type.value},
                *[{"name": f"prop:{k}", "value": str(v)} for k, v in c.properties.items()],
            ],
        }
        if c.version:
            comp["version"] = c.version
        if c.hashes:
            comp["hashes"] = [
                {"alg": alg.upper(), "content": value} for alg, value in c.hashes.items()
            ]
        if c.license:
            comp["licenses"] = [{"license": {"id": c.license}}]
        if c.evidence:
            comp["evidence"] = {"identity": [{"field": "name", "methods": [{"technique": "manifest-analysis", "value": e} for e in c.evidence]}]}
        return comp

    @staticmethod
    def _dependencies(result: AIBOMResult) -> list[dict]:
        deps: dict[str, list[str]] = {}
        for rel in result.relationships:
            deps.setdefault(rel.source_id, []).append(rel.target_id)
        return [{"ref": r, "dependsOn": list(set(d))} for r, d in deps.items()]
