"""SPDX 3.0.1 JSON-LD reporter."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from sentinel.aibom.models import AIBOMResult
from sentinel.aibom.reporters.base import BaseAIBOMReporter


class SPDXReporter(BaseAIBOMReporter):
    name = "spdx"
    extension = "spdx.json"

    def render(self, result: AIBOMResult) -> str:
        doc_id = f"urn:uuid:{uuid.uuid4()}"
        packages = [self._pkg(c, doc_id) for c in result.components]
        rels = [
            {
                "type": "Relationship",
                "spdxId": f"_:rel-{i}",
                "from": rel.source_id,
                "to": [rel.target_id],
                "relationshipType": rel.type.value,
            }
            for i, rel in enumerate(result.relationships)
        ]
        doc = {
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "type": "SpdxDocument",
            "spdxId": doc_id,
            "name": "Eresus Sentinel AIBOM",
            "creationInfo": {
                "type": "CreationInfo",
                "specVersion": "3.0.1",
                "created": datetime.now(timezone.utc).isoformat(),
                "createdBy": ["Eresus Sentinel"],
            },
            "rootElement": [p["spdxId"] for p in packages[:5]],
            "element": packages + rels,
        }
        return json.dumps(doc, indent=2, default=str)

    @staticmethod
    def _pkg(c, doc_id: str) -> dict:
        return {
            "type": "software_Package",
            "spdxId": c.id,
            "name": c.name,
            "packageVersion": c.version or "NOASSERTION",
            "description": c.description,
            "primaryPurpose": c.type.value,
            "extension": [{"type": "sentinel", "properties": c.properties}],
        }
