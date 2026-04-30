"""Platform adapters for BOM output in different ecosystem formats."""
from __future__ import annotations

from typing import Any

from sentinel.aibom.models import AIBOMResult, AIComponent


def to_cyclonedx(result: AIBOMResult) -> dict[str, Any]:
    """Convert AIBOM to CycloneDX-compatible format."""
    components = []
    for comp in result.components:
        cdx_comp: dict[str, Any] = {
            "bom-ref": comp.id,
            "type": _cyclonedx_type(comp),
            "name": comp.name,
        }
        if comp.version:
            cdx_comp["version"] = comp.version
        if comp.vendor:
            cdx_comp["publisher"] = comp.vendor
        if comp.license:
            cdx_comp["licenses"] = [{"license": {"id": comp.license}}]
        if comp.description:
            cdx_comp["description"] = comp.description
        if comp.hashes:
            cdx_comp["hashes"] = [
                {"alg": k.upper(), "content": v}
                for k, v in comp.hashes.items()
            ]
        if comp.properties:
            cdx_comp["properties"] = [
                {"name": k, "value": str(v)}
                for k, v in comp.properties.items()
                if isinstance(v, (str, int, float, bool))
            ]
        components.append(cdx_comp)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "tools": [{"name": result.tool, "version": result.version}],
            "timestamp": result.generated_at,
        },
        "components": components,
        "dependencies": [
            {
                "ref": rel.source_id,
                "dependsOn": [rel.target_id],
            }
            for rel in result.relationships
        ],
    }


def to_spdx(result: AIBOMResult) -> dict[str, Any]:
    """Convert AIBOM to SPDX-compatible format."""
    packages = []
    for comp in result.components:
        pkg: dict[str, Any] = {
            "SPDXID": f"SPDXRef-{comp.id[:36]}",
            "name": comp.name,
            "downloadLocation": "NOASSERTION",
        }
        if comp.version:
            pkg["versionInfo"] = comp.version
        if comp.vendor:
            pkg["supplier"] = f"Organization: {comp.vendor}"
        if comp.license:
            pkg["licenseConcluded"] = comp.license
        if comp.description:
            pkg["description"] = comp.description
        packages.append(pkg)

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Eresus-Sentinel-AIBOM",
        "creationInfo": {
            "created": result.generated_at,
            "creators": [f"Tool: {result.tool}-{result.version}"],
        },
        "packages": packages,
        "relationships": [
            {
                "spdxElementId": f"SPDXRef-{rel.source_id[:36]}",
                "relationshipType": _spdx_rel_type(rel.type.value),
                "relatedSpdxElement": f"SPDXRef-{rel.target_id[:36]}",
            }
            for rel in result.relationships
        ],
    }


def _cyclonedx_type(comp: AIComponent) -> str:
    type_map = {
        "model": "machine-learning-model",
        "agent": "application",
        "tool": "library",
        "secret": "data",
        "config": "data",
        "endpoint": "service",
        "container": "container",
    }
    for key, val in type_map.items():
        if key in comp.type.value.lower():
            return val
    return "library"


def _spdx_rel_type(rel_type: str) -> str:
    mapping = {
        "uses": "DEPENDS_ON",
        "contains": "CONTAINS",
        "depends_on": "DEPENDS_ON",
        "calls": "DEPENDS_ON",
        "generates": "GENERATES",
        "configured_by": "BUILD_TOOL_OF",
    }
    return mapping.get(rel_type, "OTHER")
