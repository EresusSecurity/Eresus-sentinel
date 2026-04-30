"""Pre-built AI BOM fuzz payloads."""

from __future__ import annotations

from ..base import Payload, PayloadCategory
from .generator import AIBOMFuzzerGenerator


class AIBOMPayloadFactory:
    """Produce categorized BOM/report fixtures."""

    @classmethod
    def all_payloads(cls) -> list[Payload]:
        return cls.malicious_payloads() + cls.benign_payloads()

    @classmethod
    def malicious_payloads(cls) -> list[Payload]:
        return [
            cls._payload("aibom_json_relationship_abuse", "aibom_json"),
            cls._payload("aibom_cyclonedx_external_endpoint", "cyclonedx"),
            cls._payload("aibom_spdx_self_dependency", "spdx"),
            cls._payload("aibom_sarif_path_escape", "sarif"),
            cls._payload("aibom_csv_formula_surface", "csv"),
            cls._payload("aibom_html_report_xss", "html"),
            cls._payload("aibom_project_manifest_secret", "project_zip_manifest"),
        ]

    @classmethod
    def benign_payloads(cls) -> list[Payload]:
        return [
            Payload(
                name="aibom_benign_empty",
                category=PayloadCategory.BENIGN,
                data=b'{"tool":"Eresus Sentinel AIBOM","components":[],"relationships":[]}',
                severity_expected="NONE",
            )
        ]

    @staticmethod
    def _payload(name: str, format_name: str) -> Payload:
        return Payload(
            name=name,
            category=PayloadCategory.EVASION,
            data=AIBOMFuzzerGenerator(format=format_name).generate(seed=24),
            severity_expected="MEDIUM",
            description=f"{format_name} BOM/report fuzz fixture",
            tags=["aibom", format_name],
        )
