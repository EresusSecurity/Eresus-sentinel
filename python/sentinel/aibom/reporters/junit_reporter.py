"""JUnit XML reporter for CI integration."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from xml.dom import minidom

from sentinel.aibom.models import AIBOMResult
from sentinel.aibom.reporters.base import BaseAIBOMReporter


class JUnitReporter(BaseAIBOMReporter):
    name = "junit"
    extension = "xml"

    def render(self, result: AIBOMResult) -> str:
        failures = [c for c in result.components if c.risks]
        suite = ET.Element(
            "testsuite",
            name="eresus-aibom",
            tests=str(len(result.components)),
            failures=str(len(failures)),
            errors="0",
        )
        for c in result.components:
            case = ET.SubElement(suite, "testcase", classname=c.type.value, name=c.name)
            if c.risks:
                failure = ET.SubElement(case, "failure", type="risk", message="; ".join(c.risks))
                failure.text = c.description or ""
        return minidom.parseString(ET.tostring(suite)).toprettyxml(indent="  ")
