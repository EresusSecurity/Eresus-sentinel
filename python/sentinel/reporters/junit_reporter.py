"""JUnit XML report generator for Sentinel findings.

Maps Sentinel findings to JUnit test cases so CI systems (GitHub Actions,
Jenkins, GitLab CI) can display results natively.

Mapping:
  - Each unique (rule_id, target) pair → one <testcase>
  - CRITICAL/HIGH findings → <failure>
  - MEDIUM/LOW findings → <skipped> with message
  - INFO findings → passing testcase with system-out
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any

from sentinel.reporters.base import BaseReporter

_FAIL_SEVERITIES = {"critical", "high"}
_SKIP_SEVERITIES = {"medium", "low"}


def _sev(f) -> str:
    return str(getattr(getattr(f, "severity", None), "value", getattr(f, "severity", "info"))).lower()


class JUnitReporter(BaseReporter):
    """Generate JUnit XML from Sentinel findings."""

    def generate(self, findings: list, metadata: dict[str, Any] | None = None) -> str:
        meta = metadata or {}
        timestamp = meta.get("timestamp") or datetime.now(timezone.utc).isoformat()
        scan_path = str(meta.get("scan_path", "."))

        failures = sum(1 for f in findings if _sev(f) in _FAIL_SEVERITIES)
        skipped = sum(1 for f in findings if _sev(f) in _SKIP_SEVERITIES)

        suite = ET.Element("testsuite")
        suite.set("name", "Eresus Sentinel")
        suite.set("tests", str(len(findings) or 1))
        suite.set("failures", str(failures))
        suite.set("errors", "0")
        suite.set("skipped", str(skipped))
        suite.set("timestamp", timestamp)
        suite.set("hostname", scan_path)

        if not findings:
            tc = ET.SubElement(suite, "testcase")
            tc.set("name", "sentinel.no_findings")
            tc.set("classname", "sentinel")
            tc.set("time", "0")
            sys_out = ET.SubElement(tc, "system-out")
            sys_out.text = "No findings — scan clean."
        else:
            for f in findings:
                tc = self._finding_to_testcase(f)
                suite.append(tc)

        ET.indent(suite, space="  ")
        xml_bytes = ET.tostring(suite, encoding="unicode", xml_declaration=True)
        if not xml_bytes.startswith("<?xml"):
            xml_bytes = '<?xml version="1.0" encoding="UTF-8"?>\n' + xml_bytes
        return xml_bytes

    @staticmethod
    def _finding_to_testcase(f) -> ET.Element:
        sev = _sev(f)
        rule_id = str(getattr(f, "rule_id", "UNKNOWN"))
        title = str(getattr(f, "title", rule_id))
        target = str(getattr(f, "target", ""))
        description = str(getattr(f, "description", ""))
        classname = f"sentinel.{getattr(f, 'module', 'scan')}"
        name = f"{rule_id}: {title}"

        tc = ET.Element("testcase")
        tc.set("name", name)
        tc.set("classname", classname)
        tc.set("time", "0")

        if sev in _FAIL_SEVERITIES:
            failure = ET.SubElement(tc, "failure")
            failure.set("message", title)
            failure.set("type", sev.upper())
            failure.text = (
                f"Rule: {rule_id}\n"
                f"Severity: {sev.upper()}\n"
                f"Target: {target}\n"
                f"Description: {description}"
            )
        elif sev in _SKIP_SEVERITIES:
            skipped = ET.SubElement(tc, "skipped")
            skipped.set("message", f"[{sev.upper()}] {title}")
        else:
            sys_out = ET.SubElement(tc, "system-out")
            sys_out.text = f"[INFO] {rule_id}: {description}"

        return tc
