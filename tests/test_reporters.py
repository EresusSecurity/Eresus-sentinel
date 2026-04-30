"""Tests for sentinel.reporters package."""
from __future__ import annotations

import unittest
from dataclasses import dataclass


@dataclass
class _FakeFinding:
    rule_id: str = "TEST-001"
    title: str = "Test finding"
    description: str = "A test finding for reporters"
    target: str = "test.py"
    severity: str = "high"
    confidence: float = 0.9
    module: str = "test"


class TestGetReporter(unittest.TestCase):

    def test_known_formats(self):
        from sentinel.reporters import get_reporter
        for fmt in ("html", "junit", "csv", "markdown", "md", "table"):
            r = get_reporter(fmt)
            self.assertIsNotNone(r)

    def test_unknown_format_raises(self):
        from sentinel.reporters import get_reporter
        with self.assertRaises(ValueError):
            get_reporter("pdf")


class TestHtmlReporter(unittest.TestCase):

    def test_empty_findings(self):
        from sentinel.reporters import get_reporter
        r = get_reporter("html")
        output = r.generate([], {"scan_path": "/test"})
        self.assertIn("<!DOCTYPE html>", output)
        self.assertIn("No findings", output)

    def test_with_findings(self):
        from sentinel.reporters import get_reporter
        r = get_reporter("html")
        output = r.generate([_FakeFinding()], {"scan_path": "/test"})
        self.assertIn("TEST-001", output)
        self.assertIn("Test finding", output)


class TestJUnitReporter(unittest.TestCase):

    def test_empty_findings(self):
        from sentinel.reporters import get_reporter
        r = get_reporter("junit")
        output = r.generate([])
        self.assertIn("<testsuite", output)
        self.assertIn("sentinel.no_findings", output)

    def test_high_severity_is_failure(self):
        from sentinel.reporters import get_reporter
        r = get_reporter("junit")
        output = r.generate([_FakeFinding(severity="high")])
        self.assertIn("<failure", output)

    def test_low_severity_is_skipped(self):
        from sentinel.reporters import get_reporter
        r = get_reporter("junit")
        output = r.generate([_FakeFinding(severity="low")])
        self.assertIn("<skipped", output)


class TestCsvReporter(unittest.TestCase):

    def test_has_header(self):
        from sentinel.reporters import get_reporter
        r = get_reporter("csv")
        output = r.generate([])
        self.assertTrue(output.startswith("rule_id,"))

    def test_has_row(self):
        from sentinel.reporters import get_reporter
        r = get_reporter("csv")
        output = r.generate([_FakeFinding()])
        self.assertIn("TEST-001", output)


class TestMarkdownReporter(unittest.TestCase):

    def test_has_header(self):
        from sentinel.reporters import get_reporter
        r = get_reporter("markdown")
        output = r.generate([_FakeFinding()], {"scan_path": "/test"})
        self.assertIn("# ", output)
        self.assertIn("TEST-001", output)


class TestTableReporter(unittest.TestCase):

    def test_generates_output(self):
        from sentinel.reporters import get_reporter
        r = get_reporter("table")
        output = r.generate([_FakeFinding()])
        self.assertIn("TEST-001", output)


if __name__ == "__main__":
    unittest.main()
