"""Sentinel report generator package.

Provides multiple output formats for Finding lists.

Usage:
    from sentinel.reporters import get_reporter
    reporter = get_reporter("html")
    output = reporter.generate(findings, metadata={"scan_path": "."})
"""
from __future__ import annotations

from sentinel.reporters.base import BaseReporter
from sentinel.reporters.csv_reporter import CsvReporter
from sentinel.reporters.html_reporter import HtmlReporter
from sentinel.reporters.junit_reporter import JUnitReporter
from sentinel.reporters.markdown_reporter import MarkdownReporter
from sentinel.reporters.table_reporter import TableReporter

_REGISTRY: dict[str, type[BaseReporter]] = {
    "html": HtmlReporter,
    "junit": JUnitReporter,
    "csv": CsvReporter,
    "markdown": MarkdownReporter,
    "md": MarkdownReporter,
    "table": TableReporter,
}


def get_reporter(fmt: str) -> BaseReporter:
    """Return a reporter instance for *fmt*.

    Args:
        fmt: Format name — ``html``, ``junit``, ``csv``, ``markdown``/``md``, ``table``.

    Raises:
        ValueError: If *fmt* is not recognised.
    """
    cls = _REGISTRY.get(fmt.lower())
    if cls is None:
        raise ValueError(
            f"Unknown report format {fmt!r}. Available: {sorted(_REGISTRY)}"
        )
    return cls()


__all__ = [
    "BaseReporter",
    "HtmlReporter",
    "JUnitReporter",
    "CsvReporter",
    "MarkdownReporter",
    "TableReporter",
    "get_reporter",
]
