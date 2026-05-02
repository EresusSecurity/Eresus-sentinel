import textwrap

from sentinel.diff_scanner import DiffScanner
from sentinel.sast.analyzer import SASTAnalyzer
from sentinel.sast.secrets_scanner import EntropyConfig, EntropyDetector


def test_sast_cross_file_taint_tracks_imported_user_input(tmp_path):
    (tmp_path / "sources.py").write_text(
        textwrap.dedent(
            """
            from flask import request

            def payload():
                return request.get_json().get("expr")
            """
        ),
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        textwrap.dedent(
            """
            from sources import payload

            def run():
                data = payload()
                return eval(data)
            """
        ),
        encoding="utf-8",
    )

    findings = SASTAnalyzer().scan_path(str(tmp_path))

    cross = [f for f in findings if f.rule_id == "SAST-CROSS-001"]
    assert cross
    assert cross[0].severity.value == "high"
    assert "sources.py" in cross[0].description


def test_sast_cross_file_taint_tracks_module_alias_calls(tmp_path):
    (tmp_path / "sources.py").write_text(
        textwrap.dedent(
            """
            def payload():
                return input("expr> ")
            """
        ),
        encoding="utf-8",
    )
    (tmp_path / "runner.py").write_text(
        textwrap.dedent(
            """
            import sources as src

            exec(src.payload())
            """
        ),
        encoding="utf-8",
    )

    findings = SASTAnalyzer().scan_path(str(tmp_path))

    assert any(f.rule_id == "SAST-CROSS-001" for f in findings)


def test_secrets_entropy_thresholds_flag_random_tokens_not_uuids():
    detector = EntropyDetector(EntropyConfig())

    random_findings = detector.scan_line(
        'API_TOKEN="xqy7I9mN2pQv8ZrL4sTu6WbY0cDeFgHj"',
        1,
        "settings.py",
    )
    uuid_findings = detector.scan_line(
        'TRACE_ID="550e8400-e29b-41d4-a716-446655440000"',
        2,
        "settings.py",
    )

    assert {f.rule_id for f in random_findings} & {"SEC-ENTROPY-B64", "SEC-ENTROPY-GEN"}
    assert uuid_findings == []


def test_diff_scanner_pr_mode_tags_findings():
    diff_text = textwrap.dedent(
        """
        diff --git a/model.py b/model.py
        index 1111111..2222222 100644
        --- a/model.py
        +++ b/model.py
        @@ -1,2 +1,2 @@
        +model = torch.load("weights.pt")
        """
    )

    findings = DiffScanner().scan_pr_patch(
        diff_text,
        base_ref="main",
        head_ref="feature/deser",
        pr_number="42",
    )

    assert any(f.rule_id == "DIFF-DESER-002" for f in findings)
    tags = findings[0].tags
    assert "mode:pr" in tags
    assert "base:main" in tags
    assert "head:feature/deser" in tags
    assert "pr:42" in tags
