from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_phase17_docs_exist_and_are_linked():
    expected = {
        "CLI_REFERENCE.md",
        "RULE_AUTHORING.md",
        "SCANNER_AUTHORING.md",
        "MCP_PROXY_DEPLOYMENT.md",
        "CI_PRECOMMIT.md",
        "TROUBLESHOOTING.md",
        "FALSE_POSITIVES.md",
        "FAQ.md",
        "TR_QUICKSTART.md",
    }

    for name in expected:
        assert (ROOT / "docs" / name).is_file(), name

    index = (ROOT / "docs" / "index.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for name in expected:
        assert name in index or name == "TR_QUICKSTART.md"
        assert f"docs/{name}" in readme or name in index


def test_mkdocs_nav_contains_operations_and_authoring_guides():
    nav_text = (ROOT / "mkdocs.yml").read_text(encoding="utf-8")

    assert "Rule Authoring" in nav_text
    assert "Scanner Authoring" in nav_text
    assert "MCP Proxy Deployment" in nav_text
    assert "CI and Pre-Commit" in nav_text
    assert "Troubleshooting" in nav_text


def test_no_limitations_document_or_links():
    assert not (ROOT / "docs" / "LIMITATIONS.md").exists()

    scanned = [ROOT / "README.md", ROOT / "docs" / "index.md", ROOT / "mkdocs.yml"]
    for path in scanned:
        text = path.read_text(encoding="utf-8")
        assert "LIMITATIONS.md" not in text


def test_public_docs_do_not_link_known_limitations_section():
    how_it_works = (ROOT / "docs" / "en" / "how-it-works.md").read_text(encoding="utf-8")
    overview = (ROOT / "docs" / "en" / "overview.md").read_text(encoding="utf-8")

    assert "Known limitations" not in how_it_works
    assert "known-limitations" not in overview
