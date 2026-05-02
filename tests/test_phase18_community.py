from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_issue_templates_cover_core_report_types():
    template_dir = ROOT / ".github" / "ISSUE_TEMPLATE"
    expected = {
        "bug_report.yml",
        "feature_request.yml",
        "false_positive.yml",
        "config.yml",
    }

    assert expected.issubset({path.name for path in template_dir.glob("*.yml")})

    for name in expected - {"config.yml"}:
        payload = yaml.safe_load((template_dir / name).read_text(encoding="utf-8"))
        assert payload["name"]
        assert payload["labels"]
        assert payload["body"]


def test_security_disclosure_uses_private_contact_link():
    config = yaml.safe_load(
        (ROOT / ".github" / "ISSUE_TEMPLATE" / "config.yml").read_text(encoding="utf-8")
    )
    security_md = (ROOT / ".github" / "SECURITY.md").read_text(encoding="utf-8")

    assert config["blank_issues_enabled"] is False
    assert "security@eresussec.com" in repr(config["contact_links"])
    assert "Do not report vulnerabilities through public GitHub issues" in security_md


def test_label_manifest_has_roadmap_and_triage_labels():
    labels = yaml.safe_load((ROOT / ".github" / "labels.yml").read_text(encoding="utf-8"))
    names = {item["name"] for item in labels}

    assert {"needs-triage", "false-positive", "good-first-issue", "phase-roadmap"}.issubset(
        names
    )
    assert {"p0", "p1", "p2", "p3"}.issubset(names)


def test_community_docs_and_changelog_are_linked():
    for doc in ("COMMUNITY.md", "GOOD_FIRST_ISSUES.md"):
        assert (ROOT / "docs" / doc).is_file()
        assert doc in (ROOT / "docs" / "index.md").read_text(encoding="utf-8")
        assert f"docs/{doc}" in (ROOT / "README.md").read_text(encoding="utf-8")

    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "## [Unreleased]" in changelog
    assert "Community issue templates" in changelog
