# Good First Issues

These are intentionally small contribution ideas that exercise the normal
development loop without requiring deep scanner internals.

| Area | Issue Idea | Suggested Label |
|---|---|---|
| Docs | Add a sanitized false-positive example to `docs/FALSE_POSITIVES.md` | `good-first-issue`, `docs` |
| Rules | Add a benign fixture for a noisy prompt firewall phrase | `good-first-issue`, `scanner` |
| CLI | Add a JSON smoke test for a command with `-f json` | `good-first-issue`, `phase-roadmap` |
| AIBOM | Add a framework import signature and matching fixture | `good-first-issue`, `scanner` |
| Skill security | Add a clean SKILL.md frontmatter fixture | `good-first-issue`, `scanner` |
| CI | Add a package smoke assertion to `tests/test_phase15_ci_release.py` | `good-first-issue`, `ci` |

Before opening a PR, run the focused test for the touched area and include the
command in the PR body.
