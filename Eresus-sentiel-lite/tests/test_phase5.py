"""Tests for Dependency Auditor, Permission Analyzer, and YAML rule loading."""

import json
import os
import tempfile
from pathlib import Path

import pytest

from sentinel.supply_chain.dependency import DependencyAuditor, _levenshtein
from sentinel.agent.permissions import PermissionAnalyzer
from sentinel.rules import load_mcp_rules, load_supply_chain_rules
from sentinel.finding import Severity


# ======================== LEVENSHTEIN DISTANCE TESTS ========================

class TestLevenshtein:
    def test_identical(self):
        assert _levenshtein("torch", "torch") == 0

    def test_distance_one(self):
        assert _levenshtein("torch", "torcg") == 1  # substitution

    def test_distance_two(self):
        assert _levenshtein("numpy", "numyp") == 2  # transposition

    def test_empty_string(self):
        assert _levenshtein("", "abc") == 3
        assert _levenshtein("abc", "") == 3


# ======================== DEPENDENCY AUDITOR TESTS ========================

class TestDependencyAuditor:
    def setup_method(self):
        self.auditor = DependencyAuditor()

    def test_parse_requirements_txt(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("""
# AI/ML deps
transformers==4.30.0
torch>=2.0.0
numpy
safetensors==0.4.1
# Custom
my-custom-lib
""")
        findings = self.auditor.audit_file(str(req))
        # Should find: transformers (known vuln), numpy (unpinned), my-custom-lib (unpinned)
        assert len(findings) > 0

    def test_known_vulnerable_package(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("transformers==4.30.0\n")
        findings = self.auditor.audit_file(str(req))
        vuln = [f for f in findings if f.rule_id == "DEP-010"]
        assert len(vuln) > 0
        assert "transformers" in vuln[0].evidence

    def test_unpinned_dependency(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("numpy\n")
        findings = self.auditor.audit_file(str(req))
        unpinned = [f for f in findings if f.rule_id == "DEP-020"]
        assert len(unpinned) > 0

    def test_wildcard_dependency(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("torch==*\n")
        # The spec parser will extract "*" as version
        findings = self.auditor.audit_file(str(req))
        # Check has either wildcard or known vuln findings
        assert len(findings) > 0

    def test_typosquatting_detection(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("transforers==4.35.0\n")  # Missing 'm' - typosquat
        findings = self.auditor.audit_file(str(req))
        typo = [f for f in findings if f.rule_id == "DEP-030"]
        assert len(typo) > 0
        assert "transformers" in typo[0].evidence

    def test_safe_dependencies(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("pyyaml>=6.0\n")
        findings = self.auditor.audit_file(str(req))
        # Should NOT trigger known vuln or typosquat
        vuln = [f for f in findings if f.rule_id in ("DEP-010", "DEP-030")]
        assert len(vuln) == 0

    def test_package_json_parsing(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "dependencies": {
                "openai": "^4.0.0",
                "express": "latest"
            }
        }))
        findings = self.auditor.audit_file(str(pkg))
        assert len(findings) > 0  # "latest" triggers wildcard

    def test_cargo_toml_parsing(self, tmp_path):
        cargo = tmp_path / "Cargo.toml"
        cargo.write_text("""
[dependencies]
serde = "1.0"
tokio = { version = "1.35", features = ["full"] }
""")
        findings = self.auditor.audit_file(str(cargo))
        # Should parse without errors
        assert isinstance(findings, list)

    def test_audit_directory(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("transformers==4.30.0\nnumpy\n")
        findings = self.auditor.audit_directory(str(tmp_path))
        assert len(findings) > 0

    def test_empty_directory(self, tmp_path):
        findings = self.auditor.audit_directory(str(tmp_path))
        no_deps = [f for f in findings if f.rule_id == "DEP-001"]
        assert len(no_deps) == 1  # "No dependency files found"


# ======================== PERMISSION ANALYZER TESTS ========================

class TestPermissionAnalyzer:
    def setup_method(self):
        self.analyzer = PermissionAnalyzer()

    def _basic_config(self):
        return {
            "agents": [
                {
                    "name": "admin_bot",
                    "permissions": {
                        "allowed": [
                            "file:write", "file:delete", "file:read",
                            "command:exec", "command:shell",
                            "database:write", "database:drop",
                            "credential:read", "user:elevate",
                        ],
                        "denied": [],
                        "scopes": [],
                        "requires_approval": ["user:elevate"],
                    }
                },
                {
                    "name": "reader_bot",
                    "permissions": {
                        "allowed": ["file:read", "database:read"],
                        "denied": ["command:exec", "file:write"],
                        "scopes": ["internal"],
                    }
                },
                {
                    "name": "wildcard_bot",
                    "permissions": {
                        "allowed": ["*"],
                        "denied": [],
                    }
                },
                {
                    "name": "conflicted_bot",
                    "permissions": {
                        "allowed": ["file:write", "file:read"],
                        "denied": ["file:write"],
                        "scopes": ["internal"],
                    }
                },
            ]
        }

    def test_excessive_permissions(self):
        self.analyzer.load_config(self._basic_config())
        findings = self.analyzer.analyze()
        excessive = [f for f in findings if f.rule_id == "PERM-010"]
        assert len(excessive) > 0  # admin_bot has 7+ critical perms

    def test_critical_without_approval(self):
        self.analyzer.load_config(self._basic_config())
        findings = self.analyzer.analyze()
        no_approval = [f for f in findings if f.rule_id == "PERM-020"]
        assert len(no_approval) > 0  # admin_bot: command:exec, file:write, etc. without approval

    def test_permission_conflict(self):
        self.analyzer.load_config(self._basic_config())
        findings = self.analyzer.analyze()
        conflicts = [f for f in findings if f.rule_id == "PERM-030"]
        assert len(conflicts) > 0  # conflicted_bot: file:write in both

    def test_no_deny_list(self):
        self.analyzer.load_config(self._basic_config())
        findings = self.analyzer.analyze()
        no_deny = [f for f in findings if f.rule_id == "PERM-040"]
        assert len(no_deny) > 0  # admin_bot + wildcard_bot have empty deny

    def test_no_scope(self):
        self.analyzer.load_config(self._basic_config())
        findings = self.analyzer.analyze()
        no_scope = [f for f in findings if f.rule_id == "PERM-050"]
        assert len(no_scope) > 0  # admin_bot has critical perms but no scope

    def test_wildcard_permission(self):
        self.analyzer.load_config(self._basic_config())
        findings = self.analyzer.analyze()
        wildcard = [f for f in findings if f.rule_id == "PERM-060"]
        assert len(wildcard) > 0  # wildcard_bot has "*"

    def test_safe_config(self):
        config = {
            "agents": [{
                "name": "safe_bot",
                "permissions": {
                    "allowed": ["file:read"],
                    "denied": ["command:exec"],
                    "scopes": ["internal"],
                }
            }]
        }
        self.analyzer.load_config(config)
        findings = self.analyzer.analyze()
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 0

    def test_inheritance(self):
        config = {
            "agents": [
                {
                    "name": "base",
                    "permissions": {
                        "allowed": ["file:read", "file:write"],
                        "denied": [],
                    }
                },
                {
                    "name": "child",
                    "permissions": {
                        "allowed": ["database:read"],
                        "denied": [],
                        "inherits_from": "base",
                    }
                },
            ]
        }
        self.analyzer.load_config(config)
        findings = self.analyzer.analyze()
        # child inherits file:write which is critical
        assert len(findings) > 0


# ======================== YAML RULE LOADING TESTS ========================

class TestMCPRulesLoad:
    def test_load_mcp_rules(self):
        rules = load_mcp_rules()
        assert "dangerous_capabilities" in rules
        assert "description_injection_patterns" in rules
        assert "path_parameter_keywords" in rules
        assert "auth_field_names" in rules

    def test_dangerous_capabilities_content(self):
        rules = load_mcp_rules()
        caps = rules["dangerous_capabilities"]
        assert "command_exec" in caps
        assert "file_write" in caps
        assert "credential_access" in caps
        assert len(caps) >= 10  # We have 13 categories

    def test_description_patterns_compiled(self):
        rules = load_mcp_rules()
        patterns = rules["description_injection_patterns"]
        assert len(patterns) >= 10
        # Each should have compiled regex
        for p in patterns:
            assert hasattr(p["pattern"], "search")

    def test_path_keywords_populated(self):
        rules = load_mcp_rules()
        keywords = rules["path_parameter_keywords"]
        assert len(keywords) >= 15
        assert "path" in keywords
        assert "filepath" in keywords

    def test_auth_fields_populated(self):
        rules = load_mcp_rules()
        fields = rules["auth_field_names"]
        assert len(fields) >= 10
        assert "requiresConfirmation" in fields


class TestSupplyChainRulesLoad:
    def test_load_supply_chain_rules(self):
        rules = load_supply_chain_rules()
        assert "dangerous_extensions" in rules
        assert "safe_extensions" in rules

    def test_dangerous_extensions_content(self):
        rules = load_supply_chain_rules()
        exts = rules["dangerous_extensions"]
        assert ".pkl" in exts
        assert ".exe" in exts
        assert exts[".pkl"]["severity"] == "CRITICAL"

    def test_safe_extensions_content(self):
        rules = load_supply_chain_rules()
        safe = rules["safe_extensions"]
        assert ".safetensors" in safe
        assert ".gguf" in safe

    def test_known_vulnerable_packages(self):
        rules = load_supply_chain_rules()
        vuln = rules.get("known_vulnerable_packages", [])
        assert len(vuln) >= 10
        names = [v["name"] for v in vuln]
        assert "transformers" in names
        assert "langchain" in names
