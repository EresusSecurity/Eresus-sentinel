"""Tests for enhanced skill scanner modules (Phase 6)."""
from __future__ import annotations

import unittest


class TestBytecodeAnalyzer(unittest.TestCase):

    def test_clean_source(self):
        from sentinel.agent.bytecode_analyzer import BytecodeAnalyzer
        ba = BytecodeAnalyzer()
        result = ba.analyze_source("x = 1 + 2\nprint(x)")
        self.assertTrue(result.parsed)
        self.assertEqual(len(result.issues), 0)

    def test_dangerous_import(self):
        from sentinel.agent.bytecode_analyzer import BytecodeAnalyzer
        ba = BytecodeAnalyzer()
        result = ba.analyze_source("import subprocess\nsubprocess.call(['ls'])")
        self.assertTrue(result.parsed)
        self.assertGreater(len(result.dangerous_imports), 0)
        self.assertIn("subprocess", result.dangerous_imports)

    def test_syntax_error(self):
        from sentinel.agent.bytecode_analyzer import BytecodeAnalyzer
        ba = BytecodeAnalyzer()
        result = ba.analyze_source("def broken(:\n  pass")
        self.assertFalse(result.parsed)
        self.assertIsNotNone(result.error)


class TestBashTaintTracker(unittest.TestCase):

    def test_clean_script(self):
        from sentinel.agent.bash_taint_tracker import BashTaintTracker
        bt = BashTaintTracker()
        result = bt.analyze_script("#!/bin/bash\necho 'hello world'\n")
        self.assertEqual(len(result.issues), 0)

    def test_tainted_eval(self):
        from sentinel.agent.bash_taint_tracker import BashTaintTracker
        bt = BashTaintTracker()
        result = bt.analyze_script("#!/bin/bash\nread -r input\neval $input\n")
        self.assertGreater(len(result.issues), 0)


class TestAnalyzabilityScorer(unittest.TestCase):

    def test_clean_code(self):
        from sentinel.agent.analyzability import AnalyzabilityScorer
        scorer = AnalyzabilityScorer()
        result = scorer.score_source("def hello():\n    return 'world'\n")
        self.assertEqual(result.verdict, "clean")
        self.assertGreater(result.analyzability_score, 0.8)

    def test_obfuscated_code(self):
        from sentinel.agent.analyzability import AnalyzabilityScorer
        scorer = AnalyzabilityScorer()
        result = scorer.score_source(
            "import base64\nexec(base64.b64decode('cHJpbnQoImhlbGxvIik='))\n"
        )
        self.assertGreaterEqual(result.obfuscation_score, 0.2)


class TestScanPolicy(unittest.TestCase):

    def test_presets(self):
        from sentinel.agent.scan_policy import ScanPolicy
        for preset in ("default", "strict", "permissive"):
            p = ScanPolicy.from_preset(preset)
            self.assertIsNotNone(p)

    def test_strict_blocks_medium(self):
        from sentinel.agent.scan_policy import ScanPolicy, PolicyAction
        p = ScanPolicy.strict()
        self.assertEqual(p.action_for_severity("MEDIUM"), PolicyAction.BLOCK)

    def test_suppression(self):
        from sentinel.agent.scan_policy import ScanPolicy
        p = ScanPolicy(suppressed_rule_ids=["SKILL-001"])
        self.assertTrue(p.is_suppressed("SKILL-001"))
        self.assertFalse(p.is_suppressed("SKILL-002"))


class TestRulePacks(unittest.TestCase):

    def test_core_pack_exists(self):
        from sentinel.agent.rule_packs import CoreRulePack
        self.assertEqual(CoreRulePack.name, "core")
        self.assertGreater(len(CoreRulePack.rules), 5)

    def test_core_pack_detects_eval(self):
        from sentinel.agent.rule_packs import CoreRulePack
        results = CoreRulePack.scan("x = eval(user_input)")
        rule_ids = {r.rule.id for r in results}
        self.assertIn("SKILL-001", rule_ids)


if __name__ == "__main__":
    unittest.main()
