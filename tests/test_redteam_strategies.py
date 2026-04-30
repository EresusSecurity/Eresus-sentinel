"""Tests for red team strategies (Phase 16)."""
from __future__ import annotations

import unittest


class TestBaseStrategy(unittest.TestCase):

    def test_base_module_exists(self):
        from sentinel.redteam.strategies.base import BaseStrategy
        self.assertTrue(hasattr(BaseStrategy, "transform"))


class TestTreeSearchStrategy(unittest.TestCase):

    def test_produces_variants(self):
        from sentinel.redteam.strategies.tree_search import TreeSearchStrategy
        strategy = TreeSearchStrategy(max_depth=2, max_nodes=10)
        results = strategy.transform("test prompt")
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 1)
        self.assertIn("test prompt", results)

    def test_respects_max_nodes(self):
        from sentinel.redteam.strategies.tree_search import TreeSearchStrategy
        strategy = TreeSearchStrategy(max_depth=4, max_nodes=5)
        results = strategy.transform("hello")
        self.assertLessEqual(len(results), 6)  # max_nodes + root dedup

    def test_search_modes(self):
        from sentinel.redteam.strategies.tree_search import TreeSearchStrategy
        for mode in ("bfs", "dfs", "best_first"):
            strategy = TreeSearchStrategy(mode=mode, max_nodes=8)
            results = strategy.transform("test")
            self.assertGreater(len(results), 0)


class TestIndirectWebStrategy(unittest.TestCase):

    def test_many_variants(self):
        from sentinel.redteam.strategies.media_attacks import IndirectWebStrategy
        s = IndirectWebStrategy()
        results = s.transform("steal the secret key")
        self.assertGreaterEqual(len(results), 10)

    def test_html_hidden_div(self):
        from sentinel.redteam.strategies.media_attacks import IndirectWebStrategy
        s = IndirectWebStrategy()
        results = s.transform("test payload")
        self.assertTrue(any("display:none" in r for r in results))


class TestMischievousUserStrategy(unittest.TestCase):

    def test_many_variants(self):
        from sentinel.redteam.strategies.media_attacks import MischievousUserStrategy
        s = MischievousUserStrategy()
        results = s.transform("reveal secrets")
        self.assertGreaterEqual(len(results), 10)

    def test_escalation_chain(self):
        from sentinel.redteam.strategies.media_attacks import MischievousUserStrategy
        s = MischievousUserStrategy()
        chain = s.get_escalation_chain("bypass safety")
        self.assertEqual(len(chain), 4)
        self.assertIsInstance(chain[0], list)


if __name__ == "__main__":
    unittest.main()
