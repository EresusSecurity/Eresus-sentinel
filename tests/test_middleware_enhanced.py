"""Tests for SentinelAgentMiddleware and SentinelToolMiddleware."""
from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch


class TestSentinelAgentMiddleware(unittest.TestCase):

    def _make_mw(self, mode="monitor"):
        with patch("sentinel.middleware.SentinelMiddleware") as MockMW:
            from sentinel.middleware import SentinelAgentMiddleware
            from sentinel.firewall.base import ScanAction, ScanResult

            mock_instance = MockMW.return_value
            mock_instance.guard_input.return_value = ScanResult(
                action=ScanAction.PASS, findings=[], risk_score=0.1, sanitized="safe"
            )
            mock_instance.guard_output.return_value = ScanResult(
                action=ScanAction.PASS, findings=[], risk_score=0.1, sanitized="safe output"
            )
            mw = SentinelAgentMiddleware(mode=mode)
            mw._mw = mock_instance
            return mw, mock_instance

    def test_mode_validation(self):
        from sentinel.middleware import SentinelAgentMiddleware
        with self.assertRaises(ValueError):
            SentinelAgentMiddleware(mode="invalid")

    def test_off_mode_passthrough(self):
        mw, mock = self._make_mw(mode="off")
        result = mw.before_model("test prompt")
        self.assertEqual(result, "test prompt")
        mock.guard_input.assert_not_called()

    def test_monitor_mode_no_raise(self):
        from sentinel.firewall.base import ScanAction, ScanResult
        mw, mock = self._make_mw(mode="monitor")
        mock.guard_input.return_value = ScanResult(
            action=ScanAction.BLOCK, findings=["f1"], risk_score=0.9, sanitized=""
        )
        result = mw.before_model("bad prompt")
        self.assertEqual(result, "bad prompt")

    def test_enforce_mode_raises(self):
        from sentinel.firewall.base import ScanAction, ScanResult
        mw, mock = self._make_mw(mode="enforce")
        mock.guard_input.return_value = ScanResult(
            action=ScanAction.BLOCK, findings=["f1"], risk_score=0.9, sanitized=""
        )
        with self.assertRaises(ValueError):
            mw.before_model("bad prompt")

    def test_history_tracking(self):
        mw, _ = self._make_mw(mode="monitor")
        mw.before_model("test")
        mw.after_model("output")
        self.assertEqual(len(mw.history), 2)
        self.assertEqual(mw.history[0]["phase"], "before_model")
        self.assertEqual(mw.history[1]["phase"], "after_model")
        mw.clear_history()
        self.assertEqual(len(mw.history), 0)


class TestSentinelToolMiddleware(unittest.TestCase):

    def _make_mw(self, mode="monitor", blocked_tools=None):
        with patch("sentinel.middleware.SentinelMiddleware") as MockMW:
            from sentinel.middleware import SentinelToolMiddleware
            from sentinel.firewall.base import ScanAction, ScanResult

            mock_instance = MockMW.return_value
            mock_instance.guard_input.return_value = ScanResult(
                action=ScanAction.PASS, findings=[], risk_score=0.0, sanitized="safe"
            )
            mock_instance.guard_output.return_value = ScanResult(
                action=ScanAction.PASS, findings=[], risk_score=0.0, sanitized="safe result"
            )
            mw = SentinelToolMiddleware(mode=mode, blocked_tools=blocked_tools)
            mw._mw = mock_instance
            return mw, mock_instance

    def test_off_mode_passthrough(self):
        mw, mock = self._make_mw(mode="off")
        args = {"path": "/tmp/test"}
        result = mw.wrap_tool_call("read_file", args)
        self.assertEqual(result, args)
        mock.guard_input.assert_not_called()

    def test_blocked_tool_enforce(self):
        mw, _ = self._make_mw(mode="enforce", blocked_tools=["rm"])
        with self.assertRaises(ValueError):
            mw.wrap_tool_call("rm", {"target": "/"})

    def test_blocked_tool_monitor(self):
        mw, _ = self._make_mw(mode="monitor", blocked_tools=["rm"])
        result = mw.wrap_tool_call("rm", {"target": "/"})
        self.assertEqual(result, {"target": "/"})

    def test_tool_result_inspection(self):
        mw, _ = self._make_mw(mode="monitor")
        result = mw.wrap_tool_result("read_file", "file contents here")
        self.assertEqual(result, "safe result")

    def test_history_includes_tool_name(self):
        mw, _ = self._make_mw(mode="monitor")
        mw.wrap_tool_call("read_file", {"p": "x"})
        self.assertEqual(len(mw.history), 1)
        self.assertEqual(mw.history[0]["tool"], "read_file")


if __name__ == "__main__":
    unittest.main()
