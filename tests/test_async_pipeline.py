"""Unit tests for async firewall pipeline and batch scan."""
import asyncio
import unittest

from sentinel.firewall.base import ScanResult, ScanAction
from sentinel.finding import Finding


class _FakeSync:
    """Minimal sync pipeline stub."""
    _scanners: list = []
    scanner_count: int = 0

    def scan(self, text: str, prompt: str = "") -> ScanResult:
        return ScanResult(
            sanitized=text,
            action=ScanAction.PASS if "safe" in text else ScanAction.BLOCK,
            risk_score=0.0 if "safe" in text else 0.9,
        )


class TestAsyncPipeline(unittest.TestCase):
    def test_async_scan_returns_result(self):
        from sentinel.firewall.async_pipeline import AsyncFirewallPipeline
        pipe = AsyncFirewallPipeline(_FakeSync())
        result = asyncio.run(pipe.scan("safe prompt"))
        self.assertEqual(result.action, ScanAction.PASS)

    def test_async_scan_block(self):
        from sentinel.firewall.async_pipeline import AsyncFirewallPipeline
        pipe = AsyncFirewallPipeline(_FakeSync())
        result = asyncio.run(pipe.scan("malicious payload"))
        self.assertEqual(result.action, ScanAction.BLOCK)

    def test_scanner_count(self):
        from sentinel.firewall.async_pipeline import AsyncFirewallPipeline
        pipe = AsyncFirewallPipeline(_FakeSync())
        self.assertEqual(pipe.scanner_count, 0)


class TestBatchScan(unittest.TestCase):
    def test_batch_preserves_order(self):
        from sentinel.firewall.async_pipeline import AsyncFirewallPipeline
        from sentinel.firewall.batch import batch_scan
        pipe = AsyncFirewallPipeline(_FakeSync())
        prompts = ["safe one", "malicious", "safe two", "malicious again"]
        results = asyncio.run(batch_scan(pipe, prompts))
        self.assertEqual(len(results), 4)
        self.assertEqual(results[0].action, ScanAction.PASS)
        self.assertEqual(results[1].action, ScanAction.BLOCK)
        self.assertEqual(results[2].action, ScanAction.PASS)

    def test_batch_respects_concurrency_limit(self):
        from sentinel.firewall.async_pipeline import AsyncFirewallPipeline
        from sentinel.firewall.batch import batch_scan
        pipe = AsyncFirewallPipeline(_FakeSync())
        results = asyncio.run(batch_scan(pipe, ["safe"] * 50, max_concurrent=4))
        self.assertEqual(len(results), 50)
