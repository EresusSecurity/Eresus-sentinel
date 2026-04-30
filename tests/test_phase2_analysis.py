"""Tests for Phase 2: analysis enrichment, cache, license checker, progress reporter."""

import os
import tempfile
import unittest

from sentinel.analysis.anomaly_detector import AnomalyDetector
from sentinel.analysis.framework_patterns import (
    ALL_PROFILES,
    PYTORCH,
    SKLEARN,
    detect_framework,
    is_safe_module,
)
from sentinel.analysis.unified_context import AnalysisContext, UnifiedAnalyzer
from sentinel.cache.cache_manager import CacheManager, content_hash, file_cache_key
from sentinel.cache.scan_results_cache import ScanResultsCache
from sentinel.config.explanations import all_rule_ids, explain, explain_finding
from sentinel.detectors.suspicious_symbols import SuspiciousSymbolDetector
from sentinel.finding import Finding, Severity
from sentinel.integrations.license_checker import (
    LicenseRisk,
    check_license,
    lookup,
    normalize_license,
)
from sentinel.reporters.progress import Phase, ProgressReporter


class TestAnomalyDetector(unittest.TestCase):
    def setUp(self):
        self.det = AnomalyDetector()

    def test_clean_data(self):
        data = b"\x80\x05\x95\x00\x00\x00\x00" + b"\x8c" * 100 + b"\x2e"
        findings = self.det.analyze(data, "clean.pkl")
        # Should have very few or no findings for normal-looking data
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        self.assertEqual(len(critical), 0)

    def test_high_exec_ratio(self):
        # Lots of GLOBAL (0x63) and REDUCE (0x52)
        data = b"\x63" * 50 + b"\x52" * 50 + b"\x00" * 100
        findings = self.det.analyze(data, "malicious.pkl")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("ANOMALY-001", rule_ids)

    def test_high_entropy(self):
        import os as _os
        data = _os.urandom(2000)
        findings = self.det.analyze(data, "random.pkl")
        rule_ids = [f.rule_id for f in findings]
        # Random data triggers chi-squared (ANOMALY-002) and/or entropy (ANOMALY-003)
        self.assertTrue(
            "ANOMALY-002" in rule_ids or "ANOMALY-003" in rule_ids,
            f"Expected ANOMALY-002 or ANOMALY-003, got {rule_ids}",
        )


class TestFrameworkPatterns(unittest.TestCase):
    def test_profiles_exist(self):
        self.assertIn("pytorch", ALL_PROFILES)
        self.assertIn("sklearn", ALL_PROFILES)

    def test_detect_pytorch(self):
        modules = {"torch._utils", "torch.nn.modules", "collections"}
        self.assertEqual(detect_framework(modules), "pytorch")

    def test_detect_sklearn(self):
        modules = {"sklearn.ensemble", "sklearn.pipeline", "numpy"}
        self.assertEqual(detect_framework(modules), "sklearn")

    def test_detect_none(self):
        modules = {"my_custom_module"}
        self.assertIsNone(detect_framework(modules))

    def test_is_safe_module(self):
        self.assertTrue(is_safe_module("torch._utils", "pytorch"))
        self.assertTrue(is_safe_module("numpy"))
        self.assertFalse(is_safe_module("os.system"))


class TestSuspiciousSymbolDetector(unittest.TestCase):
    def setUp(self):
        self.det = SuspiciousSymbolDetector()

    def test_clean_pickle(self):
        data = b"\x80\x05\x8ctorch._utils\n_rebuild_tensor\n"
        findings = self.det.scan_bytes(data, "clean.pkl")
        blocked = [f for f in findings if f.rule_id == "SYMBOL-001"]
        self.assertEqual(len(blocked), 0)

    def test_os_system(self):
        data = b"cos\nsystem\n"
        findings = self.det.scan_bytes(data, "malicious.pkl")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("SYMBOL-001", rule_ids)

    def test_subprocess(self):
        data = b"csubprocess\nPopen\n"
        findings = self.det.scan_bytes(data, "malicious.pkl")
        blocked = [f for f in findings if f.severity == Severity.CRITICAL]
        self.assertGreater(len(blocked), 0)


class TestCacheManager(unittest.TestCase):
    def test_put_get(self):
        cache = CacheManager(max_entries=100)
        cache.put("k1", {"data": 42})
        self.assertEqual(cache.get("k1"), {"data": 42})

    def test_miss(self):
        cache = CacheManager()
        self.assertIsNone(cache.get("nonexistent"))

    def test_eviction(self):
        cache = CacheManager(max_entries=3)
        cache.put("a", 1)
        cache.put("b", 2)
        cache.put("c", 3)
        cache.put("d", 4)  # should evict "a"
        self.assertIsNone(cache.get("a"))
        self.assertEqual(cache.get("d"), 4)

    def test_invalidate(self):
        cache = CacheManager()
        cache.put("k", "v")
        self.assertTrue(cache.invalidate("k"))
        self.assertIsNone(cache.get("k"))

    def test_clear(self):
        cache = CacheManager()
        cache.put("a", 1)
        cache.put("b", 2)
        self.assertEqual(cache.clear(), 2)
        self.assertEqual(cache.size, 0)

    def test_stats(self):
        cache = CacheManager()
        cache.put("k", "v")
        cache.get("k")
        cache.get("miss")
        stats = cache.stats
        self.assertEqual(stats["hits"], 1)
        self.assertEqual(stats["misses"], 1)

    def test_content_hash(self):
        h1 = content_hash(b"hello")
        h2 = content_hash(b"hello")
        h3 = content_hash(b"world")
        self.assertEqual(h1, h2)
        self.assertNotEqual(h1, h3)

    def test_persist_and_load(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            cache = CacheManager(persist_path=path)
            cache.put("k1", "v1")
            cache.persist()

            cache2 = CacheManager(persist_path=path)
            self.assertEqual(cache2.get("k1"), "v1")
        finally:
            os.unlink(path)


class TestScanResultsCache(unittest.TestCase):
    def test_store_and_get(self):
        cache = ScanResultsCache()
        findings = [Finding.artifact(
            rule_id="TEST-001", title="test", description="test",
            severity=Severity.LOW, target="/tmp/test.pkl",
        )]
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(b"test data")
            path = f.name
        try:
            cache.store_findings(path, findings)
            result = cache.get_findings(path)
            self.assertIsNotNone(result)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["rule_id"], "TEST-001")
        finally:
            os.unlink(path)

    def test_batch_check(self):
        cache = ScanResultsCache()
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(b"data1")
            p1 = f.name
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(b"data2")
            p2 = f.name
        try:
            cache.store_findings(p1, [])
            cached, uncached = cache.batch_check([p1, p2])
            self.assertIn(p1, cached)
            self.assertIn(p2, uncached)
        finally:
            os.unlink(p1)
            os.unlink(p2)


class TestLicenseChecker(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(normalize_license("Apache 2.0"), "apache-2.0")
        self.assertEqual(normalize_license("MIT"), "mit")

    def test_lookup(self):
        info = lookup("apache-2.0")
        self.assertIsNotNone(info)
        self.assertEqual(info.risk, LicenseRisk.PERMISSIVE)

    def test_missing_license(self):
        findings = check_license(None, target="model.bin")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "LICENSE-001")

    def test_permissive_ok(self):
        findings = check_license("MIT", target="model.bin")
        self.assertEqual(len(findings), 0)

    def test_noncommercial(self):
        findings = check_license("cc-by-nc-4.0", require_commercial=True, target="model.bin")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("LICENSE-003", rule_ids)

    def test_copyleft(self):
        findings = check_license("gpl-3.0", block_copyleft=True, target="model.bin")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("LICENSE-004", rule_ids)


class TestExplanations(unittest.TestCase):
    def test_known_rule(self):
        info = explain("ANOMALY-001")
        self.assertIsNotNone(info)
        self.assertIn("desc", info)

    def test_unknown_rule(self):
        self.assertIsNone(explain("NONEXISTENT-999"))

    def test_all_rule_ids(self):
        ids = all_rule_ids()
        self.assertGreater(len(ids), 10)


class TestProgressReporter(unittest.TestCase):
    def test_basic_lifecycle(self):
        events = []
        reporter = ProgressReporter(callback=events.append, quiet=True)
        reporter.start(total_files=10)
        reporter.discovery(10)
        reporter.scanning(1, 10, "file1.pkl")
        reporter.add_findings(3)
        reporter.scanning(2, 10, "file2.pkl")
        reporter.analysis("Running anomaly detection")
        reporter.done()

        self.assertEqual(len(events), 6)
        self.assertEqual(events[0].phase, Phase.INIT)
        self.assertEqual(events[-1].phase, Phase.DONE)
        self.assertEqual(events[-1].findings_so_far, 3)

    def test_log_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            path = f.name
        try:
            reporter = ProgressReporter(log_file=path, quiet=True)
            reporter.start(5)
            reporter.done()
            with open(path) as f:
                lines = f.readlines()
            self.assertEqual(len(lines), 2)
        finally:
            os.unlink(path)


class TestUnifiedAnalyzer(unittest.TestCase):
    def test_analyze_nonexistent(self):
        analyzer = UnifiedAnalyzer()
        ctx = analyzer.analyze("/nonexistent/path")
        self.assertEqual(ctx.total_findings, 0)

    def test_analysis_context_risk_score(self):
        ctx = AnalysisContext(target="/test")
        ctx.add_findings([
            Finding.artifact(rule_id="T-1", title="t", description="t",
                             severity=Severity.CRITICAL, target="/test"),
        ])
        score = ctx.compute_risk_score()
        self.assertGreater(score, 0.0)

    def test_summary(self):
        ctx = AnalysisContext(target="/test")
        s = ctx.summary()
        self.assertIn("target", s)
        self.assertIn("risk_score", s)


if __name__ == "__main__":
    unittest.main()
