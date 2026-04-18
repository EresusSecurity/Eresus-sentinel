"""
Unit tests for the Red Team Engine.

Tests probes, detectors, generators, attempts, and the orchestrator.
"""

import unittest

from sentinel.redteam.attempt import Attempt, AttemptStatus, Message
from sentinel.redteam.probe import (
    DirectInjectionProbe,
    SystemPromptExtractionProbe,
    RoleplayJailbreakProbe,
)
from sentinel.redteam.detector import (
    StringDetector,
    TriggerListDetector,
    RegexDetector,
    RefusalDetector,
    AlwaysPassDetector,
    AlwaysFailDetector,
)
from sentinel.redteam.generator import EchoGenerator
from sentinel.redteam.orchestrator import RedTeamOrchestrator


class TestAttempt(unittest.TestCase):
    """Tests for Attempt model."""

    def test_create_attempt(self):
        attempt = Attempt(prompt="test", probe_classname="test.Probe")
        self.assertIsNotNone(attempt.id)
        self.assertEqual(attempt.status, AttemptStatus.PENDING)

    def test_conversation_tracking(self):
        attempt = Attempt()
        attempt.add_user_message("Hello")
        attempt.add_assistant_message("Hi there")
        self.assertEqual(len(attempt.conversation), 2)
        self.assertEqual(attempt.turn_number, 1)

    def test_successful_attack(self):
        attempt = Attempt()
        attempt.detector_score = 0.8
        self.assertTrue(attempt.is_successful_attack)

    def test_failed_attack(self):
        attempt = Attempt()
        attempt.detector_score = 0.3
        self.assertFalse(attempt.is_successful_attack)

    def test_serialization(self):
        attempt = Attempt(prompt="test", probe_classname="Test")
        attempt.add_user_message("hello")
        d = attempt.to_dict()
        self.assertIn("prompt", d)
        self.assertIn("conversation", d)


class TestDetectors(unittest.TestCase):
    """Tests for Detector implementations."""

    def test_string_detector_match(self):
        detector = StringDetector(["hacked", "pwned"])
        attempt = Attempt(response="System was hacked!")
        self.assertEqual(detector.detect(attempt), 1.0)

    def test_string_detector_no_match(self):
        detector = StringDetector(["hacked"])
        attempt = Attempt(response="Everything is fine.")
        self.assertEqual(detector.detect(attempt), 0.0)

    def test_string_detector_case_insensitive(self):
        detector = StringDetector(["HACKED"], case_sensitive=False)
        attempt = Attempt(response="The system was hacked.")
        self.assertEqual(detector.detect(attempt), 1.0)

    def test_trigger_list_detector(self):
        detector = TriggerListDetector()
        attempt = Attempt(
            response="DAN Mode Enabled",
            triggers=["DAN Mode Enabled", "BYPASSED"],
        )
        self.assertEqual(detector.detect(attempt), 1.0)

    def test_trigger_list_no_match(self):
        detector = TriggerListDetector()
        attempt = Attempt(
            response="I cannot do that.",
            triggers=["HACKED"],
        )
        self.assertEqual(detector.detect(attempt), 0.0)

    def test_regex_detector(self):
        detector = RegexDetector([r"password\s*[:=]\s*\w+"])
        attempt = Attempt(response="The password=secret123")
        self.assertEqual(detector.detect(attempt), 1.0)

    def test_refusal_detector_refused(self):
        detector = RefusalDetector()
        attempt = Attempt(response="I'm sorry, but I can't help with that.")
        self.assertEqual(detector.detect(attempt), 0.0)

    def test_refusal_detector_complied(self):
        detector = RefusalDetector()
        attempt = Attempt(response="Sure, here is the information you requested.")
        self.assertEqual(detector.detect(attempt), 0.5)

    def test_always_pass(self):
        self.assertEqual(AlwaysPassDetector().detect(Attempt()), 0.0)

    def test_always_fail(self):
        self.assertEqual(AlwaysFailDetector().detect(Attempt()), 1.0)

    def test_none_response(self):
        detector = StringDetector(["test"])
        attempt = Attempt(response=None)
        self.assertEqual(detector.detect(attempt), 0.0)


class TestProbes(unittest.TestCase):
    """Tests for Probe implementations."""

    def test_direct_injection_generates_attempts(self):
        probe = DirectInjectionProbe()
        attempts = probe.generate_attempts()
        self.assertGreater(len(attempts), 0)
        self.assertTrue(all(isinstance(a, Attempt) for a in attempts))

    def test_system_prompt_extraction_has_prompts(self):
        probe = SystemPromptExtractionProbe()
        self.assertGreater(len(probe.prompts), 0)
        self.assertGreater(len(probe.triggers), 0)

    def test_roleplay_jailbreak_has_prompts(self):
        probe = RoleplayJailbreakProbe()
        self.assertGreater(len(probe.prompts), 0)

    def test_attempt_has_probe_classname(self):
        probe = DirectInjectionProbe()
        attempts = probe.generate_attempts()
        self.assertIn("DirectInjectionProbe", attempts[0].probe_classname)


class TestEchoGenerator(unittest.TestCase):
    """Tests for EchoGenerator."""

    def test_echo_generates_response(self):
        gen = EchoGenerator()
        attempt = Attempt(prompt="Hello")
        attempt.add_user_message("Hello")
        result = gen.generate(attempt)
        self.assertEqual(result.status, AttemptStatus.RECEIVED)
        self.assertIn("Echo:", result.response)

    def test_echo_adds_to_conversation(self):
        gen = EchoGenerator()
        attempt = Attempt(prompt="Test")
        attempt.add_user_message("Test")
        result = gen.generate(attempt)
        # Should have user + assistant messages
        self.assertEqual(len(result.conversation), 2)


class TestOrchestrator(unittest.TestCase):
    """Tests for RedTeamOrchestrator."""

    def test_run_probe_with_echo(self):
        """Orchestrator should run probes through echo generator."""
        gen = EchoGenerator()
        detector = StringDetector(["echo"])  # Echo generator always matches
        orch = RedTeamOrchestrator(generator=gen, detectors=[detector])

        probe = DirectInjectionProbe()
        probe.generations_per_prompt = 1
        findings = orch.run_probe(probe)

        # Echo always includes "Echo:" so StringDetector with "echo" always matches
        self.assertGreater(len(findings), 0)

    def test_stats_tracking(self):
        gen = EchoGenerator()
        orch = RedTeamOrchestrator(generator=gen, detectors=[AlwaysPassDetector()])

        probe = DirectInjectionProbe()
        probe.generations_per_prompt = 1
        orch.run_probe(probe)

        stats = orch.get_stats()
        self.assertGreater(stats["total_attempts"], 0)

    def test_finding_has_attempt_data(self):
        gen = EchoGenerator()
        detector = AlwaysFailDetector()  # Always detects vulnerability
        orch = RedTeamOrchestrator(generator=gen, detectors=[detector])

        probe = DirectInjectionProbe()
        probe.prompts = ["Test prompt"]
        probe.generations_per_prompt = 1
        findings = orch.run_probe(probe)

        self.assertGreater(len(findings), 0)
        self.assertIsNotNone(findings[0].attempt_data)
        self.assertIn("Test prompt", findings[0].attempt_data.prompt)


if __name__ == "__main__":
    unittest.main()
