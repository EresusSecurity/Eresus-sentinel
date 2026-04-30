"""Multi-agent security testing module.

Provides four test harnesses for cross-agent security evaluation:

- :class:`~sentinel.agent.multi_agent.cascading_hallucination.CascadingHallucinationDetector`
- :class:`~sentinel.agent.multi_agent.cross_contamination.CrossContaminationTester`
- :class:`~sentinel.agent.multi_agent.memory_poisoning.MemoryPoisoningSimulator`
- :class:`~sentinel.agent.multi_agent.decision_drift_monitor.DecisionDriftMonitor`
"""
from sentinel.agent.multi_agent.cascading_hallucination import CascadingHallucinationDetector
from sentinel.agent.multi_agent.cross_contamination import CrossContaminationTester
from sentinel.agent.multi_agent.decision_drift_monitor import DecisionDriftMonitor
from sentinel.agent.multi_agent.memory_poisoning import MemoryPoisoningSimulator

__all__ = [
    "CascadingHallucinationDetector",
    "CrossContaminationTester",
    "MemoryPoisoningSimulator",
    "DecisionDriftMonitor",
]
