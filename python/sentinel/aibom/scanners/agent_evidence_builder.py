"""Build composite agent evidence by aggregating signals across files."""
from __future__ import annotations

from pathlib import Path

from sentinel.aibom.models import AIComponent, AIComponentType
from sentinel.aibom.scanners.base import BaseAIBOMScanner
from sentinel.rules import load_aibom_patterns


class AgentEvidenceBuilder(BaseAIBOMScanner):
    name = "agent-evidence-builder"

    def scan(self, root: Path) -> list[AIComponent]:
        file_evidence: dict[str, dict] = {}

        for p in self._iter_files(root, suffixes=(".py",)):
            text = self._read(p)
            if not text:
                continue
            evidence = self._collect_evidence(text)
            if evidence["signals"]:
                file_evidence[str(p)] = evidence

        return self._build_components(file_evidence)

    def _collect_evidence(self, text: str) -> dict:
        rules = load_aibom_patterns()["agent_evidence"]
        signals: list[str] = []
        frameworks: list[str] = []

        for key, name in rules["frameworks"].items():
            if key in text:
                frameworks.append(name)
                signals.append(f"framework:{name}")

        sig_map = {"tool_binding": "tool-binding", "memory": "memory-persistence",
                   "planning": "planning-loop", "llm_call": "llm-call",
                   "streaming": "streaming", "retrieval": "retrieval"}
        for sig_name, rx in rules["signals"].items():
            if rx.search(text):
                signals.append(sig_map.get(sig_name, sig_name))

        return {
            "signals": signals,
            "frameworks": frameworks,
            "has_tools": "tool-binding" in signals,
            "has_memory": "memory-persistence" in signals,
            "has_planning": "planning-loop" in signals,
            "has_llm": "llm-call" in signals,
        }

    def _build_components(self, evidence: dict[str, dict]) -> list[AIComponent]:
        out: list[AIComponent] = []
        all_frameworks: set[str] = set()
        all_signals: set[str] = set()

        for path, ev in evidence.items():
            all_frameworks.update(ev["frameworks"])
            all_signals.update(ev["signals"])

        if not all_signals:
            return out

        confidence = self._compute_confidence(all_signals)
        agent_type = self._infer_type(all_signals)

        out.append(AIComponent(
            type=agent_type,
            name=f"agent-composite:{'+'.join(sorted(all_frameworks)) or 'unknown'}",
            path=next(iter(evidence)),
            description=f"Composite agent evidence ({len(all_signals)} signals across {len(evidence)} files)",
            evidence=sorted(all_signals),
            properties={
                "frameworks": sorted(all_frameworks),
                "file_count": len(evidence),
                "signal_count": len(all_signals),
                "confidence": confidence,
                "has_tools": "tool-binding" in all_signals,
                "has_memory": "memory-persistence" in all_signals,
                "has_planning": "planning-loop" in all_signals,
            },
        ))
        return out

    @staticmethod
    def _compute_confidence(signals: set[str]) -> float:
        score = 0.0
        if any(s.startswith("framework:") for s in signals):
            score += 0.4
        if "tool-binding" in signals:
            score += 0.2
        if "llm-call" in signals:
            score += 0.2
        if "planning-loop" in signals:
            score += 0.1
        if "memory-persistence" in signals:
            score += 0.1
        return min(score, 1.0)

    @staticmethod
    def _infer_type(signals: set[str]) -> AIComponentType:
        if "planning-loop" in signals:
            return AIComponentType.AGENT_PLANNER
        if any("react" in s for s in signals):
            return AIComponentType.AGENT_REACT
        return AIComponentType.AGENT
