"""Detect ML lifecycle phases: training, evaluation, deployment, experimentation."""
from __future__ import annotations

from pathlib import Path

from sentinel.aibom.models import AIComponent, AIComponentType
from sentinel.aibom.scanners.base import BaseAIBOMScanner
from sentinel.rules import load_aibom_patterns

_PHASE_TYPE = {
    "evaluation": AIComponentType.EVALUATION,
}


class MLLifecycleDetector(BaseAIBOMScanner):
    name = "ml-lifecycle-detector"

    def scan(self, root: Path) -> list[AIComponent]:
        rules = load_aibom_patterns()["ml_lifecycle"]
        out: list[AIComponent] = []
        for p in self._iter_files(root, suffixes=(".py", ".ipynb")):
            text = self._read(p)
            if not text:
                continue
            self._detect_phases(p, text, rules, out)
            self._detect_hp(p, text, rules.get("hyperparameters", []), out)
        return out

    @staticmethod
    def _detect_phases(p, text, rules, out):
        for phase, patterns in rules.items():
            if phase == "hyperparameters":
                continue
            for entry in patterns:
                rx, label = entry[0], entry[1]
                co_occ = entry[3] if len(entry) > 3 else ()
                if rx.search(text):
                    if co_occ and not any(ctx in text for ctx in co_occ):
                        continue
                    ct = _PHASE_TYPE.get(phase, AIComponentType.WORKFLOW)
                    out.append(AIComponent(
                        type=ct, name=f"ml-{phase}:{label}", path=str(p),
                        description=f"ML lifecycle phase: {phase} ({label})",
                        evidence=[label], properties={"phase": phase, "framework": label},
                    ))
                    break

    @staticmethod
    def _detect_hp(p, text, patterns, out):
        hp: dict[str, str] = {}
        for entry in patterns:
            rx, label = entry[0], entry[1]
            capture = entry[2] if len(entry) > 2 else False
            m = rx.search(text)
            if m and capture:
                hp[label] = m.group(1).strip()
        if hp:
            out.append(AIComponent(
                type=AIComponentType.CONFIG, name="hyperparameters", path=str(p),
                description=f"ML hyperparameters: {', '.join(hp.keys())}",
                evidence=list(hp.keys()), properties={"hyperparameters": hp},
            ))
