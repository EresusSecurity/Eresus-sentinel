"""
Unified analysis context — aggregates results from all analyzers into a
single scored report with confidence-weighted findings.

Used as the top-level entry point for comprehensive model security analysis.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from sentinel.analysis.anomaly_detector import AnomalyDetector
from sentinel.analysis.framework_patterns import ALL_PROFILES, detect_framework
from sentinel.analysis.integrated import (
    FileEntropyScanner,
    IntegratedAnalyzer,
    MLContextAnalyzer,
    OpcodeSequenceAnalyzer,
    PatternDetector,
    SemanticAnalyzer,
)
from sentinel.finding import Finding, Severity

logger = logging.getLogger(__name__)


@dataclass
class AnalysisContext:
    """Aggregated analysis context for a scan target."""
    target: str
    detected_framework: Optional[str] = None
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    risk_score: float = 0.0  # 0.0 (safe) to 1.0 (critical)
    findings: list[Finding] = field(default_factory=list)
    modules_seen: set[str] = field(default_factory=set)

    def add_findings(self, new_findings: list[Finding]) -> None:
        self.findings.extend(new_findings)
        for f in new_findings:
            self.total_findings += 1
            sev = f.severity if isinstance(f.severity, Severity) else Severity.INFO
            if sev == Severity.CRITICAL:
                self.critical_count += 1
            elif sev == Severity.HIGH:
                self.high_count += 1
            elif sev == Severity.MEDIUM:
                self.medium_count += 1
            elif sev == Severity.LOW:
                self.low_count += 1
            else:
                self.info_count += 1

    def compute_risk_score(self) -> float:
        """Weighted risk score: CRITICAL=1.0, HIGH=0.7, MEDIUM=0.4, LOW=0.1."""
        if self.total_findings == 0:
            self.risk_score = 0.0
            return 0.0
        weighted = (
            self.critical_count * 1.0
            + self.high_count * 0.7
            + self.medium_count * 0.4
            + self.low_count * 0.1
        )
        # Normalize: cap at 1.0, scale by log
        import math
        self.risk_score = min(1.0, weighted / max(1, math.log2(self.total_findings + 1) * 2))
        return self.risk_score

    def summary(self) -> dict:
        return {
            "target": self.target,
            "detected_framework": self.detected_framework,
            "risk_score": round(self.risk_score, 3),
            "total_findings": self.total_findings,
            "by_severity": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
        }


class UnifiedAnalyzer:
    """Unified analysis pipeline combining all analyzers with anomaly detection."""

    def __init__(self) -> None:
        self._integrated = IntegratedAnalyzer()
        self._anomaly = AnomalyDetector()

    def analyze(self, target_path: str) -> AnalysisContext:
        """Run all analyzers on a target and return an aggregated context."""
        ctx = AnalysisContext(target=target_path)

        # Run integrated analyzer (entropy, pattern, opcode, semantic, context)
        ctx.add_findings(self._integrated.analyze(target_path))

        # Run anomaly detector on pickle-like files
        path = Path(target_path)
        if path.is_file() and path.suffix.lower() in (".pkl", ".pickle", ".pt", ".pth", ".joblib"):
            try:
                data = path.read_bytes()
                ctx.add_findings(self._anomaly.analyze(data, str(path)))
            except OSError:
                pass
        elif path.is_dir():
            for f in path.rglob("*"):
                if f.is_file() and f.suffix.lower() in (".pkl", ".pickle", ".pt", ".pth", ".joblib"):
                    try:
                        data = f.read_bytes()
                        ctx.add_findings(self._anomaly.analyze(data, str(f)))
                    except OSError:
                        pass

        ctx.compute_risk_score()
        logger.info(
            "Unified analysis of %s: %d findings, risk=%.3f, framework=%s",
            target_path, ctx.total_findings, ctx.risk_score, ctx.detected_framework,
        )
        return ctx
