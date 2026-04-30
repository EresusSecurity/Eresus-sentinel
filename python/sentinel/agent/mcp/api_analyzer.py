"""External API-based MCP analysis orchestrator.

Coordinates all MCP sub-analyzers into a single pipeline result, optionally
calling external APIs (VirusTotal, OSV) when keys are configured.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class MCPApiAnalysisResult:
    server_name: str
    tool_count: int = 0
    readiness_score: float = 0.0
    readiness_grade: str = "F"
    vuln_count: int = 0
    prompt_injection_issues: int = 0
    behavioral_issues: int = 0
    vt_malicious: int = 0
    overall_risk: str = "unknown"
    findings: list[dict] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    error: Optional[str] = None


class MCPApiAnalyzer:
    """Orchestrate all MCP analyzer modules into a single result.

    Args:
        vt_api_key: VirusTotal API key (optional).
        use_osv: Query OSV vulnerability database (default True).
        use_behavioral_llm: LLM client for behavioral alignment (optional).
        readiness_passing_score: Readiness threshold (default 60.0).
    """

    def __init__(
        self,
        vt_api_key: Optional[str] = None,
        use_osv: bool = True,
        use_behavioral_llm: Any = None,
        readiness_passing_score: float = 60.0,
    ) -> None:
        from sentinel.agent.mcp.behavioral_alignment import BehavioralAlignmentAnalyzer
        from sentinel.agent.mcp.prompt_defense import PromptDefenseAnalyzer
        from sentinel.agent.mcp.readiness_analyzer import ReadinessAnalyzer
        from sentinel.agent.mcp.virustotal_analyzer import VirusTotalAnalyzer
        from sentinel.agent.mcp.vulnerable_package import VulnerablePackageAnalyzer

        self._readiness = ReadinessAnalyzer()
        self._prompt_defense = PromptDefenseAnalyzer()
        self._vt = VirusTotalAnalyzer(api_key=vt_api_key)
        self._vuln_pkg = VulnerablePackageAnalyzer(use_osv=use_osv)
        self._behavioral = BehavioralAlignmentAnalyzer(llm_client=use_behavioral_llm)
        self._readiness_threshold = readiness_passing_score

    def analyze(
        self,
        server_info: dict[str, Any],
        tools: list[dict[str, Any]],
        capabilities: dict[str, Any] | None = None,
        project_path: Optional[str] = None,
        binary_path: Optional[str] = None,
    ) -> MCPApiAnalysisResult:
        """Run the full analysis pipeline.

        Args:
            server_info: MCP server info dict (``name``, ``version``, etc.)
            tools: List of MCP tool definition dicts.
            capabilities: Optional capabilities dict from server manifest.
            project_path: Path to server project root (for dependency scanning).
            binary_path: Path to server binary (for VirusTotal lookup).
        """
        server_name = server_info.get("name", "<unnamed>")
        result = MCPApiAnalysisResult(
            server_name=server_name,
            tool_count=len(tools),
        )

        try:
            self._run_readiness(result, server_info, tools, capabilities or {})
            self._run_prompt_defense(result, tools)
            self._run_behavioral(result, tools)
            if project_path:
                self._run_vuln_scan(result, project_path)
            if binary_path:
                self._run_vt(result, binary_path)
            result.overall_risk = self._compute_risk(result)
        except Exception as exc:
            logger.exception("MCPApiAnalyzer pipeline error for %s", server_name)
            result.error = str(exc)
            result.overall_risk = "error"

        return result

    def _run_readiness(
        self,
        result: MCPApiAnalysisResult,
        server_info: dict,
        tools: list,
        capabilities: dict,
    ) -> None:
        r = self._readiness.analyze(server_info, tools, capabilities)
        result.readiness_score = r.percentage
        result.readiness_grade = r.grade
        result.recommendations.extend(r.recommendations)
        if r.percentage < self._readiness_threshold:
            result.findings.append({
                "type": "readiness",
                "severity": "MEDIUM",
                "message": f"Server readiness {r.percentage:.0f}% below threshold ({self._readiness_threshold:.0f}%)",
                "grade": r.grade,
            })

    def _run_prompt_defense(self, result: MCPApiAnalysisResult, tools: list) -> None:
        defense_results = self._prompt_defense.analyze_server(tools)
        for dr in defense_results:
            result.prompt_injection_issues += len(dr.issues)
            for issue in dr.issues:
                result.findings.append({
                    "type": "prompt_injection",
                    "severity": issue.severity,
                    "tool": dr.tool_name,
                    "field": issue.field,
                    "message": f"Potential prompt injection in {issue.field!r}: {issue.snippet!r}",
                })
            result.recommendations.extend(dr.recommendations)

    def _run_behavioral(self, result: MCPApiAnalysisResult, tools: list) -> None:
        for tool in tools:
            src = tool.get("_source_code", "")
            if not src:
                continue
            ba = self._behavioral.analyze(
                tool_name=tool.get("name", "?"),
                description=tool.get("description", ""),
                source_code=src,
            )
            if not ba.aligned:
                result.behavioral_issues += 1
                result.findings.append({
                    "type": "behavioral_misalignment",
                    "severity": "HIGH",
                    "tool": ba.tool_name,
                    "confidence": ba.confidence,
                    "message": f"Tool behavior may not match description (confidence {ba.confidence:.2f})",
                    "issues": ba.issues,
                })

    def _run_vuln_scan(self, result: MCPApiAnalysisResult, project_path: str) -> None:
        vr = self._vuln_pkg.scan_path(project_path)
        result.vuln_count = len(vr.vulnerabilities)
        for vuln in vr.vulnerabilities:
            result.findings.append({
                "type": "vulnerable_dependency",
                "severity": vuln.severity,
                "package": f"{vuln.package}=={vuln.version}",
                "vuln_id": vuln.vuln_id,
                "message": vuln.summary,
            })
        if vr.error:
            logger.warning("Vuln scan error for %s: %s", project_path, vr.error)

    def _run_vt(self, result: MCPApiAnalysisResult, binary_path: str) -> None:
        if not Path(binary_path).exists():
            return
        vt = self._vt.analyze_file(binary_path)
        result.vt_malicious = vt.malicious
        if not vt.is_clean:
            result.findings.append({
                "type": "virustotal",
                "severity": "CRITICAL" if vt.malicious >= 3 else "HIGH",
                "sha256": vt.sha256,
                "verdict": vt.verdict,
                "detections": f"{vt.malicious}/{vt.total_engines}",
                "message": f"VirusTotal: {vt.malicious} malicious, {vt.suspicious} suspicious detections",
                "permalink": vt.permalink,
            })

    @staticmethod
    def _compute_risk(result: MCPApiAnalysisResult) -> str:
        if result.vt_malicious >= 3:
            return "critical"
        if result.behavioral_issues > 0 or result.prompt_injection_issues > 2:
            return "high"
        if result.vuln_count > 0 or result.prompt_injection_issues > 0:
            return "medium"
        if result.readiness_score < 50:
            return "low"
        return "clean"
