"""Agent/MCP security -- tool trust boundary validation and permission analysis.

Extended with:
- Static analysis (taint tracking, dataflow, prompt defense)
- Behavioral analysis (runtime MCP behavior monitoring)
- Skill scanner (command safety, trigger analysis, cross-skill)
- YARA pattern analyzer (12 built-in malware detection rules)
- Threat taxonomy (OWASP LLM + Agentic + MITRE ATLAS)
- Report generator (JSON, SARIF, Markdown, HTML)
"""

from .mcp_validator import MCPValidator
from .trust_map import TrustBoundaryMapper
from .permissions import PermissionAnalyzer
from .static_analysis import StaticAnalyzer, TaintTracker, PromptDefenseAnalyzer
from .behavioral_analyzer import BehavioralAnalyzer, ToolCallEvent, BehaviorFinding
from .skill_scanner import SkillScanner, CommandSafetyAnalyzer, TriggerAnalyzer
from .yara_analyzer import YaraAnalyzer, YaraMatch, YaraMatchSeverity
from .threat_taxonomy import ThreatTaxonomy, ThreatCategory as ThreatCat
from .report_generator import ReportGenerator, ScanReport, ScanFinding, ReportFormat

__all__ = [
    "MCPValidator", "TrustBoundaryMapper", "PermissionAnalyzer",
    "StaticAnalyzer", "TaintTracker", "PromptDefenseAnalyzer",
    "BehavioralAnalyzer", "ToolCallEvent", "BehaviorFinding",
    "SkillScanner", "CommandSafetyAnalyzer", "TriggerAnalyzer",
    "YaraAnalyzer", "YaraMatch", "YaraMatchSeverity",
    "ThreatTaxonomy", "ThreatCat",
    "ReportGenerator", "ScanReport", "ScanFinding", "ReportFormat",
]
