"""Agent/MCP security -- tool trust boundary validation and permission analysis.

Extended with:
- Static analysis (taint tracking, dataflow, prompt defense)
- Behavioral analysis (runtime MCP behavior monitoring)
- Skill scanner (command safety, trigger analysis, cross-skill)
- YARA pattern analyzer (12 built-in malware detection rules)
- Threat taxonomy (OWASP LLM + Agentic + MITRE ATLAS)
- Report generator (JSON, SARIF, Markdown, HTML)
"""

from .a2a_scanner import A2AScanner, A2AScanResult
from .behavioral_analyzer import BehavioralAnalyzer, BehaviorFinding, ToolCallEvent
from .mcp_validator import MCPValidator
from .permissions import PermissionAnalyzer
from .report_generator import ReportFormat, ReportGenerator, ScanFinding, ScanReport
from .skill_eval_manifest import (
    SKILL_EVAL_CATEGORIES,
    SKILL_POLICY_PROFILES,
    discover_skill_eval_fixtures,
    skill_eval_manifest,
)
from .skill_scanner import (
    CommandSafetyAnalyzer,
    SkillScanner,
    SkillThreatRuleScanner,
    TriggerAnalyzer,
)
from .static_analysis import PromptDefenseAnalyzer, StaticAnalyzer, TaintTracker
from .threat_taxonomy import ThreatCategory as ThreatCat
from .threat_taxonomy import ThreatTaxonomy
from .trust_map import TrustBoundaryMapper
from .yara_analyzer import YaraAnalyzer, YaraMatch, YaraMatchSeverity

__all__ = [
    "MCPValidator", "TrustBoundaryMapper", "PermissionAnalyzer",
    "StaticAnalyzer", "TaintTracker", "PromptDefenseAnalyzer",
    "BehavioralAnalyzer", "ToolCallEvent", "BehaviorFinding",
    "SkillScanner", "CommandSafetyAnalyzer", "SkillThreatRuleScanner", "TriggerAnalyzer",
    "YaraAnalyzer", "YaraMatch", "YaraMatchSeverity",
    "ThreatTaxonomy", "ThreatCat",
    "ReportGenerator", "ScanReport", "ScanFinding", "ReportFormat",
    "A2AScanner", "A2AScanResult",
    "SKILL_EVAL_CATEGORIES", "SKILL_POLICY_PROFILES",
    "discover_skill_eval_fixtures", "skill_eval_manifest",
]
