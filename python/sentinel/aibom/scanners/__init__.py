"""AIBOM scanners."""
from sentinel.aibom.scanners.a2a_detector import A2ADetector
from sentinel.aibom.scanners.agent_detector import AgentDetector
from sentinel.aibom.scanners.agent_evidence_builder import AgentEvidenceBuilder
from sentinel.aibom.scanners.base import BaseAIBOMScanner
from sentinel.aibom.scanners.cicd_scanner import CICDScanner
from sentinel.aibom.scanners.cloud_scanner import CloudScanner
from sentinel.aibom.scanners.config_scanner import ConfigScanner
from sentinel.aibom.scanners.container_extractor import ContainerExtractor
from sentinel.aibom.scanners.container_scanner import ContainerScanner
from sentinel.aibom.scanners.data_file_scanner import DataFileScanner
from sentinel.aibom.scanners.dependency_scanner import DependencyScanner
from sentinel.aibom.scanners.deployment_detector import DeploymentDetector
from sentinel.aibom.scanners.endpoint_classifier import EndpointClassifier
from sentinel.aibom.scanners.env_var_resolver import EnvVarResolver
from sentinel.aibom.scanners.file_cache import FileCache
from sentinel.aibom.scanners.import_context import ImportContext
from sentinel.aibom.scanners.kb_enrichment_scanner import KBEnrichmentScanner
from sentinel.aibom.scanners.mcp_detector import MCPDetector
from sentinel.aibom.scanners.ml_lifecycle_detector import MLLifecycleDetector
from sentinel.aibom.scanners.model_detector import ModelDetector
from sentinel.aibom.scanners.model_file_scanner import ModelFileScanner
from sentinel.aibom.scanners.multi_language_scanner import MultiLanguageScanner
from sentinel.aibom.scanners.remote_agent_resolver import RemoteAgentResolver
from sentinel.aibom.scanners.secret_detector import SecretDetector
from sentinel.aibom.scanners.shadow_ai_detector import ShadowAIDetector
from sentinel.aibom.scanners.skill_detector import SkillDetector
from sentinel.aibom.scanners.structural_agent_scanner import StructuralAgentScanner
from sentinel.aibom.scanners.vuln_scanner import VulnScanner
from sentinel.aibom.scanners.workflow_scanner import WorkflowScanner
from sentinel.aibom.scanners.workspace_dep_scanner import WorkspaceDepScanner

__all__ = [
    "BaseAIBOMScanner",
    "ModelDetector",
    "DependencyScanner",
    "ConfigScanner",
    "MCPDetector",
    "AgentDetector",
    "SecretDetector",
    "EndpointClassifier",
    "DataFileScanner",
    "ContainerScanner",
    "CICDScanner",
    "WorkflowScanner",
    "ShadowAIDetector",
    "A2ADetector",
    "RemoteAgentResolver",
    "MLLifecycleDetector",
    "EnvVarResolver",
    "DeploymentDetector",
    "ModelFileScanner",
    "StructuralAgentScanner",
    "VulnScanner",
    "SkillDetector",
    "AgentEvidenceBuilder",
    "ContainerExtractor",
    "CloudScanner",
    "KBEnrichmentScanner",
    "ImportContext",
    "MultiLanguageScanner",
    "FileCache",
    "WorkspaceDepScanner",
    "default_scanners",
    "scanner_registry",
]


def default_scanners() -> list[BaseAIBOMScanner]:
    return [
        ModelDetector(),
        DependencyScanner(),
        ConfigScanner(),
        MCPDetector(),
        AgentDetector(),
        SecretDetector(),
        EndpointClassifier(),
        DataFileScanner(),
        ContainerScanner(),
        CICDScanner(),
        WorkflowScanner(),
        ShadowAIDetector(),
        A2ADetector(),
        RemoteAgentResolver(),
        MLLifecycleDetector(),
        EnvVarResolver(),
        DeploymentDetector(),
        ModelFileScanner(),
        StructuralAgentScanner(),
        VulnScanner(),
        SkillDetector(),
        AgentEvidenceBuilder(),
        ContainerExtractor(),
        CloudScanner(),
        KBEnrichmentScanner(),
        ImportContext(),
        MultiLanguageScanner(),
        WorkspaceDepScanner(),
    ]


def scanner_registry() -> list[dict[str, str]]:
    """Return scanner metadata for CLI/debug output."""
    registry = []
    for scanner in default_scanners():
        registry.append({
            "id": scanner.name,
            "class": f"{scanner.__class__.__module__}.{scanner.__class__.__name__}",
            "description": (scanner.__doc__ or "").strip().splitlines()[0]
            if scanner.__doc__ else "",
        })
    return registry
