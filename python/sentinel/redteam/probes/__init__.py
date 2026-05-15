"""
Eresus Sentinel — Red Team Probe Registry.

51 attack probes across 12 categories.

Probe categories:
  Security probes:
  - ToolMisuse — function call abuse testing
  - DataExfiltration — data theft vector testing
  - PrivilegeEscalation — authorization boundary testing
  - ContextManipulation — context window attacks
  - ResourceExhaustion — DoS/resource abuse testing

  Jailbreak probes:
  - LatentInjection — document poisoning (resume, financial, legal, WHOIS)
  - DAN — 12 DAN jailbreak variants (Classic, DevMode, STAN, DUDE, Persona, Authority)
  - DRA — 8 dynamic role assignment strategies
  - EncodingBypass — 9 encoding schemes (base64, ROT13, leet, morse, hex, reverse, Caesar, Unicode)
  - SuffixAttack — GCG-style adversarial suffixes
  - Phrasing — 10 linguistic rephrasing strategies
  - FITD — foot-in-the-door multi-turn escalation (6 chains)
  - SATA — sentiment-aware targeted attacks (6 emotional strategies)

  Content safety probes:
  - PackageHallucination — 4 ecosystem probes (Python, npm, Cargo, Go)
  - GlitchToken — 5 glitch token categories
  - MalwareGen — malware generation compliance testing
  - Continuation — harmful text continuation testing
  - TopicSafety — sensitive topic guardrail testing
  - DirectRequest — unobfuscated harmful request testing
  - Exploitation — CVE exploitation and PoC testing
  - Misleading — false statistics, causation, and logical fallacies

  Autonomous probes:
  - AtkGen — LLM-powered autonomous attack generation (8 seed families)

  Injection probes:
  - AnsiEscape — terminal escape code injection
  - Smuggling — markdown/delimiter/whitespace smuggling
  - WebInjection — XSS, SSTI, header injection

  Privacy probes:
  - LeakReplay — training data memorization testing
"""

from sentinel.redteam.probes.actor_attack import ActorAttackProbe
from sentinel.redteam.probes.audio_attack import AudioAttackProbe
from sentinel.redteam.probes.genetic import GeneticJailbreakProbe
from sentinel.redteam.probes.historical_academic import HistoricalAcademicProbe
from sentinel.redteam.probes.image_attack import ImageAttackProbe
from sentinel.redteam.probes.many_shot import ManyShotProbe
from sentinel.redteam.probes.pair_probe import PAIRProbe
from sentinel.redteam.probes.persuasion import PersuasionProbe
from sentinel.redteam.probes.thought_experiment import ThoughtExperimentProbe
from sentinel.redteam.probes.word_game import WordGameProbe
from sentinel.redteam.probes.aegis import (
    AegisCSEProbe,
    AegisDefamationProbe,
    AegisElectionsProbe,
    AegisHateProbe,
    AegisIPProbe,
    AegisNonViolentCrimesProbe,
    AegisPrivacyProbe,
    AegisSexCrimesProbe,
    AegisSexualContentProbe,
    AegisSpecializedAdviceProbe,
    AegisSuicideProbe,
    AegisViolentCrimesProbe,
    AegisWeaponsProbe,
)
from sentinel.redteam.probes.ansi_escape import AnsiEscapeProbe, AnsiRawProbe
from sentinel.redteam.probes.apikey import APIKeyExtraction, CredentialPhishing
from sentinel.redteam.probes.ascii_smuggling import ASCIISmugglingProbe

# divergence probe removed (duplicate of data_exfiltration + glitch_tokens)
from sentinel.redteam.probes.atkgen import AtkGenProbe
from sentinel.redteam.probes.av_spam import AVSpamProbe
from sentinel.redteam.probes.badchars import (
    ControlCharacters,
    MixedEncodings,
    OverlongSequences,
    UnicodeExploits,
)
from sentinel.redteam.probes.beavertails import (
    BeaverTailsAnimalAbuseProbe,
    BeaverTailsChildAbuseProbe,
    BeaverTailsDrugAbuseProbe,
    BeaverTailsFinancialCrimeProbe,
    BeaverTailsHateSpeechProbe,
    BeaverTailsMisinfoProbe,
    BeaverTailsPrivacyViolenceProbe,
    BeaverTailsSelfHarmProbe,
    BeaverTailsTerrorismProbe,
    BeaverTailsTheftProbe,
    BeaverTailsUnethicalProbe,
    BeaverTailsViolenceProbe,
)
from sentinel.redteam.probes.benchmark_probes import (
    IndirectPromptInjectionProbe,
    ModelIdentificationProbe,
    MultiInputFormatProbe,
    JailbreakDatasetProbe,
    RAGSourceAttributionProbe,
    ToxicChatProbe,
    UnsafeBenchProbe,
    VLGuardProbe,
)
from sentinel.redteam.probes.bfla import BFLAProbe
from sentinel.redteam.probes.bias_probe import (
    AgeBiasProbe,
    DisabilityBiasProbe,
    GenderBiasProbe,
    RacialBiasProbe,
    ReligionBiasProbe,
    SexualOrientationBiasProbe,
    SocioeconomicBiasProbe,
)
from sentinel.redteam.probes.bola import BOLAProbe
from sentinel.redteam.probes.canary_word import CanaryWordProbe
from sentinel.redteam.probes.competitors import CompetitorEndorsementProbe
from sentinel.redteam.probes.context_compliance import (
    AuthorityImpersonationProbe,
    ContextComplianceProbe,
    InstructionInjectionViaDataProbe,
)
from sentinel.redteam.probes.context_manipulation import (
    AdvancedExtractionProbe,
    ContextConfusionProbe,
    MemoryInjectionProbe,
)
from sentinel.redteam.probes.continuation import ContinuationProbe
from sentinel.redteam.probes.contracts import ContractsProbe
from sentinel.redteam.probes.cross_session_leak import CrossSessionLeakProbe
from sentinel.redteam.probes.codesec_probes import (
    ExploitGenProbe,
    InsecureCodeGenProbe,
    MalwareConceptProbe,
    NetworkAttackProbe,
    SocialEngineeringProbe,
)
from sentinel.redteam.probes.dan import DANProbe
from sentinel.redteam.probes.data_exfiltration import (
    CrossBoundaryExfilProbe,
    DirectExfilProbe,
    IndirectExfilProbe,
)
from sentinel.redteam.probes.debug_access import DebugAccessProbe
from sentinel.redteam.probes.direct_request import DirectRequestProbe
from sentinel.redteam.probes.divergent_repetition import DivergentRepetitionProbe
from sentinel.redteam.probes.donotanswer import (
    CopyrightIP,
    DiscriminationHate,
    HumanChatbotHarms,
    InformationHazards,
    MaliciousUses,
    Misinformation,
)
from sentinel.redteam.probes.dra import DRAProbe
from sentinel.redteam.probes.encoding_bypass import EncodingProbe
from sentinel.redteam.probes.excessive_agency import (
    ExcessiveAgencyProbe,
    GoalMisalignmentProbe,
    HijackingProbe,
    IntentProbe,
    UnverifiableClaimsProbe,
    WordplayProbe,
    XSTestProbe,
)
from sentinel.redteam.probes.exploitation import ExploitationProbe
from sentinel.redteam.probes.agent_probes import (
    ALL_AGENT_PROBES,
    AgentIdentityAbuseProbe,
    AutonomousAgentDriftProbe,
    CrescendoJailbreakProbe,
    CrossContextRetrievalProbe,
    ExploitToolAgentProbe,
    GoalTheftProbe,
    InsecureInterAgentCommunicationProbe,
    RecursiveHijackingProbe,
    SystemReconnaissanceProbe,
    ToolMetadataPoisoningProbe,
)
from sentinel.redteam.probes.extra_probes import (
    ALL_EXTRA_PROBES,
    HarmfulBehaviorProbe,
    JailbreakRoleplayProbe,
)
from sentinel.redteam.probes.fileformats import (
    ArchiveBombs,
    PDFInjection,
    PolyglotGeneration,
    SVGInjection,
    XMLInjection,
)
from sentinel.redteam.probes.fitd import FITDProbe
from sentinel.redteam.probes.glitch_tokens import GlitchTokenProbe
from sentinel.redteam.probes.goodside import GoodsideProbe
from sentinel.redteam.probes.grandma import GrandmaEscalation, GrandmaExploit
from sentinel.redteam.probes.hallucination import HallucinationProbe
from sentinel.redteam.probes.harmbench import (
    HarmfulBehaviorContextualProbe,
    HarmfulBehaviorCopyrightProbe,
    HarmfulBehaviorStandardProbe,
)
from sentinel.redteam.probes.imitation import ImitationProbe
from sentinel.redteam.probes.industry_compliance import (
    CodingAgentSecurityProbe,
    CodingAgentVerificationProbe,
    COPPAProbe,
    EcommerceOrderFraudProbe,
    EcommercePCIDSSProbe,
    EcommercePriceManipulationProbe,
    FERPAProbe,
    FinancialComplianceProbe,
    FinancialDataLeakageProbe,
    FinancialHallucinationProbe,
    FinancialImpartialityProbe,
    FinancialSycophancyProbe,
    InsuranceDiscriminationProbe,
    InsuranceMisinformationProbe,
    MedicalFDADisclosureProbe,
    MedicalHallucinationProbe,
    MedicalOffLabelProbe,
    MedicalPHIProbe,
    MedicalSycophancyProbe,
    PharmacyControlledSubstanceProbe,
    PharmacyDosageProbe,
    PharmacyDrugInteractionProbe,
    RealEstateFairHousingProbe,
    RealEstateValuationBiasProbe,
    TeenSafetyDangerousContentProbe,
    TeenSafetyHarmfulBodyIdealsProbe,
    TeenSafetyLocationDisclosureProbe,
    TelecomCPNIProbe,
    TelecomE911Probe,
    TelecomTCPAProbe,
)
from sentinel.redteam.probes.industry_expanded import (
    EcommerceSafetyProbe,
    PharmacySafetyProbe,
    RealEstateSafetyProbe,
    TeenSafetyProbe,
    TelecomSafetyProbe,
)
from sentinel.redteam.probes.industry_safety import (
    FinancialSafetyProbe,
    InsuranceSafetyProbe,
    LegalSafetyProbe,
    MedicalSafetyProbe,
)
from sentinel.redteam.probes.latent_injection import (
    FinancialReportInjectionProbe,
    LegalDocInjectionProbe,
    ResumeInjectionProbe,
    WhoisInjectionProbe,
)
from sentinel.redteam.probes.leak_replay import LeakReplayProbe
from sentinel.redteam.probes.malware_gen import MalwareGenProbe
from sentinel.redteam.probes.mcp_redteam import (
    MCPCrossOriginProbe,
    MCPPromptInjectionProbe,
    MCPResourceExfilProbe,
    MCPSchemaManipulationProbe,
    MCPToolPoisoningProbe,
)
from sentinel.redteam.probes.memory_poisoning import AgentMemoryPoisoningProbe
from sentinel.redteam.probes.misleading import MisleadingProbe
from sentinel.redteam.probes.off_topic import OffTopicProbe
from sentinel.redteam.probes.overreliance import OverrelianceProbe
from sentinel.redteam.probes.package_hallucination import PackageHallucinationProbe
from sentinel.redteam.probes.phrasing import PhrasingProbe
from sentinel.redteam.probes.pii_probe import (
    PIIExtractionProbe,
    PIIGenerationProbe,
    PIIMemorizationProbe,
)
from sentinel.redteam.probes.policy_puppetry import PolicyPuppetryProbe
from sentinel.redteam.probes.privilege_escalation import (
    ContextWindowPoisoningProbe,
    RoleEscalationProbe,
    ToolPermissionEscalationProbe,
)
from sentinel.redteam.probes.prompt_extraction import PromptExtractionProbe
from sentinel.redteam.probes.prompt_inject import PromptInjectProbe
from sentinel.redteam.probes.rag_exfiltration import RAGExfiltrationProbe
from sentinel.redteam.probes.rbac import RBACProbe
from sentinel.redteam.probes.realtoxicityprompts import RTP_PROBES as _rtp_all
from sentinel.redteam.probes.realtoxicityprompts import RTPBlank, RTPSevere
from sentinel.redteam.probes.reasoning_dos import ReasoningDOSProbe
from sentinel.redteam.probes.resource_exhaustion import (
    ContextOverflowProbe,
    RecursiveToolProbe,
    TokenBombProbe,
)
from sentinel.redteam.probes.sata import SATAProbe
from sentinel.redteam.probes.shell_injection import ShellInjectionProbe
from sentinel.redteam.probes.smuggling import SmugglingProbe
from sentinel.redteam.probes.snowball import SnowballProbe
from sentinel.redteam.probes.sql_injection import SQLInjectionProbe
from sentinel.redteam.probes.ssrf import SSRFProbe
from sentinel.redteam.probes.suffix_attack import SuffixAttackProbe
from sentinel.redteam.probes.tap import TAPProbe
from sentinel.redteam.probes.tool_discovery import ToolDiscoveryProbe
from sentinel.redteam.probes.tool_misuse import (
    ToolChainAbuseProbe,
    ToolInvocationProbe,
    ToolParameterInjectionProbe,
)
from sentinel.redteam.probes.topic_safety import TopicSafetyProbe
from sentinel.redteam.probes.visual_jailbreak import (
    ASCIIArtJailbreak,
    MarkdownInjection,
    TextImagePrompt,
    UnicodeLookalike,
)
from sentinel.redteam.probes.web_injection import WebInjectionProbe

__all__ = [
    # Security probes
    "ToolInvocationProbe",
    "ToolParameterInjectionProbe",
    "ToolChainAbuseProbe",
    "DirectExfilProbe",
    "IndirectExfilProbe",
    "CrossBoundaryExfilProbe",
    "RoleEscalationProbe",
    "ToolPermissionEscalationProbe",
    "ContextWindowPoisoningProbe",
    "AdvancedExtractionProbe",
    "MemoryInjectionProbe",
    "ContextConfusionProbe",
    "TokenBombProbe",
    "RecursiveToolProbe",
    "ContextOverflowProbe",
    # Jailbreak probes
    "ResumeInjectionProbe",
    "FinancialReportInjectionProbe",
    "LegalDocInjectionProbe",
    "WhoisInjectionProbe",
    "DANProbe",
    "EncodingProbe",
    "SuffixAttackProbe",
    "PromptInjectProbe",
    "GoodsideProbe",
    "TAPProbe",
    # Content safety probes
    "PackageHallucinationProbe",
    "GlitchTokenProbe",
    "MalwareGenProbe",
    "ContinuationProbe",
    "TopicSafetyProbe",
    "DirectRequestProbe",
    "ExploitationProbe",
    "SnowballProbe",
    "CopyrightIP",
    # Phase 9 probes
    "RTPBlank",
    "RTPSevere",
    "ASCIIArtJailbreak",
    "UnicodeLookalike",
    "MarkdownInjection",
    "TextImagePrompt",
    "GrandmaExploit",
    "GrandmaEscalation",
    "InformationHazards",
    "APIKeyExtraction",
    "CredentialPhishing",
    "ControlCharacters",
    "UnicodeExploits",
    "OverlongSequences",
    "MixedEncodings",
    "SVGInjection",
    "XMLInjection",
    "PolyglotGeneration",
    "ArchiveBombs",
    "PDFInjection",

    # Autonomous probes
    "AtkGenProbe",
    # Advanced jailbreak probes
    "DRAProbe",
    "SATAProbe",
    "PhrasingProbe",
    "FITDProbe",
    "MisleadingProbe",
    # Policy Puppetry (state-of-the-art XML config bypass)
    "PolicyPuppetryProbe",
    # AV/Spam output scanning verification
    "AVSpamProbe",
    # Injection probes
    "AnsiEscapeProbe",
    "AnsiRawProbe",
    "SmugglingProbe",
    "WebInjectionProbe",
    # Privacy probes
    "LeakReplayProbe",
    # Advanced adversarial probes
    "ASCIISmugglingProbe",
    "RAGExfiltrationProbe",
    "AgentMemoryPoisoningProbe",
    "DivergentRepetitionProbe",
    "ReasoningDOSProbe",
    "CrossSessionLeakProbe",
    "CanaryWordProbe",
    # Industry-specific safety probes
    "FinancialSafetyProbe",
    "MedicalSafetyProbe",
    "LegalSafetyProbe",
    "InsuranceSafetyProbe",
    # AEGIS benchmark probes
    "AegisViolentCrimesProbe", "AegisNonViolentCrimesProbe",
    "AegisSexCrimesProbe", "AegisCSEProbe", "AegisDefamationProbe",
    "AegisSpecializedAdviceProbe", "AegisPrivacyProbe", "AegisIPProbe",
    "AegisWeaponsProbe", "AegisHateProbe", "AegisSuicideProbe",
    "AegisSexualContentProbe", "AegisElectionsProbe",
    # BeaverTails benchmark probes
    "BeaverTailsAnimalAbuseProbe", "BeaverTailsChildAbuseProbe",
    "BeaverTailsDrugAbuseProbe", "BeaverTailsFinancialCrimeProbe",
    "BeaverTailsHateSpeechProbe", "BeaverTailsMisinfoProbe",
    "BeaverTailsUnethicalProbe", "BeaverTailsPrivacyViolenceProbe",
    "BeaverTailsSelfHarmProbe", "BeaverTailsTerrorismProbe",
    "BeaverTailsTheftProbe", "BeaverTailsViolenceProbe",
    # Additional benchmark probes
    "ToxicChatProbe", "JailbreakDatasetProbe", "JailbreakRoleplayProbe", "UnsafeBenchProbe", "VLGuardProbe",
    "CodeSecurityProbe",
    "RAGSourceAttributionProbe", "MultiInputFormatProbe",
    "ModelIdentificationProbe", "IndirectPromptInjectionProbe",
    # Bias probes
    "RacialBiasProbe", "GenderBiasProbe", "AgeBiasProbe",
    "ReligionBiasProbe", "DisabilityBiasProbe",
    "SexualOrientationBiasProbe", "SocioeconomicBiasProbe",
    # Context compliance probes
    "ContextComplianceProbe", "AuthorityImpersonationProbe",
    "InstructionInjectionViaDataProbe",
    # Code security probes
    "InsecureCodeGenProbe", "ExploitGenProbe",
    "SocialEngineeringProbe", "MalwareConceptProbe",
    "NetworkAttackProbe",
    # Excessive agency probes
    "ExcessiveAgencyProbe", "GoalMisalignmentProbe", "HijackingProbe",
    "IntentProbe", "UnverifiableClaimsProbe", "WordplayProbe", "XSTestProbe",
    # Harmful behavior probes
    "HarmfulBehaviorStandardProbe", "HarmfulBehaviorContextualProbe", "HarmfulBehaviorCopyrightProbe",
    "HarmfulBehaviorProbe",
    # PII probes
    "PIIExtractionProbe", "PIIGenerationProbe", "PIIMemorizationProbe",
    # Agent probes (agent_probes.py)
    "ALL_AGENT_PROBES",
    "AgentIdentityAbuseProbe",
    "ToolMetadataPoisoningProbe",
    "InsecureInterAgentCommunicationProbe",
    "CrossContextRetrievalProbe",
    "SystemReconnaissanceProbe",
    "ExploitToolAgentProbe",
    "AutonomousAgentDriftProbe",
    "GoalTheftProbe",
    "RecursiveHijackingProbe",
    "CrescendoJailbreakProbe",
    # MCP security probes
    "MCPToolPoisoningProbe", "MCPResourceExfilProbe", "MCPPromptInjectionProbe",
    "MCPSchemaManipulationProbe", "MCPCrossOriginProbe",
    # Industry compliance probes
    "FinancialHallucinationProbe", "FinancialComplianceProbe",
    "FinancialSycophancyProbe", "FinancialDataLeakageProbe",
    "FinancialImpartialityProbe",
    "MedicalHallucinationProbe", "MedicalSycophancyProbe",
    "MedicalFDADisclosureProbe", "MedicalOffLabelProbe", "MedicalPHIProbe",
    "TelecomCPNIProbe", "TelecomE911Probe", "TelecomTCPAProbe",
    "EcommercePriceManipulationProbe", "EcommercePCIDSSProbe",
    "EcommerceOrderFraudProbe",
    "InsuranceDiscriminationProbe", "InsuranceMisinformationProbe",
    "PharmacyDosageProbe", "PharmacyDrugInteractionProbe",
    "PharmacyControlledSubstanceProbe",
    "RealEstateFairHousingProbe", "RealEstateValuationBiasProbe",
    "TeenSafetyDangerousContentProbe", "TeenSafetyLocationDisclosureProbe",
    "TeenSafetyHarmfulBodyIdealsProbe",
    "COPPAProbe", "FERPAProbe",
    "CodingAgentSecurityProbe", "CodingAgentVerificationProbe",
    # Industry expanded probes
    "PharmacySafetyProbe", "EcommerceSafetyProbe", "TelecomSafetyProbe",
    "RealEstateSafetyProbe", "TeenSafetyProbe",
    # Authorization probes
    "BFLAProbe", "BOLAProbe", "RBACProbe",
    # Miscellaneous probes
    "CompetitorEndorsementProbe", "ContractsProbe", "DebugAccessProbe",
    "HallucinationProbe", "ImitationProbe", "OffTopicProbe",
    "OverrelianceProbe", "PromptExtractionProbe",
    "ShellInjectionProbe", "SQLInjectionProbe", "SSRFProbe",
    "ToolDiscoveryProbe",
    # Sprint 1 probes
    "GeneticJailbreakProbe",
    "ActorAttackProbe",
    "WordGameProbe",
    "AudioAttackProbe",
    # Sprint 2 probes
    "PAIRProbe",
    "PersuasionProbe",
    "ManyShotProbe",
    "ThoughtExperimentProbe",
    "HistoricalAcademicProbe",
    "ImageAttackProbe",
]
