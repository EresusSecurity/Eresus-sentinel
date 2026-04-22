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

from sentinel.redteam.probes.tool_misuse import (
    ToolInvocationProbe,
    ToolParameterInjectionProbe,
    ToolChainAbuseProbe,
)
from sentinel.redteam.probes.data_exfiltration import (
    DirectExfilProbe,
    IndirectExfilProbe,
    CrossBoundaryExfilProbe,
)
from sentinel.redteam.probes.privilege_escalation import (
    RoleEscalationProbe,
    ToolPermissionEscalationProbe,
    ContextWindowPoisoningProbe,
)
from sentinel.redteam.probes.context_manipulation import (
    AdvancedExtractionProbe,
    MemoryInjectionProbe,
    ContextConfusionProbe,
)
from sentinel.redteam.probes.resource_exhaustion import (
    TokenBombProbe,
    RecursiveToolProbe,
    ContextOverflowProbe,
)
from sentinel.redteam.probes.latent_injection import (
    ResumeInjectionProbe,
    FinancialReportInjectionProbe,
    LegalDocInjectionProbe,
    WhoisInjectionProbe,
)
from sentinel.redteam.probes.dan import DANProbe
from sentinel.redteam.probes.encoding_bypass import EncodingProbe
from sentinel.redteam.probes.package_hallucination import PackageHallucinationProbe
from sentinel.redteam.probes.glitch_tokens import GlitchTokenProbe
from sentinel.redteam.probes.ansi_escape import AnsiEscapeProbe, AnsiRawProbe
from sentinel.redteam.probes.leak_replay import LeakReplayProbe
from sentinel.redteam.probes.malware_gen import MalwareGenProbe
from sentinel.redteam.probes.smuggling import SmugglingProbe
from sentinel.redteam.probes.suffix_attack import SuffixAttackProbe
from sentinel.redteam.probes.continuation import ContinuationProbe
from sentinel.redteam.probes.exploitation import ExploitationProbe
from sentinel.redteam.probes.web_injection import WebInjectionProbe
from sentinel.redteam.probes.topic_safety import TopicSafetyProbe
from sentinel.redteam.probes.direct_request import DirectRequestProbe
from sentinel.redteam.probes.snowball import SnowballProbe
from sentinel.redteam.probes.prompt_inject import PromptInjectProbe
from sentinel.redteam.probes.goodside import GoodsideProbe
from sentinel.redteam.probes.tap import TAPProbe
from sentinel.redteam.probes.donotanswer import InformationHazards, MaliciousUses, DiscriminationHate, Misinformation, HumanChatbotHarms, CopyrightIP
from sentinel.redteam.probes.visual_jailbreak import ASCIIArtJailbreak, UnicodeLookalike, MarkdownInjection, TextImagePrompt
from sentinel.redteam.probes.grandma import GrandmaExploit, GrandmaEscalation
from sentinel.redteam.probes.realtoxicityprompts import RTP_PROBES as _rtp_all, RTPBlank, RTPSevere
from sentinel.redteam.probes.apikey import APIKeyExtraction, CredentialPhishing
from sentinel.redteam.probes.badchars import ControlCharacters, UnicodeExploits, OverlongSequences, MixedEncodings
from sentinel.redteam.probes.fileformats import SVGInjection, XMLInjection, PolyglotGeneration, ArchiveBombs, PDFInjection
# divergence probe removed (duplicate of data_exfiltration + glitch_tokens)
from sentinel.redteam.probes.atkgen import AtkGenProbe
from sentinel.redteam.probes.dra import DRAProbe
from sentinel.redteam.probes.sata import SATAProbe
from sentinel.redteam.probes.phrasing import PhrasingProbe
from sentinel.redteam.probes.fitd import FITDProbe
from sentinel.redteam.probes.misleading import MisleadingProbe
from sentinel.redteam.probes.policy_puppetry import PolicyPuppetryProbe
from sentinel.redteam.probes.av_spam import AVSpamProbe
from sentinel.redteam.probes.ascii_smuggling import ASCIISmugglingProbe
from sentinel.redteam.probes.rag_exfiltration import RAGExfiltrationProbe
from sentinel.redteam.probes.memory_poisoning import AgentMemoryPoisoningProbe
from sentinel.redteam.probes.divergent_repetition import DivergentRepetitionProbe
from sentinel.redteam.probes.reasoning_dos import ReasoningDOSProbe
from sentinel.redteam.probes.cross_session_leak import CrossSessionLeakProbe
from sentinel.redteam.probes.canary_word import CanaryWordProbe
from sentinel.redteam.probes.industry_safety import (
    FinancialSafetyProbe,
    MedicalSafetyProbe,
    LegalSafetyProbe,
    InsuranceSafetyProbe,
)

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
]
