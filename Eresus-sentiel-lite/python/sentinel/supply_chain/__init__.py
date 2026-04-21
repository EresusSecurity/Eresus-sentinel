"""
Supply chain security -- model provenance, integrity, dependency auditing,
HuggingFace model repository scanning, adversarial embedding detection,
and live vulnerability scanning (OSV/NVD, typosquatting, dependency confusion).
"""

from .provenance import ProvenanceVerifier
from .dependency import DependencyAuditor
from .hf_scanner import HFRemoteScanner
from .hubness_detector import AdversarialHubnessScanner, HubnessDetector
from .live_scanner import LiveDependencyScanner, OSVClient, TyposquatDetector

HFModelScanner = HFRemoteScanner

__all__ = [
    "ProvenanceVerifier", "DependencyAuditor", "HFModelScanner",
    "HFRemoteScanner",
    "AdversarialHubnessScanner", "HubnessDetector",
    "LiveDependencyScanner", "OSVClient", "TyposquatDetector",
]
