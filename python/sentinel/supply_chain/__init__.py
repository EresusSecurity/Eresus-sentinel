"""
Supply chain security -- model provenance, integrity, dependency auditing,
HuggingFace model repository scanning, adversarial embedding detection,
and live vulnerability scanning (OSV/NVD, typosquatting, dependency confusion).
"""

from .dependency import DependencyAuditor
from .hf_scanner import HFRemoteScanner
from .hubness_detector import (
    AdversarialHubnessScanner,
    ConceptAwareHubnessDetector,
    HubnessDetector,
    ModalityAwareHubnessDetector,
)
from .live_scanner import LiveDependencyScanner, OSVClient, TyposquatDetector
from .provenance import ProvenanceVerifier
from .securebert2 import (
    SecureBERTModelSpec,
    get_securebert2_model,
    securebert2_catalog,
    securebert2_eval_fixtures,
    securebert2_model_ids,
    validate_securebert2_model_id,
)

HFModelScanner = HFRemoteScanner

__all__ = [
    "ProvenanceVerifier", "DependencyAuditor", "HFModelScanner",
    "HFRemoteScanner",
    "AdversarialHubnessScanner", "HubnessDetector",
    "ConceptAwareHubnessDetector", "ModalityAwareHubnessDetector",
    "LiveDependencyScanner", "OSVClient", "TyposquatDetector",
    "SecureBERTModelSpec", "securebert2_catalog", "securebert2_model_ids",
    "get_securebert2_model", "validate_securebert2_model_id",
    "securebert2_eval_fixtures",
]
