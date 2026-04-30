from sentinel.supply_chain.hubness_detector import (
    AdversarialHubnessScanner,
    AnomalyType,
    EmbeddingVector,
    HubnessDetector,
)
from sentinel.supply_chain.securebert2 import (
    get_securebert2_model,
    securebert2_catalog,
    securebert2_eval_fixtures,
    securebert2_model_ids,
    validate_securebert2_model_id,
)


def _hub_vectors():
    return [
        EmbeddingVector("hub", [0.0, 0.0, 0.0], metadata={"concept": "vuln", "modality": "text"}),
        EmbeddingVector("v1", [1.0, 0.0, 0.0], metadata={"concept": "vuln", "modality": "text"}),
        EmbeddingVector("v2", [-1.0, 0.0, 0.0], metadata={"concept": "vuln", "modality": "text"}),
        EmbeddingVector("v3", [0.0, 1.0, 0.0], metadata={"concept": "vuln", "modality": "text"}),
        EmbeddingVector("v4", [0.0, -1.0, 0.0], metadata={"concept": "vuln", "modality": "text"}),
        EmbeddingVector("v5", [0.0, 0.0, 1.0], metadata={"concept": "vuln", "modality": "text"}),
        EmbeddingVector("v6", [0.0, 0.0, -1.0], metadata={"concept": "vuln", "modality": "text"}),
    ]


def test_hubness_robust_concept_and_modality_modes():
    vectors = _hub_vectors()

    robust = HubnessDetector(k=1, hubness_threshold=2.0, robust_z_threshold=2.0).detect(vectors)
    scanner = AdversarialHubnessScanner()
    concept = scanner.concept_scan(vectors)
    modality = scanner.modality_scan(vectors)

    assert any(finding.vector_ids == ["hub"] for finding in robust)
    assert any("robust_z" in finding.details for finding in robust)
    assert any(finding.anomaly_type is AnomalyType.CONCEPT_HUBNESS for finding in concept)
    assert any(finding.anomaly_type is AnomalyType.MODALITY_HUBNESS for finding in modality)


def test_securebert2_catalog_is_offline_and_task_mapped():
    catalog = securebert2_catalog()

    assert len(catalog) == 5
    assert "cisco-ai/SecureBERT2.0-base" in securebert2_model_ids()
    assert validate_securebert2_model_id("CiscoAITeam/SecureBERT2.0-NER")
    spec = get_securebert2_model("code_vulnerability_detection")
    assert spec is not None
    assert spec.model_id.endswith("code-vuln-detection")
    assert securebert2_eval_fixtures("code_vulnerability_detection")
