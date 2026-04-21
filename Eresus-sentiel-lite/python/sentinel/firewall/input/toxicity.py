"""
Eresus Sentinel — Toxicity Scanner.

Detects toxic, hateful, violent, sexual, or harmful content in
prompts/responses using both keyword heuristics and optional
ML classification.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import InputScanner, OutputScanner, ScanResult, ScanAction

logger = logging.getLogger(__name__)

TOXICITY_CATEGORIES = {
    "hate_speech": [
        r"(?i)\b(?:kill\s+all|exterminate|genocide|ethnic\s+cleansing)\b",
        r"(?i)\b(?:racial\s+(?:slur|superiority)|white\s+(?:power|supremac))",
        r"(?i)\b(?:death\s+to\s+(?:all|the))\b",
        r"(?i)\bshould\s+(?:all\s+)?be\s+(?:eliminated|exterminated|eradicated|wiped\s+out|destroyed)\b",
        r"(?i)\b(?:wipe\s+(?:them|out)|eliminate\s+(?:them|all|the))\b",
    ],
    "violence": [
        r"(?i)\b(?:how\s+to\s+(?:make|build|create)\s+(?:a\s+)?(?:\w+\s+)?(?:bomb|explosive|weapon|poison|gun|grenade|mine|ied))\b",
        r"(?i)\b(?:instructions?\s+(?:for|to)\s+(?:kill|murder|assassinate|harm))\b",
        r"(?i)\b(?:step.by.step\s+(?:guide|tutorial)\s+(?:to|for)\s+(?:violence|killing|murder))\b",
        r"(?i)\b(?:how\s+to\s+(?:make|build|create)\b.{0,30}\b(?:bomb|explosive|weapon|poison|gun|grenade))\b",
        r"(?i)\b(?:(?:make|build|create)\s+(?:a\s+)?(?:\w+\s+)?(?:bomb|explosive|weapon))\b.{0,20}\bstep\s+by\s+step\b",
    ],
    "self_harm": [
        r"(?i)\b(?:how\s+to\s+(?:commit\s+)?suicide|ways?\s+to\s+(?:end|take)\s+(?:my|your|one'?s)\s+life)\b",
        r"(?i)\b(?:methods?\s+of\s+self.harm|cutting\s+(?:myself|yourself))\b",
    ],
    "sexual_explicit": [
        r"(?i)\b(?:explicit\s+sexual|pornographic\s+(?:content|material|description))\b",
        r"(?i)\b(?:write\s+(?:me\s+)?(?:erotica|sexual\s+(?:content|story|scene)))\b",
    ],
    "illegal_activity": [
        r"(?i)\b(?:how\s+to\s+(?:hack|steal|forge|counterfeit|synthesize\s+(?:drugs|meth|fentanyl)))\b",
        r"(?i)\b(?:instructions?\s+(?:for|to)\s+(?:break|bypass|pick)\s+(?:into|a)\s+(?:lock|safe|door|car|house))\b",
        r"(?i)\b(?:how\s+to\s+(?:launder|embezzle|smuggle|traffic))\b",
    ],
    "harassment": [
        r"(?i)\b(?:you(?:'re|\s+are)\s+(?:worthless|pathetic|stupid|ugly|disgusting|trash))\b",
        r"(?i)\b(?:nobody\s+(?:loves?|cares?\s+about|wants?)\s+you)\b",
        r"(?i)\b(?:(?:go|you\s+should)\s+(?:die|kill\s+yourself))\b",
    ],
}

_COMPILED_PATTERNS: dict[str, list[re.Pattern]] = {}
for cat, patterns in TOXICITY_CATEGORIES.items():
    _COMPILED_PATTERNS[cat] = [re.compile(p) for p in patterns]


class ToxicityScanner(InputScanner):
    """Detects toxic content via regex heuristics + optional ML (PyTorch/ONNX)."""

    def __init__(
        self,
        threshold: float = 0.7,
        use_ml: bool = False,
        use_onnx: bool = False,
        model_path: str = "unitary/toxic-bert",
        categories: Optional[list[str]] = None,
    ):
        self._threshold = threshold
        self._use_ml = use_ml
        self._use_onnx = use_onnx
        self._model_path = model_path
        self._categories = categories or list(TOXICITY_CATEGORIES.keys())
        self._classifier = None
        self._ml_loaded = False

    def _load_ml(self) -> None:
        if self._ml_loaded:
            return
        self._ml_loaded = True
        if not self._use_ml:
            return
        try:
            from transformers import AutoTokenizer, TextClassificationPipeline

            tokenizer = AutoTokenizer.from_pretrained(self._model_path)
            model = None

            if self._use_onnx:
                try:
                    from optimum.onnxruntime import ORTModelForSequenceClassification
                    model = ORTModelForSequenceClassification.from_pretrained(
                        self._model_path, export=True,
                    )
                    logger.info("ToxicityScanner: ONNX runtime loaded")
                except (ImportError, Exception):
                    logger.info("ToxicityScanner: ONNX unavailable, using PyTorch")

            if model is None:
                from transformers import AutoModelForSequenceClassification
                model = AutoModelForSequenceClassification.from_pretrained(self._model_path)

            self._classifier = TextClassificationPipeline(
                model=model, tokenizer=tokenizer, top_k=None, truncation=True,
            )
            logger.info("ToxicityScanner ML model loaded: %s", self._model_path)
        except ImportError:
            logger.info("transformers not installed, using heuristic-only toxicity detection")
        except Exception as exc:
            logger.warning("Failed to load toxicity ML model: %s", exc)

    def scan(self, prompt: str) -> ScanResult:
        if not prompt or len(prompt.strip()) < 3:
            return ScanResult(sanitized=prompt, action=ScanAction.PASS, risk_score=0.0)

        findings = []
        max_score = 0.0

        # Heuristic scan
        for category in self._categories:
            patterns = _COMPILED_PATTERNS.get(category, [])
            for pattern in patterns:
                match = pattern.search(prompt)
                if match:
                    score = 0.9
                    max_score = max(max_score, score)
                    findings.append(Finding.firewall_input(
                        rule_id="FIREWALL-INPUT-050",
                        title=f"Toxic content detected: {category}",
                        description=(
                            f"Input contains {category.replace('_', ' ')} content "
                            f"matching pattern: '{match.group(0)[:80]}'"
                        ),
                        severity=Severity.HIGH,
                        confidence=score,
                        target="<prompt>",
                        evidence=f"Category: {category}, Match: {match.group(0)[:120]}",
                        cwe_ids=["CWE-1021"],
                        tags=["owasp:llm02", "category:toxicity"],
                        remediation="Block or flag content for human review.",
                    ))
                    break  # One finding per category

        if not findings:
            # Try ML classification if heuristics passed
            if self._use_ml:
                self._load_ml()
                if self._classifier:
                    try:
                        results = self._classifier(prompt[:512])
                        for item in (results if isinstance(results[0], dict) else results[0]):
                            label = item.get("label", "").lower()
                            score = item.get("score", 0.0)
                            if score >= self._threshold and label != "non-toxic" and label != "neutral":
                                max_score = max(max_score, score)
                                findings.append(Finding.firewall_input(
                                    rule_id="FIREWALL-INPUT-051",
                                    title=f"Toxic content detected (ML): {label}",
                                    description=f"ML classifier detected '{label}' with {score:.1%} confidence",
                                    severity=Severity.HIGH,
                                    confidence=score,
                                    target="<prompt>",
                                    evidence=f"Label: {label}, Score: {score:.4f}",
                                    cwe_ids=["CWE-1021"],
                                    tags=["category:toxicity", "layer:ml"],
                                ))
                    except Exception as exc:
                        logger.warning("ML toxicity scan error: %s", exc)

        if not findings:
            return ScanResult(sanitized=prompt, action=ScanAction.PASS, risk_score=0.0)

        action = ScanAction.BLOCK if max_score > 0.8 else ScanAction.WARN
        return ScanResult(
            sanitized=prompt,
            action=action,
            risk_score=max_score,
            findings=findings,
        )


class ToxicityOutputScanner(OutputScanner):
    """Detects toxic content in LLM responses."""

    def __init__(self, threshold: float = 0.7):
        self._input_scanner = ToxicityScanner(threshold=threshold)

    def scan(self, prompt: str, output: str) -> ScanResult:
        return self._input_scanner.scan(output)
