"""ML classifier for prompt injection using transformers (PyTorch/ONNX)."""

from __future__ import annotations

import logging
from typing import Optional

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import InputScanner, ScanResult, ScanAction

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"
INJECTION_LABEL = "INJECTION"
SAFE_LABEL = "SAFE"


class MLClassifier(InputScanner):
    """Transformer-based prompt injection classifier with ONNX support."""

    def __init__(
        self,
        model_path: str = DEFAULT_MODEL,
        threshold: float = 0.85,
        injection_label: str = INJECTION_LABEL,
        use_onnx: bool = False,
        max_length: int = 512,
    ):
        self._model_path = model_path
        self._threshold = threshold
        self._injection_label = injection_label.upper()
        self._use_onnx = use_onnx
        self._max_length = max_length
        self._pipeline = None
        self._loaded = False
        self._available = False

    @property
    def is_available(self) -> bool:
        """Whether ML dependencies are available."""
        if not self._loaded:
            self._try_load()
        return self._available

    def _try_load(self) -> None:
        """Load model: ONNX if requested and available, else PyTorch."""
        if self._loaded:
            return
        self._loaded = True

        try:
            from transformers import (
                AutoTokenizer,
                TextClassificationPipeline,
            )

            tokenizer = AutoTokenizer.from_pretrained(self._model_path)

            model = None
            runtime = "pytorch"

            # Try ONNX runtime first (if requested)
            if self._use_onnx:
                try:
                    from optimum.onnxruntime import ORTModelForSequenceClassification

                    model = ORTModelForSequenceClassification.from_pretrained(
                        self._model_path,
                        export=True,
                    )
                    runtime = "onnx"
                    logger.info(
                        "MLClassifier using ONNX runtime for %s",
                        self._model_path,
                    )
                except ImportError:
                    logger.info(
                        "optimum not installed, falling back to PyTorch. "
                        "For ONNX acceleration: pip install optimum[onnxruntime]"
                    )
                except Exception as onnx_exc:
                    logger.warning(
                        "ONNX export failed, falling back to PyTorch: %s",
                        onnx_exc,
                    )

            # Fallback to PyTorch
            if model is None:
                from transformers import AutoModelForSequenceClassification

                model = AutoModelForSequenceClassification.from_pretrained(
                    self._model_path
                )

            self._pipeline = TextClassificationPipeline(
                model=model,
                tokenizer=tokenizer,
                top_k=None,
                truncation=True,
                max_length=self._max_length,
            )
            self._available = True
            self._runtime = runtime
            logger.info(
                "MLClassifier loaded: %s (runtime=%s)",
                self._model_path,
                runtime,
            )

        except ImportError:
            logger.warning(
                "transformers/torch not installed. "
                "MLClassifier layer will be skipped. "
                "Install: pip install transformers torch"
            )
        except Exception as exc:
            logger.error("Failed to load MLClassifier: %s", exc)

    def scan(self, prompt: str) -> ScanResult:
        """Classify a single prompt."""
        if not prompt or len(prompt.strip()) < 3:
            return ScanResult(
                sanitized=prompt,
                action=ScanAction.PASS,
                risk_score=0.0,
            )

        if not self.is_available:
            return ScanResult(
                sanitized=prompt,
                action=ScanAction.PASS,
                risk_score=0.0,
            )

        score = self._classify(prompt)

        if score < self._threshold:
            return ScanResult(
                sanitized=prompt,
                action=ScanAction.PASS,
                risk_score=score,
            )

        severity = Severity.CRITICAL if score > 0.95 else Severity.HIGH

        finding = Finding.firewall_input(
            rule_id="FIREWALL-INPUT-020",
            title="Prompt injection detected (ML classifier)",
            description=(
                f"ML classifier '{self._model_path}' identified "
                f"prompt injection with {score:.1%} confidence."
            ),
            severity=severity,
            confidence=score,
            target="<prompt>",
            evidence=(
                f"Model: {self._model_path}, Score: {score:.4f}, "
                f"Threshold: {self._threshold}"
            ),
            cwe_ids=["CWE-77"],
            tags=["owasp:llm01", "layer:ml_classifier"],
            remediation=(
                "Review prompt for injection. The ML classifier detected "
                "patterns consistent with prompt override attempts."
            ),
        )

        return ScanResult(
            sanitized=prompt,
            action=ScanAction.BLOCK,
            risk_score=score,
            findings=[finding],
        )

    def scan_batch(self, prompts: list[str]) -> list[ScanResult]:
        """Classify multiple prompts in a single batch."""
        if not self.is_available:
            return [
                ScanResult(sanitized=p, action=ScanAction.PASS, risk_score=0.0)
                for p in prompts
            ]

        scores = self._classify_batch(prompts)
        results = []

        for prompt, score in zip(prompts, scores):
            if score < self._threshold:
                results.append(ScanResult(
                    sanitized=prompt,
                    action=ScanAction.PASS,
                    risk_score=score,
                ))
            else:
                severity = Severity.CRITICAL if score > 0.95 else Severity.HIGH
                finding = Finding.firewall_input(
                    rule_id="FIREWALL-INPUT-020",
                    title="Prompt injection detected (ML classifier — batch)",
                    description=(
                        f"ML classifier detected injection with "
                        f"{score:.1%} confidence."
                    ),
                    severity=severity,
                    confidence=score,
                    target="<prompt>",
                    evidence=f"Score: {score:.4f}",
                    cwe_ids=["CWE-77"],
                    tags=["owasp:llm01", "layer:ml_classifier"],
                )
                results.append(ScanResult(
                    sanitized=prompt,
                    action=ScanAction.BLOCK,
                    risk_score=score,
                    findings=[finding],
                ))

        return results

    def _classify(self, text: str) -> float:
        """Get injection probability for a single text."""
        if not self._pipeline:
            return 0.0
        try:
            results = self._pipeline(text)
            return self._extract_score(results)
        except Exception as exc:
            logger.warning("ML classification error: %s", exc)
            return 0.0

    def _classify_batch(self, texts: list[str]) -> list[float]:
        """Get injection probabilities for a batch of texts."""
        if not self._pipeline:
            return [0.0] * len(texts)
        try:
            batch_results = self._pipeline(texts)
            return [self._extract_score(r) for r in batch_results]
        except Exception as exc:
            logger.warning("Batch classification error: %s", exc)
            return [0.0] * len(texts)

    def _extract_score(self, results) -> float:
        """Extract injection score from pipeline output."""
        if isinstance(results, list):
            for item in results:
                if isinstance(item, list):
                    for sub in item:
                        if sub.get("label", "").upper() == self._injection_label:
                            return sub["score"]
                elif isinstance(item, dict):
                    if item.get("label", "").upper() == self._injection_label:
                        return item["score"]
        return 0.0

    def warmup(self) -> bool:
        """Pre-load the model (for startup health checks)."""
        if not self.is_available:
            return False
        self._classify("Hello, how are you?")
        logger.info("MLClassifier warmed up successfully.")
        return True
