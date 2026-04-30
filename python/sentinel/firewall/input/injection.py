"""
ML-based Prompt Injection Scanner.

Uses a pre-trained DeBERTa classifier to detect prompt injection attempts.
Supports multiple scanning strategies for different prompt structures:
- Uses HuggingFace TextClassificationPipeline
- Multi-strategy scanning: full text, per-sentence, chunked, truncated
- Configurable model and threshold
"""

from __future__ import annotations

import logging
from enum import Enum

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import InputScanner, ScanAction, ScanResult

logger = logging.getLogger(__name__)

# Default model for prompt injection detection
DEFAULT_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"


class MatchStrategy(str, Enum):
    """
    Scanning strategy for prompt analysis.

    FULL: Classify the entire prompt at once.
    SENTENCE: Split into sentences and classify each.
    CHUNKS: Split into overlapping chunks and classify each.
    TRUNCATE_HEAD: Classify the last N tokens (skip system prefix).
    TRUNCATE_TAIL: Classify the first N tokens only.
    """
    FULL = "full"
    SENTENCE = "sentence"
    CHUNKS = "chunks"
    TRUNCATE_HEAD = "truncate_head"
    TRUNCATE_TAIL = "truncate_tail"


class PromptInjectionScanner(InputScanner):
    """
    ML-based prompt injection detector using a text classification model.

    This scanner loads a HuggingFace model (default: DeBERTa-v3) trained
    to distinguish legitimate prompts from injection attacks.

    Multi-strategy modes:
    - FULL: classify entire prompt — fast but misses buried injection
    - SENTENCE: split into sentences — catches injection hidden in context
    - CHUNKS: overlapping windows — for very long prompts
    - TRUNCATE_HEAD/TAIL: focus on edges where injection is commonly placed

    NOTE: Requires `transformers` and `torch` packages.
    Falls back to heuristic-only mode if unavailable.
    """

    def __init__(
        self,
        model_path: str = DEFAULT_MODEL,
        threshold: float = 0.85,
        strategy: MatchStrategy = MatchStrategy.FULL,
        chunk_size: int = 512,
        chunk_overlap: int = 64,
        use_onnx: bool = False,
    ):
        """
        Args:
            model_path: HuggingFace model identifier or local path.
            threshold: Classification threshold (0.0-1.0). Higher = fewer false positives.
            strategy: Scanning strategy to use.
            chunk_size: Token count per chunk (for CHUNKS strategy).
            chunk_overlap: Overlap between chunks (for CHUNKS strategy).
            use_onnx: Use ONNX runtime for faster inference.
        """
        self._model_path = model_path
        self._threshold = threshold
        self._strategy = strategy
        self._chunk_size = chunk_size
        self._chunk_overlap = chunk_overlap
        self._use_onnx = use_onnx
        self._classifier = None
        self._loaded = False

    def _ensure_loaded(self) -> bool:
        """Lazy-load the classification model."""
        if self._loaded:
            return self._classifier is not None

        self._loaded = True
        try:
            from transformers import (
                AutoModelForSequenceClassification,
                AutoTokenizer,
                TextClassificationPipeline,
            )

            tokenizer = AutoTokenizer.from_pretrained(self._model_path)
            model = AutoModelForSequenceClassification.from_pretrained(self._model_path)

            self._classifier = TextClassificationPipeline(
                model=model,
                tokenizer=tokenizer,
                top_k=None,
                truncation=True,
                max_length=512,
            )
            logger.info("Loaded injection classifier: %s", self._model_path)
            return True

        except ImportError:
            logger.warning(
                "transformers/torch not available. "
                "PromptInjectionScanner will not run. "
                "Install: pip install transformers torch"
            )
            return False
        except Exception as e:
            logger.error("Failed to load injection classifier: %s", e)
            return False

    def scan(self, prompt: str) -> ScanResult:
        """
        Scan a prompt for injection using the ML classifier.

        Falls back to PASS if the model cannot be loaded.
        """
        if not prompt or len(prompt.strip()) < 3:
            return ScanResult(
                sanitized=prompt,
                action=ScanAction.PASS,
                risk_score=0.0,
            )

        if not self._ensure_loaded():
            # Cannot load model — return PASS with a warning
            logger.debug("ML classifier unavailable, skipping injection scan")
            return ScanResult(
                sanitized=prompt,
                action=ScanAction.PASS,
                risk_score=0.0,
            )

        # Apply strategy
        if self._strategy == MatchStrategy.FULL:
            max_score = self._classify_full(prompt)
        elif self._strategy == MatchStrategy.SENTENCE:
            max_score = self._classify_sentences(prompt)
        elif self._strategy == MatchStrategy.CHUNKS:
            max_score = self._classify_chunks(prompt)
        elif self._strategy == MatchStrategy.TRUNCATE_HEAD:
            max_score = self._classify_truncated(prompt, head=True)
        elif self._strategy == MatchStrategy.TRUNCATE_TAIL:
            max_score = self._classify_truncated(prompt, head=False)
        else:
            max_score = self._classify_full(prompt)

        if max_score < self._threshold:
            return ScanResult(
                sanitized=prompt,
                action=ScanAction.PASS,
                risk_score=max_score,
            )

        # Detection!
        severity = Severity.CRITICAL if max_score > 0.95 else Severity.HIGH

        finding = Finding.firewall_input(
            rule_id="FIREWALL-INPUT-001",
            title="Prompt injection detected (ML classifier)",
            description=(
                f"ML classifier detected prompt injection with "
                f"{max_score:.1%} confidence using {self._strategy.value} strategy."
            ),
            severity=severity,
            confidence=max_score,
            target="<prompt>",
            evidence=f"Classifier: {self._model_path}, Score: {max_score:.4f}, "
                     f"Threshold: {self._threshold}, Strategy: {self._strategy.value}",
            cwe_ids=["CWE-77"],
            tags=[
                "owasp:llm01",
                "avid-effect:security:S0403",
                "quality:Security:PromptStability",
            ],
            remediation=(
                "Reject or sanitize the input. Review for embedded instructions "
                "that attempt to override system behavior."
            ),
        )

        return ScanResult(
            sanitized=prompt,
            action=ScanAction.BLOCK,
            risk_score=max_score,
            findings=[finding],
        )

    # ─── Strategy Implementations ─────────────────────────────

    def _classify_full(self, text: str) -> float:
        """Classify the full text at once."""
        return self._get_injection_score(text)

    def _classify_sentences(self, text: str) -> float:
        """Split into sentences and classify each. Return max score."""
        import re
        sentences = re.split(r"[.!?\n]+", text)
        sentences = [s.strip() for s in sentences if len(s.strip()) > 5]

        if not sentences:
            return self._classify_full(text)

        scores = [self._get_injection_score(s) for s in sentences]
        return max(scores) if scores else 0.0

    def _classify_chunks(self, text: str) -> float:
        """Split into overlapping chunks and classify each."""
        chunks = []
        step = self._chunk_size - self._chunk_overlap
        for i in range(0, len(text), max(1, step)):
            chunk = text[i:i + self._chunk_size]
            if len(chunk) > 10:
                chunks.append(chunk)

        if not chunks:
            return self._classify_full(text)

        scores = [self._get_injection_score(c) for c in chunks]
        return max(scores) if scores else 0.0

    def _classify_truncated(self, text: str, head: bool) -> float:
        """Classify only the head or tail of the text."""
        max_chars = self._chunk_size * 4  # Approximate char count
        if head:
            truncated = text[-max_chars:] if len(text) > max_chars else text
        else:
            truncated = text[:max_chars] if len(text) > max_chars else text

        return self._get_injection_score(truncated)

    def _get_injection_score(self, text: str) -> float:
        """Get the injection probability score from the classifier."""
        if not self._classifier:
            return 0.0

        try:
            results = self._classifier(text)
            for result in results:
                if isinstance(result, list):
                    for item in result:
                        if item.get("label", "").upper() == "INJECTION":
                            return item["score"]
                elif isinstance(result, dict):
                    if result.get("label", "").upper() == "INJECTION":
                        return result["score"]
            return 0.0
        except Exception as e:
            logger.warning("Classification error: %s", e)
            return 0.0
