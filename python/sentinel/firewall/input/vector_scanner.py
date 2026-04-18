"""Vector similarity scanner — TF-IDF cosine similarity against known attack corpus."""

from __future__ import annotations

import logging
import math
import re
from collections import Counter
from typing import Optional

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import InputScanner, ScanResult, ScanAction

logger = logging.getLogger(__name__)


def _tokenize(text: str) -> list[str]:
    """Simple whitespace + punctuation tokenizer."""
    return re.findall(r"\b\w+\b", text.lower())


def _cosine_similarity(vec_a: dict[str, float], vec_b: dict[str, float]) -> float:
    """Compute cosine similarity between two sparse vectors."""
    if not vec_a or not vec_b:
        return 0.0

    keys = set(vec_a.keys()) & set(vec_b.keys())
    if not keys:
        return 0.0

    dot = sum(vec_a[k] * vec_b[k] for k in keys)
    mag_a = math.sqrt(sum(v * v for v in vec_a.values()))
    mag_b = math.sqrt(sum(v * v for v in vec_b.values()))

    if mag_a == 0 or mag_b == 0:
        return 0.0

    return dot / (mag_a * mag_b)


class VectorScanner(InputScanner):
    """TF-IDF cosine similarity scanner with adaptive learning."""

    def __init__(
        self,
        threshold: float = 0.65,
        corpus: Optional[list[str]] = None,
        auto_learn: bool = False,
        feedback_log: Optional[str] = None,
    ):
        """
        Args:
            threshold: Cosine similarity threshold (0.0-1.0).
            corpus: List of known attack prompts. If None, uses default corpus.
            auto_learn: If True, automatically add blocked prompts to corpus
                        for adaptive detection (feedback loop).
            feedback_log: Path to JSONL file for persisting learned entries.
        """
        self._threshold = threshold
        self._corpus: list[str] = corpus or []
        self._corpus_vectors: list[dict[str, float]] = []
        self._idf: dict[str, float] = {}
        self._built = False
        self._auto_learn = auto_learn
        self._feedback_log = feedback_log
        self._learned_count = 0

    def add_corpus(self, texts: list[str]) -> None:
        """Add texts to the attack corpus."""
        self._corpus.extend(texts)
        self._built = False

    def build_index(self) -> None:
        """Build the TF-IDF index from the corpus."""
        if not self._corpus:
            self._load_default_corpus()

        if not self._corpus:
            logger.warning("VectorScanner: empty corpus, skipping build.")
            self._built = True
            return

        # Compute IDF
        doc_count = len(self._corpus)
        doc_freq: Counter[str] = Counter()

        tokenized_docs = []
        for doc in self._corpus:
            tokens = _tokenize(doc)
            tokenized_docs.append(tokens)
            unique_tokens = set(tokens)
            for token in unique_tokens:
                doc_freq[token] += 1

        self._idf = {
            token: math.log((doc_count + 1) / (freq + 1)) + 1
            for token, freq in doc_freq.items()
        }

        # Compute TF-IDF vectors for corpus
        self._corpus_vectors = []
        for tokens in tokenized_docs:
            vector = self._tfidf_vector(tokens)
            self._corpus_vectors.append(vector)

        self._built = True
        logger.info(
            "VectorScanner: built index with %d documents, %d terms",
            len(self._corpus), len(self._idf)
        )

    def _tfidf_vector(self, tokens: list[str]) -> dict[str, float]:
        """Compute TF-IDF vector for a token list."""
        tf = Counter(tokens)
        total = len(tokens) if tokens else 1

        vector = {}
        for token, count in tf.items():
            tf_score = count / total
            idf_score = self._idf.get(token, 1.0)
            vector[token] = tf_score * idf_score

        return vector

    def _load_default_corpus(self) -> None:
        """Load attack corpus from payloads YAML files."""
        import os

        try:
            import yaml
        except ImportError:
            logger.warning("PyYAML not available. VectorScanner uses empty corpus.")
            return

        payloads_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "..", "..", "..",
            "payloads"
        )
        payloads_dir = os.path.normpath(payloads_dir)

        if not os.path.isdir(payloads_dir):
            logger.debug("Payloads directory not found: %s", payloads_dir)
            return

        for filename in ["jailbreak.yaml", "injection.yaml", "agentic_probes.yaml"]:
            filepath = os.path.join(payloads_dir, filename)
            if not os.path.isfile(filepath):
                continue

            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)

                if isinstance(data, dict):
                    for category, items in data.items():
                        if isinstance(items, list):
                            for item in items:
                                if isinstance(item, dict) and "prompt" in item:
                                    self._corpus.append(item["prompt"])
                                elif isinstance(item, str):
                                    self._corpus.append(item)

                logger.debug("Loaded corpus from %s", filename)

            except Exception as exc:
                logger.warning("Failed to load corpus from %s: %s", filename, exc)

        logger.info(
            "VectorScanner: loaded %d attack prompts from payloads/",
            len(self._corpus)
        )

    def scan(self, prompt: str) -> ScanResult:
        """Scan a prompt using vector similarity."""
        if not prompt or len(prompt.strip()) < 5:
            return ScanResult(
                sanitized=prompt,
                action=ScanAction.PASS,
                risk_score=0.0,
            )

        if not self._built:
            self.build_index()

        if not self._corpus_vectors:
            return ScanResult(
                sanitized=prompt,
                action=ScanAction.PASS,
                risk_score=0.0,
            )

        # Vectorize the input
        tokens = _tokenize(prompt)
        prompt_vector = self._tfidf_vector(tokens)

        # Find max similarity
        max_sim = 0.0
        best_idx = -1
        for i, corpus_vec in enumerate(self._corpus_vectors):
            sim = _cosine_similarity(prompt_vector, corpus_vec)
            if sim > max_sim:
                max_sim = sim
                best_idx = i

        if max_sim < self._threshold:
            return ScanResult(
                sanitized=prompt,
                action=ScanAction.PASS,
                risk_score=max_sim,
            )

        # Get the matching corpus entry for evidence
        matched_text = ""
        if 0 <= best_idx < len(self._corpus):
            matched_text = self._corpus[best_idx][:200]

        if max_sim > 0.85:
            severity = Severity.HIGH
            action = ScanAction.BLOCK
        elif max_sim > 0.7:
            severity = Severity.MEDIUM
            action = ScanAction.WARN
        else:
            severity = Severity.LOW
            action = ScanAction.WARN

        finding = Finding.firewall_input(
            rule_id="FIREWALL-INPUT-030",
            title="Prompt matches known injection pattern (vector similarity)",
            description=(
                f"Input has {max_sim:.1%} cosine similarity to a known "
                f"injection attack in the corpus."
            ),
            severity=severity,
            confidence=max_sim,
            target="<prompt>",
            evidence=(
                f"Similarity: {max_sim:.4f}, "
                f"Threshold: {self._threshold}, "
                f"Closest match: '{matched_text}'"
            ),
            cwe_ids=["CWE-77"],
            tags=["owasp:llm01", "layer:vector_similarity"],
            remediation=(
                "Prompt closely resembles a known injection attack. "
                "Review intent and consider blocking."
            ),
        )

        # Feedback loop: auto-learn blocked prompts
        if self._auto_learn and action == ScanAction.BLOCK:
            self._learn_from_detection(prompt, max_sim)

        return ScanResult(
            sanitized=prompt,
            action=action,
            risk_score=max_sim,
            findings=[finding],
        )



    def learn(self, text: str, metadata: Optional[dict] = None) -> None:
        """Add a confirmed injection to the corpus at runtime."""
        if text in self._corpus:
            logger.debug("Text already in corpus, skipping learn.")
            return

        self._corpus.append(text)

        # Incrementally update index (no full rebuild)
        tokens = _tokenize(text)
        vector = self._tfidf_vector(tokens)
        self._corpus_vectors.append(vector)

        self._learned_count += 1
        logger.info(
            "VectorScanner: learned new entry (total corpus: %d, learned: %d)",
            len(self._corpus),
            self._learned_count,
        )

        # Persist to feedback log if configured
        if self._feedback_log and metadata:
            self._write_feedback(text, metadata)

    def _learn_from_detection(self, prompt: str, similarity: float) -> None:
        """Auto-learn blocked prompt if not near-duplicate (< 0.95 sim)."""
        if similarity >= 0.95:
            # Too similar to existing entry, skip to avoid duplicates
            return

        self.learn(prompt, metadata={
            "source": "auto_learn",
            "similarity": similarity,
            "action": "BLOCK",
        })

    def _write_feedback(self, text: str, metadata: dict) -> None:
        """Persist learned entries to feedback log file."""
        if not self._feedback_log:
            return

        try:
            import json
            import time

            entry = {
                "timestamp": time.time(),
                "text": text[:500],
                "metadata": metadata,
            }

            with open(self._feedback_log, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")

        except Exception as exc:
            logger.warning("Failed to write feedback log: %s", exc)

    @property
    def corpus_size(self) -> int:
        """Current corpus size including learned entries."""
        return len(self._corpus)

    @property
    def learned_count(self) -> int:
        """Number of entries learned at runtime."""
        return self._learned_count

    def export_learned(self) -> list[str]:
        """Export entries learned during this session."""
        if self._learned_count == 0:
            return []
        return self._corpus[-self._learned_count:]

    def corpus_drift_report(self) -> dict:
        """Compute corpus quality/drift metrics.

        Returns dict with:
          - avg_similarity: average pairwise similarity (high = redundant corpus)
          - unique_token_ratio: vocabulary diversity
          - corpus_size: total entries
          - learned_ratio: % of corpus from runtime learning
        """
        if not self._built or not self._corpus_vectors:
            return {"error": "index not built"}

        n = len(self._corpus_vectors)

        # Sample pairwise similarity (cap at 200 pairs for perf)
        import random
        sim_sum = 0.0
        sample_count = 0
        max_pairs = min(200, n * (n - 1) // 2)

        if n > 1:
            indices = list(range(n))
            for _ in range(max_pairs):
                i, j = random.sample(indices, 2)
                sim_sum += _cosine_similarity(
                    self._corpus_vectors[i], self._corpus_vectors[j]
                )
                sample_count += 1

        avg_sim = sim_sum / sample_count if sample_count > 0 else 0.0

        # Token diversity
        all_tokens = set()
        total_tokens = 0
        for doc in self._corpus:
            tokens = _tokenize(doc)
            all_tokens.update(tokens)
            total_tokens += len(tokens)

        unique_ratio = len(all_tokens) / total_tokens if total_tokens > 0 else 0.0

        return {
            "avg_pairwise_similarity": round(avg_sim, 4),
            "unique_token_ratio": round(unique_ratio, 4),
            "corpus_size": n,
            "learned_count": self._learned_count,
            "learned_ratio": round(self._learned_count / n, 4) if n > 0 else 0.0,
            "vocabulary_size": len(all_tokens),
            "health": "good" if avg_sim < 0.5 and unique_ratio > 0.3 else "review",
        }
