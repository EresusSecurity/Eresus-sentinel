"""Pickle-specific self-test pipeline."""

from __future__ import annotations

import logging
import random
import time
from typing import Optional

from ..base import FuzzConfig, Payload, PayloadCategory
from ..pipeline import FuzzPipeline
from ..scoring import DetectionScore
from .generator import PickleGenerator
from .mutators import PayloadInjectMutator, PickleMutator
from .payloads import PicklePayloadFactory

logger = logging.getLogger(__name__)


class PickleSelfTest:
    """Self-test: generates pickles and validates Sentinel's scanner.

    Three phases:
      1. Known Payloads: Run all pre-built adversarial templates
      2. Generated Samples: Random structure-aware pickles (benign baseline)
      3. Mutated Samples: Take benign pickles, inject malicious payloads,
         then verify detection

    The result is a DetectionScore with:
      - TPR: should be ≥ 95%
      - FPR: should be ≤ 5%
      - Bypass list: specific payloads the scanner missed
      - Crash list: payloads that crashed the scanner
    """

    def __init__(
        self,
        config: Optional[FuzzConfig] = None,
        seed: Optional[int] = None,
    ):
        self._config = config or FuzzConfig(samples=500)
        self._seed = seed or int(time.time())
        self._rng = random.Random(self._seed)

    def run(self, output_dir: Optional[str] = None) -> DetectionScore:
        """Run the full self-test pipeline."""
        # Late import to avoid circular dependencies
        from ...artifact.pickle_scanner import PickleScanner

        scanner = PickleScanner()

        def scanner_fn(data: bytes, source: str):
            return scanner.scan_bytes(data, source=source)

        # Collect all payloads
        all_payloads: list[Payload] = []

        # Phase 1: Known adversarial payloads
        logger.info("Phase 1: Testing %d known adversarial payloads...",
                     len(PicklePayloadFactory.malicious_payloads()))
        all_payloads.extend(PicklePayloadFactory.all_payloads())

        # Phase 2: Generated benign pickles (false positive test)
        # Use protocol 2-5 only — protocol 0/1 are legacy and legitimately
        # flagged by ARTIFACT-015 as a security concern (not a false positive).
        n_benign = self._config.samples // 3
        logger.info("Phase 2: Generating %d random benign pickles...", n_benign)
        benign_protos = [2, 3, 4, 5]
        for proto in benign_protos:
            gen = PickleGenerator(
                protocol=proto,
                min_opcodes=5,
                max_opcodes=100,
            )
            per_proto = max(1, n_benign // len(benign_protos))
            for i in range(per_proto):
                seed = self._rng.randint(0, 2**64 - 1)
                try:
                    data = gen.generate(seed=seed)
                    all_payloads.append(Payload(
                        name=f"generated_benign_p{proto}_{i}",
                        category=PayloadCategory.BENIGN,
                        data=data,
                        description=f"Random generated pickle (protocol {proto})",
                        severity_expected="NONE",
                        metadata={"protocol": proto, "seed": seed},
                    ))
                except Exception as exc:
                    logger.debug("Generator error (proto %d, seed %d): %s", proto, seed, exc)

        # Phase 3: Mutated malicious pickles (injection test)
        n_mutated = self._config.samples // 3
        logger.info("Phase 3: Generating %d mutated malicious pickles...", n_mutated)
        injector = PayloadInjectMutator(seed=self._seed)
        mutator = PickleMutator(seed=self._seed)

        for i in range(n_mutated):
            # Start with a benign pickle
            proto = self._rng.randint(2, 5)
            gen = PickleGenerator(protocol=proto, min_opcodes=5, max_opcodes=50)
            try:
                base = gen.generate(seed=self._rng.randint(0, 2**64 - 1))
                # Inject malicious payload
                injected = injector.mutate(base)
                all_payloads.append(Payload(
                    name=f"mutated_injected_{i}",
                    category=PayloadCategory.DESERIALIZATION,
                    data=injected,
                    description="Benign pickle with injected malicious GLOBAL+REDUCE",
                    severity_expected="CRITICAL",
                    metadata={"protocol": proto, "mutation": "payload_inject"},
                ))
            except Exception as exc:
                logger.debug("Mutation error (iter %d): %s", i, exc)

        # Phase 4: Mutation-only variants (structure fuzzing)
        n_mutations = self._config.samples // 3
        logger.info("Phase 4: Generating %d mutation variants...", n_mutations)
        for mal_payload in PicklePayloadFactory.malicious_payloads()[:10]:
            for j in range(max(1, n_mutations // 10)):
                try:
                    mutated_data = mutator.mutate(mal_payload.data)
                    all_payloads.append(Payload(
                        name=f"mutated_{mal_payload.name}_{j}",
                        category=mal_payload.category,
                        data=mutated_data,
                        description=f"Mutated variant of {mal_payload.name}",
                        severity_expected=mal_payload.severity_expected,
                        metadata={"base_payload": mal_payload.name},
                    ))
                except Exception as exc:
                    logger.debug("Mutation error (%s, iter %d): %s", mal_payload.name, j, exc)

        # Run pipeline
        config = FuzzConfig(
            output_dir=output_dir or self._config.output_dir,
            store_results=True,
        )
        pipeline = FuzzPipeline(scanner_fn=scanner_fn, config=config)
        score = pipeline.run(all_payloads)

        # Log summary
        logger.info("=" * 60)
        logger.info("SELF-TEST RESULTS")
        logger.info("=" * 60)
        logger.info("Total samples:    %d", score.total_samples)
        logger.info("Malicious:        %d", score.malicious_samples)
        logger.info("Benign:           %d", score.benign_samples)
        logger.info("")
        logger.info("True Positive Rate:  %.1f%%", score.tpr * 100)
        logger.info("False Positive Rate: %.1f%%", score.fpr * 100)
        logger.info("Precision:           %.1f%%", score.precision * 100)
        logger.info("F1 Score:            %.3f", score.f1)
        logger.info("Bypass Rate:         %.1f%%", score.bypass_rate * 100)
        logger.info("Scanner Crashes:     %d", score.scanner_crashes)
        logger.info("")
        if score.bypassed_payloads:
            logger.warning(
                "⚠ BYPASSED PAYLOADS (%d):", len(score.bypassed_payloads)
            )
            for name in score.bypassed_payloads[:20]:
                logger.warning("  - %s", name)
        if score.false_positive_payloads:
            logger.warning(
                "⚠ FALSE POSITIVES (%d):", len(score.false_positive_payloads)
            )
            for name in score.false_positive_payloads[:20]:
                logger.warning("  - %s", name)
        logger.info("=" * 60)

        return score
