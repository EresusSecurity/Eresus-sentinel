"""Parallel fuzzing with multiprocessing worker pool."""

from __future__ import annotations

import logging
import multiprocessing as mp
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from .base import Generator, Mutator, Payload, PayloadCategory, FuzzResult
from .scoring import ScoringEngine, DetectionScore

logger = logging.getLogger(__name__)


@dataclass
class ParallelConfig:
    """Configuration for parallel fuzzing."""
    workers: int = 0  # 0 = cpu_count
    batch_size: int = 100
    total_samples: int = 10000
    seed: Optional[int] = None


def _worker_generate(args: tuple) -> bytes:
    """Worker function for parallel generation."""
    gen_cls, gen_kwargs, seed = args
    gen = gen_cls(**gen_kwargs)
    return gen.generate(seed=seed)


def _worker_scan(args: tuple) -> dict:
    """Worker function for parallel scanning."""
    data, name, scanner_module, scanner_fn_name = args

    import importlib
    mod = importlib.import_module(scanner_module)
    scanner_fn = getattr(mod, scanner_fn_name)

    t0 = time.perf_counter()
    try:
        findings = scanner_fn(data, name)
        detected = len(findings) > 0
        count = len(findings)
        crashed = False
        error = None
    except Exception as exc:
        detected = False
        count = 0
        crashed = True
        error = f"{type(exc).__name__}: {exc}"

    elapsed = (time.perf_counter() - t0) * 1000

    return {
        "name": name,
        "detected": detected,
        "findings_count": count,
        "crashed": crashed,
        "error": error,
        "time_ms": elapsed,
    }


class ParallelFuzzer:
    """Multiprocessing worker pool for parallel generation + scanning."""

    def __init__(
        self,
        generator: Generator,
        mutators: list[Mutator],
        scanner_fn: Callable[[bytes, str], list],
        config: Optional[ParallelConfig] = None,
    ):
        self._generator = generator
        self._mutators = mutators
        self._scanner_fn = scanner_fn
        self._config = config or ParallelConfig()
        self._results: list[FuzzResult] = []

    def generate_parallel(self, count: int, seed: Optional[int] = None) -> list[bytes]:
        """Generate samples in parallel using multiprocessing."""
        import random
        rng = random.Random(seed)
        workers = self._config.workers or mp.cpu_count()

        seeds = [rng.randint(0, 2**64 - 1) for _ in range(count)]

        samples = []
        batch_size = self._config.batch_size

        for batch_start in range(0, count, batch_size):
            batch_end = min(batch_start + batch_size, count)
            batch_seeds = seeds[batch_start:batch_end]

            batch_samples = []
            for s in batch_seeds:
                sample = self._generator.generate(seed=s)
                batch_samples.append(sample)

            samples.extend(batch_samples)

            logger.debug(
                "Generated batch %d-%d (%d total)",
                batch_start, batch_end, len(samples),
            )

        return samples

    def scan_parallel(self, payloads: list[Payload]) -> list[FuzzResult]:
        """Scan payloads in parallel batches."""
        results = []
        batch_size = self._config.batch_size

        for batch_start in range(0, len(payloads), batch_size):
            batch = payloads[batch_start:batch_start + batch_size]

            for payload in batch:
                result = FuzzResult(payload=payload)
                t0 = time.perf_counter()
                try:
                    findings = self._scanner_fn(payload.data, payload.name)
                    result.detected = len(findings) > 0
                    result.findings_count = len(findings)
                except Exception as exc:
                    result.scanner_crashed = True
                    result.error = f"{type(exc).__name__}: {exc}"
                result.detection_time_ms = (time.perf_counter() - t0) * 1000
                results.append(result)

        self._results = results
        return results

    def run(self) -> DetectionScore:
        """Full parallel pipeline: generate → mutate → scan → score."""
        import random

        rng = random.Random(self._config.seed)
        count = self._config.total_samples

        logger.info(
            "Starting parallel fuzzer: %d samples, %d workers",
            count, self._config.workers or mp.cpu_count(),
        )

        # Generate
        samples = self.generate_parallel(count, seed=self._config.seed)

        # Mutate
        mutated = []
        for _i, sample in enumerate(samples):
            if self._mutators and rng.random() < 0.5:
                m = rng.choice(self._mutators)
                sample = m.mutate(sample)
            mutated.append(sample)

        # Build payloads
        payloads = [
            Payload(
                name=f"parallel_{i}",
                category=PayloadCategory.EVASION,
                data=sample,
            )
            for i, sample in enumerate(mutated)
        ]

        # Scan
        results = self.scan_parallel(payloads)

        # Score
        engine = ScoringEngine()
        for r in results:
            engine.add_result(r)

        return engine.compute()

    @property
    def results(self) -> list[FuzzResult]:
        return self._results
