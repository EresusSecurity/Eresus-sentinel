"""Coverage-guided fuzzing engine."""

from __future__ import annotations

import hashlib
import logging
import random
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from .base import FuzzResult, Generator, Mutator, Payload, PayloadCategory

logger = logging.getLogger(__name__)


@dataclass
class CoverageInfo:
    """Tracks code coverage for feedback-driven mutation."""
    total_branches: int = 0
    covered_branches: int = 0
    coverage_map: dict[str, set[int]] = field(default_factory=dict)
    new_coverage_count: int = 0
    plateau_rounds: int = 0

    @property
    def branch_coverage(self) -> float:
        if self.total_branches == 0:
            return 0.0
        return self.covered_branches / self.total_branches

    def merge_coverage(self, file_name: str, lines: set[int]) -> int:
        if file_name not in self.coverage_map:
            self.coverage_map[file_name] = set()
        before = len(self.coverage_map[file_name])
        self.coverage_map[file_name] |= lines
        after = len(self.coverage_map[file_name])
        new = after - before
        self.new_coverage_count += new
        return new

    def to_dict(self) -> dict:
        return {
            "total_branches": self.total_branches,
            "covered_branches": self.covered_branches,
            "branch_coverage": round(self.branch_coverage, 4),
            "files_covered": len(self.coverage_map),
            "total_lines_covered": sum(
                len(v) for v in self.coverage_map.values()
            ),
            "new_coverage_count": self.new_coverage_count,
            "plateau_rounds": self.plateau_rounds,
        }


class CoverageTracker:
    """Wraps coverage.py to track scanner code coverage during fuzzing."""

    def __init__(self, source_dirs: list[str] | None = None):
        self._source_dirs = source_dirs or []
        self._coverage = None
        self._info = CoverageInfo()
        self._seen_hashes: set[str] = set()

    def start(self) -> None:
        try:
            import coverage
            self._coverage = coverage.Coverage(
                source=self._source_dirs or None,
                branch=True,
            )
            self._coverage.start()
        except ImportError:
            logger.warning("coverage.py not installed, running without coverage tracking")
            self._coverage = None

    def stop(self) -> CoverageInfo:
        if self._coverage is None:
            return self._info
        self._coverage.stop()
        self._coverage.save()

        data = self._coverage.get_data()
        for fname in data.measured_files():
            lines = data.lines(fname) or []
            self._info.merge_coverage(fname, set(lines))

        arcs = 0
        for fname in data.measured_files():
            file_arcs = data.arcs(fname)
            if file_arcs:
                arcs += len(file_arcs)
        self._info.total_branches = max(arcs, self._info.total_branches)
        self._info.covered_branches = sum(
            len(v) for v in self._info.coverage_map.values()
        )

        return self._info

    def is_new_coverage(self, data: bytes) -> bool:
        h = hashlib.sha256(data).hexdigest()
        if h in self._seen_hashes:
            return False
        self._seen_hashes.add(h)
        return True

    @property
    def info(self) -> CoverageInfo:
        return self._info


class CoverageGuidedFuzzer:
    """Feedback-driven fuzzer: prefers mutations that increase coverage."""

    def __init__(
        self,
        generator: Generator,
        mutators: list[Mutator],
        scanner_fn: Callable[[bytes, str], list],
        source_dirs: list[str] | None = None,
        max_rounds: int = 1000,
        plateau_limit: int = 50,
        seed: Optional[int] = None,
    ):
        self._generator = generator
        self._mutators = mutators
        self._scanner_fn = scanner_fn
        self._tracker = CoverageTracker(source_dirs)
        self._max_rounds = max_rounds
        self._plateau_limit = plateau_limit
        self._rng = random.Random(seed)
        self._corpus: list[bytes] = []
        self._interesting: list[bytes] = []
        self._results: list[FuzzResult] = []

    def run(self) -> dict:
        logger.info("Starting coverage-guided fuzzing (%d rounds max)", self._max_rounds)

        # Seed corpus
        for _ in range(10):
            sample = self._generator.generate(seed=self._rng.randint(0, 2**64 - 1))
            self._corpus.append(sample)

        plateau = 0
        round_num = 0

        for round_num in range(self._max_rounds):
            # Pick base from corpus
            base = self._rng.choice(self._corpus) if self._corpus else b""

            # Apply random mutator
            mutator = self._rng.choice(self._mutators)
            mutated = mutator.mutate(base)

            # Track coverage
            self._tracker.start()
            payload = Payload(
                name=f"cov_round_{round_num}",
                category=PayloadCategory.EVASION,
                data=mutated,
            )

            result = self._scan_one(payload)
            self._results.append(result)

            info = self._tracker.stop()

            if self._tracker.is_new_coverage(mutated):
                self._interesting.append(mutated)
                self._corpus.append(mutated)
                plateau = 0
                logger.debug("Round %d: new coverage found", round_num)
            else:
                plateau += 1

            if plateau >= self._plateau_limit:
                logger.info(
                    "Coverage plateau at round %d, switching strategy",
                    round_num,
                )
                self._switch_strategy()
                plateau = 0

        info = self._tracker.info
        info.plateau_rounds = plateau

        return {
            "rounds": round_num + 1,
            "corpus_size": len(self._corpus),
            "interesting_inputs": len(self._interesting),
            "coverage": info.to_dict(),
            "bypasses": sum(1 for r in self._results if r.is_bypass),
            "crashes": sum(1 for r in self._results if r.scanner_crashed),
        }

    def _scan_one(self, payload: Payload) -> FuzzResult:
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
        return result

    def _switch_strategy(self) -> None:
        new_sample = self._generator.generate(
            seed=self._rng.randint(0, 2**64 - 1)
        )
        self._corpus.append(new_sample)

    @property
    def corpus(self) -> list[bytes]:
        return self._corpus

    @property
    def interesting(self) -> list[bytes]:
        return self._interesting
