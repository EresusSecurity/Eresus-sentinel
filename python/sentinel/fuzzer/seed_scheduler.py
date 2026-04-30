"""Seed scheduler — multi-policy corpus management for coverage-guided fuzzing.

Implements four scheduling policies:
  • **Power** (default) — AFL-style energy scoring; seeds that produced more
    unique bypasses/crashes get proportionally more mutations.
  • **Round-robin** — simple cyclic iteration, useful as a fairness baseline.
  • **Random** — uniformly random selection (useful for comparison).
  • **Exploit** — always picks the highest-energy seed (greedy).

Additional features:
  • Seed **aging / eviction**: seeds that are never fruitful get their energy
    decayed over time and can be evicted to keep the corpus lean.
  • **Coverage bits** tracking: seeds that cover new code paths get an energy
    bonus on top of bypass/crash counts.
  • **Import / export** of the corpus to/from a directory of raw payload files.
  • Thread-safe via a simple ``threading.Lock``.
"""

from __future__ import annotations

import json
import logging
import math
import random
import threading
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Scheduling policy enum
# ---------------------------------------------------------------------------

class SchedulePolicy(str, Enum):
    POWER = "power"
    ROUND_ROBIN = "round_robin"
    RANDOM = "random"
    EXPLOIT = "exploit"


# ---------------------------------------------------------------------------
# Seed data model
# ---------------------------------------------------------------------------

@dataclass
class SeedEntry:
    """Tracks execution history and computed energy of a single corpus seed."""
    seed_id: str
    data: bytes
    executions: int = 0
    unique_crashes: int = 0
    unique_bypasses: int = 0
    coverage_bits: int = 0
    last_energy: float = 1.0
    added_at: float = field(default_factory=time.time)
    last_used_at: float = field(default_factory=time.time)
    # Tags allow grouping seeds by category for selective scheduling
    tags: list[str] = field(default_factory=list)

    @property
    def interesting_count(self) -> int:
        """Total interesting events associated with this seed."""
        return self.unique_crashes + self.unique_bypasses

    @property
    def age_seconds(self) -> float:
        return time.time() - self.added_at

    @property
    def staleness_seconds(self) -> float:
        """Seconds since this seed was last selected."""
        return time.time() - self.last_used_at

    def to_dict(self) -> dict:
        d = asdict(self)
        d["data"] = self.data.hex()
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "SeedEntry":
        d = dict(d)
        d["data"] = bytes.fromhex(d["data"])
        return cls(**d)


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------

class SeedScheduler:
    """AFL-inspired seed scheduler with pluggable scheduling policies.

    Args:
        seeds:          Initial corpus as list of (seed_id, payload_bytes).
        policy:         Scheduling policy (power / round_robin / random / exploit).
        decay:          Energy decay factor per round without finds (0 = no decay).
        eviction_limit: Maximum corpus size; least-energetic seeds are evicted
                        when this is exceeded. 0 = unlimited.
        seed:           Optional RNG seed for reproducibility.

    Example::

        sched = SeedScheduler([("s0", b"hello world")], policy="power")
        for _ in range(1000):
            entry = sched.next()
            findings = scan(entry.data)
            sched.update(entry.seed_id, bypasses=len(findings))
    """

    def __init__(
        self,
        seeds: Optional[list[tuple[str, bytes]]] = None,
        policy: SchedulePolicy | str = SchedulePolicy.POWER,
        decay: float = 0.02,
        eviction_limit: int = 0,
        seed: Optional[int] = None,
    ):
        self._seeds: list[SeedEntry] = []
        self._policy = SchedulePolicy(policy)
        self._decay = decay
        self._eviction_limit = eviction_limit
        self._rng = random.Random(seed)
        self._lock = threading.Lock()
        self._rr_idx = 0  # round-robin cursor
        self._round = 0   # global round counter

        for sid, data in (seeds or []):
            self.add(sid, data)

    # ── CRUD ────────────────────────────────────────────────────────

    def add(self, seed_id: str, data: bytes, tags: Optional[list[str]] = None) -> SeedEntry:
        """Add a new seed to the corpus."""
        with self._lock:
            # Deduplicate by seed_id
            if any(s.seed_id == seed_id for s in self._seeds):
                raise ValueError(f"Seed ID already exists: {seed_id!r}")
            entry = SeedEntry(seed_id=seed_id, data=data, tags=tags or [])
            self._seeds.append(entry)
            self._maybe_evict()
            return entry

    def remove(self, seed_id: str) -> bool:
        with self._lock:
            before = len(self._seeds)
            self._seeds = [s for s in self._seeds if s.seed_id != seed_id]
            return len(self._seeds) < before

    def get(self, seed_id: str) -> Optional[SeedEntry]:
        with self._lock:
            for s in self._seeds:
                if s.seed_id == seed_id:
                    return s
            return None

    def __len__(self) -> int:
        with self._lock:
            return len(self._seeds)

    # ── Scheduling ───────────────────────────────────────────────────

    def next(self, tag_filter: Optional[str] = None) -> Optional[SeedEntry]:
        """Return the next seed according to the active scheduling policy.

        Args:
            tag_filter: If provided, only consider seeds with this tag.
        """
        with self._lock:
            pool = [s for s in self._seeds if not tag_filter or tag_filter in s.tags]
            if not pool:
                return None

            self._round += 1
            if self._policy == SchedulePolicy.POWER:
                selected = self._power_select(pool)
            elif self._policy == SchedulePolicy.ROUND_ROBIN:
                selected = self._rr_select(pool)
            elif self._policy == SchedulePolicy.RANDOM:
                selected = self._rng.choice(pool)
            else:  # EXPLOIT
                selected = max(pool, key=lambda s: s.last_energy)

            selected.last_used_at = time.time()
            return selected

    def update(
        self,
        seed_id: str,
        *,
        bypasses: int = 0,
        crashes: int = 0,
        coverage: int = 0,
        new_coverage_bits: int = 0,
    ) -> None:
        """Record findings for *seed_id* and recompute its energy."""
        with self._lock:
            for s in self._seeds:
                if s.seed_id == seed_id:
                    s.executions += 1
                    s.unique_bypasses += bypasses
                    s.unique_crashes += crashes
                    s.coverage_bits = max(s.coverage_bits, coverage)
                    if new_coverage_bits > 0:
                        s.coverage_bits += new_coverage_bits
                    s.last_energy = self._compute_energy(s)
                    return
            logger.warning("update() called for unknown seed_id=%r", seed_id)

    def decay_all(self) -> None:
        """Apply energy decay to all seeds (call once per fuzzing round)."""
        if self._decay <= 0:
            return
        with self._lock:
            for s in self._seeds:
                s.last_energy = max(0.01, s.last_energy * (1.0 - self._decay))

    def recompute_energies(self) -> None:
        """Recompute energy for all seeds (useful after policy changes)."""
        with self._lock:
            for s in self._seeds:
                s.last_energy = self._compute_energy(s)

    # ── Query helpers ─────────────────────────────────────────────────

    def top_k(self, k: int = 5, tag_filter: Optional[str] = None) -> list[SeedEntry]:
        """Return the *k* highest-energy seeds."""
        with self._lock:
            pool = [s for s in self._seeds if not tag_filter or tag_filter in s.tags]
            return sorted(pool, key=lambda s: s.last_energy, reverse=True)[:k]

    def stale_seeds(self, threshold_seconds: float = 3600.0) -> list[SeedEntry]:
        """Return seeds that have not been selected in *threshold_seconds*."""
        with self._lock:
            return [s for s in self._seeds if s.staleness_seconds > threshold_seconds]

    def stats(self) -> dict:
        with self._lock:
            total = len(self._seeds)
            total_exec = sum(s.executions for s in self._seeds)
            total_bypasses = sum(s.unique_bypasses for s in self._seeds)
            total_crashes = sum(s.unique_crashes for s in self._seeds)
            return {
                "corpus_size": total,
                "policy": self._policy.value,
                "total_executions": total_exec,
                "total_bypasses": total_bypasses,
                "total_crashes": total_crashes,
                "rounds": self._round,
                "avg_energy": (sum(s.last_energy for s in self._seeds) / total) if total else 0.0,
            }

    # ── Import / export ───────────────────────────────────────────────

    def export_corpus(self, directory: str | Path) -> int:
        """Write each seed's raw payload to *directory/<seed_id>.bin*.

        Returns the number of files written.
        """
        d = Path(directory)
        d.mkdir(parents=True, exist_ok=True)
        with self._lock:
            for entry in self._seeds:
                (d / f"{entry.seed_id}.bin").write_bytes(entry.data)
            # Write metadata JSON
            meta = [e.to_dict() for e in self._seeds]
            (d / "corpus_meta.json").write_text(json.dumps(meta, indent=2))
            return len(self._seeds)

    def import_corpus(self, directory: str | Path) -> int:
        """Load seeds from a directory previously exported with export_corpus().

        Skips seeds whose IDs already exist in the corpus.
        Returns the number of new seeds imported.
        """
        d = Path(directory)
        meta_path = d / "corpus_meta.json"
        if meta_path.exists():
            meta = json.loads(meta_path.read_text())
            added = 0
            for item in meta:
                if not any(s.seed_id == item["seed_id"] for s in self._seeds):
                    entry = SeedEntry.from_dict(item)
                    with self._lock:
                        self._seeds.append(entry)
                    added += 1
            return added
        # Fall back: load all *.bin files
        added = 0
        for p in sorted(d.glob("*.bin")):
            sid = p.stem
            if not any(s.seed_id == sid for s in self._seeds):
                self.add(sid, p.read_bytes())
                added += 1
        return added

    # ── Internal ─────────────────────────────────────────────────────

    @staticmethod
    def _compute_energy(s: SeedEntry) -> float:
        """AFL-style performance score.

        Energy = (interesting_finds + coverage_bonus + 1) / log(executions+2) × size_factor
        Stale seeds (not used recently) receive a small staleness bonus so they
        are occasionally re-examined.
        """
        interesting = s.interesting_count + s.coverage_bits * 0.05
        exec_penalty = math.log(s.executions + 2)
        # Larger seeds cost more to mutate — slightly penalise them
        size_factor = max(0.3, 1.0 - len(s.data) / 200_000)
        # Small staleness bonus (encourages re-exploration)
        stale_bonus = min(0.5, s.staleness_seconds / 7200)
        return max(0.01, (interesting + 1.0) / exec_penalty * size_factor + stale_bonus)

    def _power_select(self, pool: list[SeedEntry]) -> SeedEntry:
        """Weighted random selection proportional to energy."""
        weights = [max(s.last_energy, 1e-6) for s in pool]
        total = sum(weights)
        r = self._rng.random() * total
        cumulative = 0.0
        for seed, w in zip(pool, weights):
            cumulative += w
            if r <= cumulative:
                return seed
        return pool[-1]

    def _rr_select(self, pool: list[SeedEntry]) -> SeedEntry:
        """Cyclic round-robin selection within *pool*."""
        if self._rr_idx >= len(pool):
            self._rr_idx = 0
        entry = pool[self._rr_idx]
        self._rr_idx = (self._rr_idx + 1) % len(pool)
        return entry

    def _maybe_evict(self) -> None:
        """Evict lowest-energy seeds if corpus exceeds eviction_limit."""
        if self._eviction_limit <= 0 or len(self._seeds) <= self._eviction_limit:
            return
        n_evict = len(self._seeds) - self._eviction_limit
        # Never evict seeds with crashes or bypasses
        evictable = sorted(
            [s for s in self._seeds if s.interesting_count == 0],
            key=lambda s: s.last_energy,
        )
        for s in evictable[:n_evict]:
            self._seeds.remove(s)
            logger.debug("Evicted stale seed %r (energy=%.4f)", s.seed_id, s.last_energy)

