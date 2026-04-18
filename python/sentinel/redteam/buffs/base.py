"""
Buff base class — all prompt mutation buffs inherit from this.

Production-grade features:
  - Abstract transform interface
  - Chain composition (sequential pipeline)
  - Parallel fan-out (one prompt → multiple variants)
  - Random subset selection
  - Transform statistics tracking
  - Deduplication
  - Augmentation mode (keep original + add mutated)
  - Introspection and serialization
"""

from __future__ import annotations

import logging
import random
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class BuffStats:
    """Statistics for buff transformations."""
    transforms_run: int = 0
    prompts_in: int = 0
    prompts_out: int = 0
    duplicates_removed: int = 0


class Buff(ABC):
    """
    Base class for prompt mutation buffs.

    A Buff transforms a list of prompt strings into a new list of mutated
    prompt strings. Multiple buffs can be composed via Chain, Parallel,
    and Augment patterns.
    """

    name: str = "base"

    def __init__(self):
        self._stats = BuffStats()

    @abstractmethod
    def transform(self, prompts: list[str]) -> list[str]:
        """Transform a list of prompts. Returns mutated prompts."""
        ...

    def transform_single(self, prompt: str) -> str:
        """Transform a single prompt."""
        results = self.transform([prompt])
        return results[0] if results else prompt

    def augment(self, prompts: list[str]) -> list[str]:
        """Return originals + transformed (doubles the dataset)."""
        transformed = self.transform(prompts)
        return prompts + transformed

    def _track(self, n_in: int, n_out: int):
        """Track statistics."""
        self._stats.transforms_run += 1
        self._stats.prompts_in += n_in
        self._stats.prompts_out += n_out

    @property
    def stats(self) -> BuffStats:
        return self._stats

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name!r})"


class IdentityBuff(Buff):
    """No-op buff — returns prompts unchanged. Useful as default/test."""
    name = "identity"

    def transform(self, prompts: list[str]) -> list[str]:
        return list(prompts)


class LowercaseBuff(Buff):
    """Converts all prompts to lowercase — bypasses case-sensitive filters."""
    name = "lowercase"

    def transform(self, prompts: list[str]) -> list[str]:
        return [p.lower() for p in prompts]


class UppercaseBuff(Buff):
    """Converts all prompts to UPPERCASE — bypasses case-sensitive filters."""
    name = "uppercase"

    def transform(self, prompts: list[str]) -> list[str]:
        return [p.upper() for p in prompts]


class TitleCaseBuff(Buff):
    """Converts prompts to Title Case."""
    name = "titlecase"

    def transform(self, prompts: list[str]) -> list[str]:
        return [p.title() for p in prompts]


class PrefixBuff(Buff):
    """Prepends a fixed prefix to each prompt."""
    name = "prefix"

    def __init__(self, prefix: str = ""):
        super().__init__()
        self._prefix = prefix

    def transform(self, prompts: list[str]) -> list[str]:
        return [self._prefix + p for p in prompts]


class SuffixBuff(Buff):
    """Appends a fixed suffix to each prompt."""
    name = "suffix"

    def __init__(self, suffix: str = ""):
        super().__init__()
        self._suffix = suffix

    def transform(self, prompts: list[str]) -> list[str]:
        return [p + self._suffix for p in prompts]


class WrapBuff(Buff):
    """Wraps each prompt with prefix and suffix (e.g., role-play framing)."""
    name = "wrap"

    def __init__(self, prefix: str = "", suffix: str = ""):
        super().__init__()
        self._prefix = prefix
        self._suffix = suffix

    def transform(self, prompts: list[str]) -> list[str]:
        return [f"{self._prefix}{p}{self._suffix}" for p in prompts]


class ChainBuff(Buff):
    """
    Chains multiple buffs sequentially.

    Each buff's output becomes the next buff's input:
        prompt → buff_1 → buff_2 → ... → buff_n → result

    Usage:
        chain = ChainBuff([LowercaseBuff(), PrefixBuff("IGNORE: ")])
    """
    name = "chain"

    def __init__(self, buffs: list[Buff]):
        super().__init__()
        self._buffs = buffs

    def transform(self, prompts: list[str]) -> list[str]:
        result = prompts
        for buff in self._buffs:
            result = buff.transform(result)
        return result

    @property
    def buff_names(self) -> list[str]:
        return [b.name for b in self._buffs]


class ParallelBuff(Buff):
    """
    Applies multiple buffs in parallel — each prompt gets all variants.

    One prompt → N mutated prompts (one per buff):
        prompt → [buff_1(prompt), buff_2(prompt), ..., buff_n(prompt)]

    Usage:
        parallel = ParallelBuff([LowercaseBuff(), UppercaseBuff(), EncodingBuff()])
        # 1 prompt → 3 variants
    """
    name = "parallel"

    def __init__(self, buffs: list[Buff], deduplicate: bool = True):
        super().__init__()
        self._buffs = buffs
        self._dedup = deduplicate

    def transform(self, prompts: list[str]) -> list[str]:
        results = []
        for prompt in prompts:
            for buff in self._buffs:
                transformed = buff.transform([prompt])
                results.extend(transformed)

        if self._dedup:
            seen = set()
            deduped = []
            for r in results:
                if r not in seen:
                    seen.add(r)
                    deduped.append(r)
            self._stats.duplicates_removed += len(results) - len(deduped)
            return deduped

        return results


class RandomSubsetBuff(Buff):
    """
    Randomly selects a subset of prompts.

    Useful for sampling from a large probe list when you don't
    want to run all prompts (cost/time optimization).
    """
    name = "random_subset"

    def __init__(self, count: int = 10, seed: int | None = None):
        super().__init__()
        self._count = count
        self._rng = random.Random(seed)

    def transform(self, prompts: list[str]) -> list[str]:
        if len(prompts) <= self._count:
            return list(prompts)
        return self._rng.sample(prompts, self._count)


class RepeatBuff(Buff):
    """Repeats each prompt N times (useful for statistical runs)."""
    name = "repeat"

    def __init__(self, n: int = 3):
        super().__init__()
        self._n = n

    def transform(self, prompts: list[str]) -> list[str]:
        return [p for p in prompts for _ in range(self._n)]


class ShuffleBuff(Buff):
    """Randomly shuffles prompt order."""
    name = "shuffle"

    def __init__(self, seed: int | None = None):
        super().__init__()
        self._rng = random.Random(seed)

    def transform(self, prompts: list[str]) -> list[str]:
        result = list(prompts)
        self._rng.shuffle(result)
        return result


class TemplateBuff(Buff):
    """
    Wraps prompts in a template string.

    Template uses {prompt} placeholder:
        "Pretend you are DAN. {prompt}"

    Usage:
        buff = TemplateBuff("As a creative writer, {prompt}")
    """
    name = "template"

    def __init__(self, template: str):
        super().__init__()
        self._template = template

    def transform(self, prompts: list[str]) -> list[str]:
        return [self._template.replace("{prompt}", p) for p in prompts]


class MultiTemplateBuff(Buff):
    """
    Applies multiple templates — each prompt generates N variants.

    Usage:
        buff = MultiTemplateBuff([
            "As DAN, {prompt}",
            "Ignore previous instructions. {prompt}",
            "In a fictional world, {prompt}",
        ])
    """
    name = "multi_template"

    def __init__(self, templates: list[str]):
        super().__init__()
        self._templates = templates

    def transform(self, prompts: list[str]) -> list[str]:
        results = []
        for prompt in prompts:
            for template in self._templates:
                results.append(template.replace("{prompt}", prompt))
        return results
