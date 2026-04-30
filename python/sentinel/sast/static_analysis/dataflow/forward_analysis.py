"""Generic forward dataflow worklist framework.

Subclasses provide the transfer function and meet operator. The engine
iterates until a fixed point is reached. Typical use: reaching definitions,
available expressions, taint propagation, constant propagation.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Generic, TypeVar

from sentinel.sast.static_analysis.cfg.builder import CFG

T = TypeVar("T")


@dataclass
class DataflowResult(Generic[T]):
    inputs: dict[int, T] = field(default_factory=dict)
    outputs: dict[int, T] = field(default_factory=dict)
    iterations: int = 0


class ForwardAnalysis(ABC, Generic[T]):
    """Generic forward dataflow worklist."""

    max_iterations: int = 10_000

    @abstractmethod
    def initial(self, cfg: CFG) -> T:
        """Initial value for the entry block."""

    @abstractmethod
    def bottom(self, cfg: CFG) -> T:
        """Lattice bottom for non-entry blocks."""

    @abstractmethod
    def meet(self, a: T, b: T) -> T:
        """Meet (join) operator."""

    @abstractmethod
    def transfer(self, cfg: CFG, bid: int, inp: T) -> T:
        """Block-level transfer function."""

    def equal(self, a: T, b: T) -> bool:  # override if T is not ==-comparable
        return a == b

    def run(self, cfg: CFG) -> DataflowResult[T]:
        result: DataflowResult[T] = DataflowResult()
        bottom = self.bottom(cfg)
        for bid in cfg.blocks:
            result.inputs[bid] = bottom
            result.outputs[bid] = bottom
        result.inputs[cfg.entry] = self.initial(cfg)

        worklist: list[int] = list(cfg.blocks)
        it = 0
        while worklist and it < self.max_iterations:
            it += 1
            bid = worklist.pop(0)
            preds = cfg.predecessors(bid)
            if preds:
                merged = result.outputs[preds[0]]
                for p in preds[1:]:
                    merged = self.meet(merged, result.outputs[p])
                result.inputs[bid] = merged
            new_out = self.transfer(cfg, bid, result.inputs[bid])
            if not self.equal(new_out, result.outputs[bid]):
                result.outputs[bid] = new_out
                for s in cfg.successors(bid):
                    if s not in worklist:
                        worklist.append(s)
        result.iterations = it
        return result
