"""Base class for red team attack strategies."""
from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
from abc import ABC, abstractmethod
from typing import ClassVar

import sentinel.redteam.strategies as pkg

logger = logging.getLogger(__name__)


class BaseStrategy(ABC):
    """Abstract base for all attack strategies.

    Subclasses set ``name`` and ``description`` class attributes and
    implement :meth:`transform` to produce prompt variants.
    """

    name: ClassVar[str] = "base"
    description: ClassVar[str] = ""

    @abstractmethod
    def transform(self, prompt: str) -> list[str]:
        """Transform *prompt* into one or more attack variants."""


class StrategyRegistry:
    """Auto-discovery registry for strategies."""

    _strategies: dict[str, type[BaseStrategy]] = {}

    @classmethod
    def register(cls, strategy_cls: type[BaseStrategy]) -> type[BaseStrategy]:
        cls._strategies[strategy_cls.name] = strategy_cls
        return strategy_cls

    @classmethod
    def get(cls, name: str) -> type[BaseStrategy] | None:
        return cls._strategies.get(name)

    @classmethod
    def all_strategies(cls) -> dict[str, type[BaseStrategy]]:
        return dict(cls._strategies)

    @classmethod
    def discover(cls) -> None:
        """Import all strategy modules to trigger registration."""
        for info in pkgutil.iter_modules(pkg.__path__):
            if info.name not in ("base", "__init__"):
                try:
                    module = importlib.import_module(f"sentinel.redteam.strategies.{info.name}")
                except Exception as exc:
                    logger.debug("Strategy import skipped for %s: %s", info.name, exc)
                    continue
                for _, obj in inspect.getmembers(module, inspect.isclass):
                    if (
                        issubclass(obj, BaseStrategy)
                        and obj is not BaseStrategy
                        and getattr(obj, "name", "base") != "base"
                    ):
                        cls.register(obj)
