"""Red team attack strategies — prompt mutation and jailbreak techniques."""
from __future__ import annotations

import importlib
import inspect
import pkgutil

from sentinel.redteam.strategies.base import BaseStrategy, StrategyRegistry

__all__ = ["BaseStrategy", "StrategyRegistry"]

for _module_info in pkgutil.iter_modules(__path__):
    if _module_info.name.startswith("_") or _module_info.name == "base":
        continue
    _module = importlib.import_module(f"{__name__}.{_module_info.name}")
    for _class_name, _class_obj in inspect.getmembers(_module, inspect.isclass):
        if _class_obj is BaseStrategy:
            continue
        if issubclass(_class_obj, BaseStrategy):
            globals()[_class_name] = _class_obj
            if _class_name not in __all__:
                __all__.append(_class_name)

del importlib, inspect, pkgutil, _class_name, _class_obj, _module, _module_info
