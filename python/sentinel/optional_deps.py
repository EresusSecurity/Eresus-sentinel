"""Small helper for optional dependency imports with consistent error messages."""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from types import ModuleType


@dataclass(frozen=True)
class OptionalDependency:
    module: str
    extra: str = ""
    package: str = ""
    purpose: str = ""

    @property
    def install_hint(self) -> str:
        if self.extra:
            return f'pip install "eresus-sentinel[{self.extra}]"'
        if self.package:
            return f"pip install {self.package}"
        return f"pip install {self.module}"


class OptionalDependencyError(ImportError):
    """Raised when a requested optional integration dependency is unavailable."""

    def __init__(self, dependency: OptionalDependency):
        detail = f"Optional dependency '{dependency.module}' is required"
        if dependency.purpose:
            detail += f" for {dependency.purpose}"
        detail += f". Install with: {dependency.install_hint}"
        super().__init__(detail)
        self.dependency = dependency


def import_optional(
    module: str,
    *,
    extra: str = "",
    package: str = "",
    purpose: str = "",
) -> ModuleType | None:
    """Import an optional module, returning None when it is unavailable."""
    try:
        return importlib.import_module(module)
    except ImportError:
        return None


def require_optional(
    module: str,
    *,
    extra: str = "",
    package: str = "",
    purpose: str = "",
) -> ModuleType:
    """Import an optional module or raise a standardized actionable error."""
    loaded = import_optional(module, extra=extra, package=package, purpose=purpose)
    if loaded is None:
        raise OptionalDependencyError(OptionalDependency(module, extra, package, purpose))
    return loaded
