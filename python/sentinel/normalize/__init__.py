"""Unicode + encoding normalization utilities."""

from .invisible import strip_invisible
from .confusables import fold_confusables
from .decoders import decode_common
from .core import normalize, expand_for_matching

__all__ = [
    "strip_invisible",
    "fold_confusables",
    "decode_common",
    "normalize",
    "expand_for_matching",
]
