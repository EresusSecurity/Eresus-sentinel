"""Unicode + encoding normalization utilities."""

from .confusables import fold_confusables
from .core import expand_for_matching, normalize
from .decoders import decode_common
from .invisible import strip_invisible

__all__ = [
    "strip_invisible",
    "fold_confusables",
    "decode_common",
    "normalize",
    "expand_for_matching",
]
