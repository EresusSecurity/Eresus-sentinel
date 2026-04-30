"""Shared utilities for artifact generators."""

from __future__ import annotations

import io
import tarfile


def pickle_rce_payload() -> bytes:
    """Standard pickle RCE gadget: os.system('id')."""
    return b"\x80\x02cos\nsystem\n(S'id'\ntR."


def tar_add_bytes(tf: tarfile.TarFile, name: str, data: bytes) -> None:
    """Add raw bytes as a file entry to an open TarFile."""
    info = tarfile.TarInfo(name)
    info.size = len(data)
    tf.addfile(info, io.BytesIO(data))
