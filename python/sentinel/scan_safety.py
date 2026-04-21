"""Scan safety utilities — resource limits, file size checks, timeouts.

Shared by all scanners to prevent hostile input from crashing
or DoS-ing the scanner process.
"""

from __future__ import annotations

import logging
import os
import multiprocessing
import signal
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

# ── Safety Limits ─────────────────────────────────────────────────

# Maximum file size to scan (2 GB)
MAX_SCAN_FILE_SIZE: int = 2 * 1024 * 1024 * 1024

# Maximum decompressed output size (256 MB)
MAX_DECOMPRESS_SIZE: int = 256 * 1024 * 1024

# Default per-scanner timeout (seconds)
DEFAULT_SCANNER_TIMEOUT: int = 120

# Maximum recursion depth for nested structures
MAX_RECURSION_DEPTH: int = 32

# Maximum string collection size (number of entries)
MAX_STRING_COLLECTION: int = 10_000


class FileTooLargeError(Exception):
    """Raised when a file exceeds the maximum scan size."""

    def __init__(self, path: str, size: int, limit: int):
        self.path = path
        self.size = size
        self.limit = limit
        super().__init__(
            f"File '{path}' is {size:,} bytes, exceeding scan limit of {limit:,} bytes"
        )


class ScanTimeoutError(Exception):
    """Raised when a scanner exceeds its timeout."""


def check_file_size(path: str | Path, max_size: int = MAX_SCAN_FILE_SIZE) -> int:
    """Check file size before reading. Returns size if OK, raises if too large."""
    p = Path(path)
    if not p.exists():
        return 0
    size = p.stat().st_size
    if size > max_size:
        raise FileTooLargeError(str(path), size, max_size)
    return size


def safe_read_bytes(path: str | Path, max_size: int = MAX_SCAN_FILE_SIZE) -> bytes:
    """Read file bytes with size pre-check."""
    check_file_size(path, max_size)
    return Path(path).read_bytes()


def _run_scanner_in_process(
    func: Callable,
    args: tuple,
    result_queue: multiprocessing.Queue,
) -> None:
    """Target function for subprocess-based scanner execution."""
    try:
        import resource
        # Apply memory limit in the subprocess (2GB)
        mem_limit = MAX_SCAN_FILE_SIZE
        try:
            resource.setrlimit(resource.RLIMIT_AS, (mem_limit, mem_limit))
        except (ValueError, OSError):
            pass
        # Apply CPU limit
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (DEFAULT_SCANNER_TIMEOUT, DEFAULT_SCANNER_TIMEOUT + 10))
        except (ValueError, OSError):
            pass
    except ImportError:
        pass

    try:
        result = func(*args)
        result_queue.put(("ok", result))
    except Exception as e:
        result_queue.put(("error", str(e)))


def run_with_timeout(
    func: Callable[..., Any],
    args: tuple = (),
    timeout: int = DEFAULT_SCANNER_TIMEOUT,
) -> Any:
    """Run a function with a timeout using multiprocessing.

    Falls back to direct execution if multiprocessing fails (e.g., in tests).
    """
    try:
        ctx = multiprocessing.get_context("fork")
        q: multiprocessing.Queue = ctx.Queue()
        proc = ctx.Process(target=_run_scanner_in_process, args=(func, args, q))
        proc.start()
        proc.join(timeout=timeout)

        if proc.is_alive():
            proc.kill()
            proc.join(timeout=5)
            raise ScanTimeoutError(
                f"Scanner timed out after {timeout}s"
            )

        if q.empty():
            raise ScanTimeoutError("Scanner process exited without result")

        status, result = q.get_nowait()
        if status == "error":
            raise RuntimeError(result)
        return result

    except (OSError, RuntimeError) as e:
        # Fallback: run directly if multiprocessing unavailable
        logger.debug("Multiprocessing unavailable (%s), running directly", e)
        return func(*args)
