"""Thread-pool executor singleton for running sync scanners off the event loop."""
from __future__ import annotations

import asyncio
import os
from concurrent.futures import ThreadPoolExecutor

_MAX_WORKERS = int(os.environ.get("SENTINEL_MAX_WORKERS", "0")) or min(8, (os.cpu_count() or 2) * 2)

_pool = ThreadPoolExecutor(max_workers=_MAX_WORKERS, thread_name_prefix="sentinel-scan")


async def run_in_pool(fn, *args):
    """Await a blocking callable in the shared thread pool."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_pool, fn, *args)
