"""Concurrent batch scanning — fires multiple prompts in parallel."""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from sentinel.firewall.base import ScanResult

if TYPE_CHECKING:
    from sentinel.firewall.async_pipeline import AsyncFirewallPipeline


async def batch_scan(
    pipeline: "AsyncFirewallPipeline",
    prompts: list[str],
    *,
    max_concurrent: int = 16,
) -> list[ScanResult]:
    """
    Scan up to *max_concurrent* prompts at once.
    Returns results in the same order as the input list.
    """
    sem = asyncio.Semaphore(max_concurrent)

    async def _one(prompt: str) -> ScanResult:
        async with sem:
            return await pipeline.scan(prompt)

    return await asyncio.gather(*(_one(p) for p in prompts))
