"""HuggingFace Bulk Scanner.

Scans multiple HuggingFace model repositories in sequence (or with limited
parallelism) using either a fast pre-download guard assessment or a full
download-and-scan mode.

Usage examples:
    scanner = HFBulkScanner()
    # Scan up to 100 text-generation models from Microsoft, guard mode only
    scanner.scan_bulk(
        owner="microsoft",
        task="text-generation",
        limit=100,
        mode="guard",
        output_path="results.jsonl",
    )
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

logger = logging.getLogger(__name__)

# ── Result dataclass ───────────────────────────────────────────────────────────

@dataclass
class BulkScanResult:
    repo_id: str
    mode: str
    scanned_at: str
    duration_s: float
    risk_level: str               # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "ERROR"
    finding_count: int
    findings: list[dict]
    error: str | None = None

    def to_jsonl(self) -> str:
        return json.dumps(asdict(self), default=str)


# ── Backoff helper ─────────────────────────────────────────────────────────────

_BACKOFF_SEQUENCE = (1.0, 2.0, 4.0, 8.0, 60.0)


async def _backoff_sleep(attempt: int) -> None:
    idx = min(attempt, len(_BACKOFF_SEQUENCE) - 1)
    delay = _BACKOFF_SEQUENCE[idx]
    logger.debug("Rate-limited — sleeping %.0fs (attempt %d)", delay, attempt)
    await asyncio.sleep(delay)


# ── HFBulkScanner ─────────────────────────────────────────────────────────────

class HFBulkScanner:
    """Bulk scanner for HuggingFace Hub model repositories.

    Parameters:
        token:       HuggingFace API token (falls back to HF_TOKEN env var).
        concurrency: Maximum simultaneous scans (default 4).
    """

    def __init__(
        self,
        token: str | None = None,
        concurrency: int = 4,
    ) -> None:
        self.token = token or os.environ.get("HF_TOKEN")
        self.concurrency = concurrency

    # ── Listing ────────────────────────────────────────────────────────────────

    def list_models(
        self,
        *,
        owner: str | None = None,
        task: str | None = None,
        tags: list[str] | None = None,
        sort: str = "downloads",
        limit: int = 1000,
        min_downloads: int = 0,
    ) -> Iterator[str]:
        """Yield repository IDs matching the given criteria.

        Args:
            owner:         HF username or organisation.
            task:          Pipeline tag (e.g. "text-generation").
            tags:          List of model tags to filter by.
            sort:          Sort field ("downloads", "likes", "lastModified").
            limit:         Maximum number of repos to yield.
            min_downloads: Minimum download count filter.
        """
        try:
            from huggingface_hub import HfApi
        except ImportError:
            raise RuntimeError(
                "huggingface-hub is required for bulk scanning. "
                "Install with: pip install 'eresus-sentinel[hf]'"
            )

        api = HfApi(token=self.token)

        # Build kwargs for the installed huggingface_hub API.
        filter_kwargs: dict = {}
        filters: list[str] = []
        if task:
            filter_kwargs["pipeline_tag"] = task
        if tags:
            filters.extend(tags)
        if filters:
            filter_kwargs["filter"] = filters
        if owner:
            filter_kwargs["author"] = owner

        count = 0
        try:
            models = api.list_models(
                sort=sort,
                limit=limit,
                **filter_kwargs,
            )
            for model_info in models:
                if count >= limit:
                    break
                downloads = getattr(model_info, "downloads", 0) or 0
                if downloads < min_downloads:
                    continue
                yield model_info.id
                count += 1
        except Exception as exc:
            raise RuntimeError(f"HF model listing failed: {exc}") from exc

    # ── Single model scan ──────────────────────────────────────────────────────

    def scan_model(self, repo_id: str, mode: str = "guard") -> BulkScanResult:
        """Scan a single HuggingFace repository.

        Args:
            repo_id: HuggingFace repository ID (e.g. "microsoft/phi-2").
            mode:    "guard" (no download, fast) or "full" (download + deep scan).
        """
        t0 = time.perf_counter()
        scanned_at = datetime.now(timezone.utc).isoformat()

        try:
            if mode == "guard":
                return self._scan_guard(repo_id, t0, scanned_at)
            else:
                return self._scan_full(repo_id, t0, scanned_at)
        except Exception as exc:
            duration = time.perf_counter() - t0
            logger.warning("scan_model(%s) failed: %s", repo_id, exc)
            return BulkScanResult(
                repo_id=repo_id,
                mode=mode,
                scanned_at=scanned_at,
                duration_s=round(duration, 3),
                risk_level="ERROR",
                finding_count=0,
                findings=[],
                error=str(exc),
            )

    def _scan_guard(self, repo_id: str, t0: float, scanned_at: str) -> BulkScanResult:
        from sentinel.hf_guard import HFGuard

        guard = HFGuard(token=self.token)
        assessment = guard.assess(repo_id)
        duration = time.perf_counter() - t0

        # Normalize risk_level
        risk = getattr(assessment, "risk_level", "INFO") or "INFO"

        # Convert dangerous_files to finding dicts
        findings_dicts: list[dict] = []
        for f in getattr(assessment, "dangerous_files", []):
            findings_dicts.append({
                "file": str(f),
                "rule_id": "HF-GUARD",
                "severity": "HIGH",
            })

        return BulkScanResult(
            repo_id=repo_id,
            mode="guard",
            scanned_at=scanned_at,
            duration_s=round(duration, 3),
            risk_level=risk,
            finding_count=len(findings_dicts),
            findings=findings_dicts,
        )

    def _scan_full(self, repo_id: str, t0: float, scanned_at: str) -> BulkScanResult:
        from sentinel.cli_dispatch import dispatch_huggingface

        findings = dispatch_huggingface(repo_id)
        duration = time.perf_counter() - t0

        findings_dicts = [
            {
                "rule_id": getattr(f, "rule_id", ""),
                "title": getattr(f, "title", ""),
                "severity": (
                    f.severity.value
                    if hasattr(f.severity, "value")
                    else str(f.severity)
                ),
                "source": getattr(f, "source", ""),
            }
            for f in findings
        ]

        # Determine aggregate risk from max severity
        _SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        if findings_dicts:
            worst = min(
                findings_dicts,
                key=lambda d: _SEV_ORDER.get(d.get("severity", "INFO").upper(), 4),
            )
            risk = worst.get("severity", "INFO").upper()
        else:
            risk = "INFO"

        return BulkScanResult(
            repo_id=repo_id,
            mode="full",
            scanned_at=scanned_at,
            duration_s=round(duration, 3),
            risk_level=risk,
            finding_count=len(findings_dicts),
            findings=findings_dicts,
        )

    # ── Bulk scan ──────────────────────────────────────────────────────────────

    def scan_bulk(
        self,
        *,
        owner: str | None = None,
        task: str | None = None,
        tags: list[str] | None = None,
        limit: int = 1000,
        min_downloads: int = 0,
        mode: str = "guard",
        output_path: str | Path | None = None,
        resume: bool = False,
    ) -> list[BulkScanResult]:
        """Scan multiple HuggingFace repos matching the given criteria.

        Args:
            owner:         Filter by HF username/org.
            task:          Filter by pipeline task.
            tags:          Filter by model tags.
            limit:         Maximum repos to scan.
            min_downloads: Minimum downloads filter.
            mode:          "guard" or "full".
            output_path:   JSONL file to append results to.
            resume:        Skip repos already present in output_path.
        """
        return asyncio.run(
            self._bulk_async(
                owner=owner,
                task=task,
                tags=tags,
                limit=limit,
                min_downloads=min_downloads,
                mode=mode,
                output_path=Path(output_path) if output_path else None,
                resume=resume,
            )
        )

    async def _bulk_async(
        self,
        *,
        owner: str | None,
        task: str | None,
        tags: list[str] | None,
        limit: int,
        min_downloads: int,
        mode: str,
        output_path: Path | None,
        resume: bool,
    ) -> list[BulkScanResult]:
        # Load already-scanned repos for resume support
        already_scanned: set[str] = set()
        if resume and output_path and output_path.exists():
            with open(output_path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                        already_scanned.add(rec.get("repo_id", ""))
                    except json.JSONDecodeError:
                        pass
            if already_scanned:
                logger.info("Resume: skipping %d already-scanned repos", len(already_scanned))

        # Collect repo IDs
        repo_ids = [
            rid for rid in self.list_models(
                owner=owner, task=task, tags=tags, limit=limit,
                min_downloads=min_downloads,
            )
            if rid not in already_scanned
        ]

        if not repo_ids:
            logger.info("No repos to scan (all already done or none matched filters).")
            return []

        logger.info("Bulk scan: %d repos, mode=%s, concurrency=%d", len(repo_ids), mode, self.concurrency)

        semaphore = asyncio.Semaphore(self.concurrency)
        results: list[BulkScanResult] = []
        output_fh = None

        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_fh = open(output_path, "a", encoding="utf-8")

        async def scan_one(repo_id: str, attempt: int = 0) -> BulkScanResult:
            async with semaphore:
                loop = asyncio.get_event_loop()
                try:
                    result = await loop.run_in_executor(
                        None, self.scan_model, repo_id, mode
                    )
                except Exception as exc:
                    msg = str(exc)
                    # Rate-limit: retry with exponential backoff
                    if "429" in msg or "rate limit" in msg.lower():
                        if attempt < len(_BACKOFF_SEQUENCE):
                            await _backoff_sleep(attempt)
                            return await scan_one(repo_id, attempt + 1)
                    result = BulkScanResult(
                        repo_id=repo_id,
                        mode=mode,
                        scanned_at=datetime.now(timezone.utc).isoformat(),
                        duration_s=0.0,
                        risk_level="ERROR",
                        finding_count=0,
                        findings=[],
                        error=msg,
                    )
                if output_fh:
                    output_fh.write(result.to_jsonl() + "\n")
                    output_fh.flush()
                return result

        tasks = [scan_one(rid) for rid in repo_ids]

        # Run with progress reporting
        try:
            from rich.progress import (
                BarColumn,
                MofNCompleteColumn,
                Progress,
                SpinnerColumn,
                TextColumn,
                TimeElapsedColumn,
            )
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold]{task.description}"),
                BarColumn(bar_width=30),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
            ) as progress:
                task_id = progress.add_task("HF bulk scan", total=len(tasks))
                for coro in asyncio.as_completed(tasks):
                    result = await coro
                    results.append(result)
                    risk_colour = {
                        "CRITICAL": "red", "HIGH": "yellow",
                        "MEDIUM": "cyan", "LOW": "green", "INFO": "dim",
                    }.get(result.risk_level, "white")
                    progress.update(
                        task_id,
                        advance=1,
                        description=(
                            f"[{risk_colour}]{result.risk_level}[/{risk_colour}] "
                            f"{result.repo_id}"
                        ),
                    )
        except ImportError:
            # No rich available — run without progress bar
            results = list(await asyncio.gather(*tasks))

        if output_fh:
            output_fh.close()

        # Summary
        by_risk: dict[str, int] = {}
        for r in results:
            by_risk[r.risk_level] = by_risk.get(r.risk_level, 0) + 1
        logger.info("Bulk scan complete: %s", by_risk)

        return results
