"""
Scheduled Red-Team Scan Scheduler.

Enables cron-based recurring scans against AI targets. Each schedule entry
defines: target model, probe set, recurrence, and notification hooks.

Usage::

    from sentinel.redteam.scheduler import ScanScheduler, ScheduleEntry

    scheduler = ScanScheduler(db_path="~/.sentinel/schedules.json")

    entry = ScheduleEntry(
        name="nightly-gpt4o",
        cron="0 2 * * *",               # 02:00 every day
        generator_config={"provider": "openai", "model": "gpt-4o"},
        probe_names=["dan", "word_game", "genetic_jailbreak"],
        notify_webhook="https://hooks.slack.com/...",
    )
    scheduler.add(entry)
    scheduler.run_forever()              # blocking loop

    # Or: run due jobs once and exit (for use in external cron/systemd)
    scheduler.run_due()
"""
from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)


# ── Cron helper (minimal, no external dep) ────────────────────────────────

def _cron_is_due(cron: str, now: datetime) -> bool:
    """Very lightweight cron matcher. Supports: ``* * * * *`` field syntax.
    Fields: minute hour day-of-month month day-of-week.
    """
    try:
        fields = cron.strip().split()
        if len(fields) != 5:
            return False
        minute, hour, dom, month, dow = fields
        checks = [
            (minute, now.minute),
            (hour, now.hour),
            (dom, now.day),
            (month, now.month),
            (dow, now.weekday()),  # 0=Monday
        ]
        for expr, val in checks:
            if expr == "*":
                continue
            if "/" in expr:
                _, step = expr.split("/")
                if val % int(step) != 0:
                    return False
            elif "-" in expr:
                lo, hi = expr.split("-")
                if not (int(lo) <= val <= int(hi)):
                    return False
            elif "," in expr:
                if val not in [int(v) for v in expr.split(",")]:
                    return False
            else:
                if val != int(expr):
                    return False
        return True
    except Exception:
        return False


# ── Data model ────────────────────────────────────────────────────────────

@dataclass
class ScheduleEntry:
    """A single scheduled scan definition."""
    name: str
    cron: str                       # cron expression e.g. "0 2 * * *"
    generator_config: dict[str, Any]  # passed to generator factory
    probe_names: list[str] = field(default_factory=list)
    max_prompts: int = 5
    notify_webhook: str | None = None
    notify_email: str | None = None
    enabled: bool = True
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    last_run: str | None = None     # ISO timestamp
    last_status: str | None = None  # "success" | "error"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class ScheduledRunResult:
    """Result of a single scheduled scan execution."""
    schedule_id: str
    schedule_name: str
    run_id: str
    started_at: str
    finished_at: str
    duration_seconds: float
    status: str          # "success" | "error"
    report_summary: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


# ── Scheduler ─────────────────────────────────────────────────────────────

class ScanScheduler:
    """Cron-based scheduler for recurring red-team scans.

    Args:
        db_path:         JSON file to persist schedule entries.
        generator_factory: Callable that takes ``generator_config`` dict and
                           returns a Generator instance. Defaults to a simple
                           LiteLLM factory if available.
        tick_interval_s: How often (seconds) to check for due jobs (default 60).
    """

    def __init__(
        self,
        db_path: str | Path | None = None,
        generator_factory: Callable[[dict[str, Any]], Any] | None = None,
        tick_interval_s: int = 60,
    ) -> None:
        self._db_path = Path(db_path).expanduser() if db_path else None
        self._generator_factory = generator_factory or self._default_generator_factory
        self._tick_interval = tick_interval_s
        self._entries: list[ScheduleEntry] = []
        self._history: list[ScheduledRunResult] = []
        self._lock = threading.Lock()
        self._stop_event = threading.Event()

        if self._db_path and self._db_path.exists():
            self._load()

    # ── CRUD ──────────────────────────────────────────────────────────

    def add(self, entry: ScheduleEntry) -> ScheduleEntry:
        with self._lock:
            self._entries.append(entry)
            self._save()
        logger.info("Scheduled scan added: %s (cron=%s)", entry.name, entry.cron)
        return entry

    def remove(self, entry_id: str) -> bool:
        with self._lock:
            before = len(self._entries)
            self._entries = [e for e in self._entries if e.id != entry_id]
            removed = len(self._entries) < before
            if removed:
                self._save()
        return removed

    def list_entries(self) -> list[ScheduleEntry]:
        with self._lock:
            return list(self._entries)

    def get_history(self, limit: int = 50) -> list[ScheduledRunResult]:
        with self._lock:
            return list(reversed(self._history))[:limit]

    # ── Execution ─────────────────────────────────────────────────────

    def run_due(self) -> list[ScheduledRunResult]:
        """Run all entries whose cron expression is due right now."""
        now = datetime.now(timezone.utc)
        results: list[ScheduledRunResult] = []
        with self._lock:
            entries = [e for e in self._entries if e.enabled]

        for entry in entries:
            if _cron_is_due(entry.cron, now):
                result = self._execute(entry)
                results.append(result)
                with self._lock:
                    self._history.append(result)
                    # Update last_run on the entry
                    for e in self._entries:
                        if e.id == entry.id:
                            e.last_run = result.finished_at
                            e.last_status = result.status
                    self._save()
        return results

    def run_forever(self, daemon: bool = True) -> threading.Thread:
        """Start scheduler in a background thread and return it.

        Args:
            daemon: If True (default) the thread is a daemon and will not
                    prevent interpreter shutdown.
        """
        t = threading.Thread(target=self._run_loop, name="sentinel-scheduler", daemon=daemon)
        t.start()
        logger.info("Scheduler thread started (tick=%ds, daemon=%s)", self._tick_interval, daemon)
        return t

    def run_blocking(self) -> None:
        """Block the calling thread running scheduled jobs. Call :meth:`stop` to exit."""
        self._run_loop()

    def _run_loop(self) -> None:
        logger.info("Scheduler loop started")
        while not self._stop_event.is_set():
            self.run_due()
            self._stop_event.wait(timeout=self._tick_interval)
        logger.info("Scheduler loop stopped")

    def stop(self) -> None:
        self._stop_event.set()

    def __del__(self) -> None:
        self._stop_event.set()

    def _execute(self, entry: ScheduleEntry) -> ScheduledRunResult:
        run_id = str(uuid.uuid4())[:8]
        started = datetime.now(timezone.utc).isoformat()
        t0 = time.time()
        logger.info("Running scheduled scan: %s (id=%s)", entry.name, run_id)

        try:
            generator = self._generator_factory(entry.generator_config)
            from sentinel.redteam.multi_model_compare import MultiModelComparison
            cmp = MultiModelComparison(
                generators=[generator],
                probe_names=entry.probe_names or ["dan"],
                max_prompts=entry.max_prompts,
            )
            report = cmp.run()
            finished = datetime.now(timezone.utc).isoformat()
            result = ScheduledRunResult(
                schedule_id=entry.id,
                schedule_name=entry.name,
                run_id=run_id,
                started_at=started,
                finished_at=finished,
                duration_seconds=round(time.time() - t0, 2),
                status="success",
                report_summary=report.as_dict(),
            )
            if entry.notify_webhook:
                self._notify_webhook(entry.notify_webhook, result)
        except Exception as exc:
            finished = datetime.now(timezone.utc).isoformat()
            result = ScheduledRunResult(
                schedule_id=entry.id,
                schedule_name=entry.name,
                run_id=run_id,
                started_at=started,
                finished_at=finished,
                duration_seconds=round(time.time() - t0, 2),
                status="error",
                error=str(exc),
            )
            logger.error("Scheduled scan %s failed: %s", entry.name, exc)
        return result

    # ── Notification ──────────────────────────────────────────────────

    def _notify_webhook(self, url: str, result: ScheduledRunResult) -> None:
        try:
            import urllib.request
            payload = json.dumps(asdict(result)).encode()
            req = urllib.request.Request(
                url, data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=10)
        except Exception as exc:
            logger.warning("Webhook notification failed: %s", exc)

    # ── Persistence ───────────────────────────────────────────────────

    @staticmethod
    def _mask_entry_for_save(entry_dict: dict) -> dict:
        """Replace api_key values with masked versions before writing to disk."""
        cfg = entry_dict.get("generator_config", {})
        if "api_key" in cfg and cfg["api_key"]:
            key = cfg["api_key"]
            cfg = dict(cfg)
            cfg["api_key"] = f"{key[:4]}...{key[-4:]}" if len(key) > 8 else "***"
            entry_dict = dict(entry_dict)
            entry_dict["generator_config"] = cfg
        return entry_dict

    def _save(self) -> None:
        if not self._db_path:
            return
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        data = {"entries": [self._mask_entry_for_save(asdict(e)) for e in self._entries]}
        self._db_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _load(self) -> None:
        if not self._db_path or not self._db_path.exists():
            return
        try:
            data = json.loads(self._db_path.read_text(encoding="utf-8"))
            for item in data.get("entries", []):
                self._entries.append(ScheduleEntry(**item))
            logger.debug("Loaded %d schedule entries", len(self._entries))
        except Exception as exc:
            logger.warning("Failed to load schedules from %s: %s", self._db_path, exc)

    # ── Default generator factory ─────────────────────────────────────

    @staticmethod
    def _default_generator_factory(config: dict[str, Any]) -> Any:
        """Build a generator from config dict. Tries LiteLLM first."""
        try:
            from sentinel.redteam.generators.litellm import LiteLLMGenerator
            return LiteLLMGenerator(
                model=config.get("model", "gpt-4o-mini"),
                api_key=config.get("api_key"),
                base_url=config.get("base_url"),
            )
        except ImportError:
            from sentinel.redteam.generators.echo import EchoGenerator
            return EchoGenerator()
