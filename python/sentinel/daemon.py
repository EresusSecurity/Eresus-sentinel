"""Background daemon for continuous file scanning.

Watches directories for new or changed files and triggers Sentinel scans
automatically. Designed for CI/CD integration and server-side deployment.

Usage:
    sentinel daemon --watch /models --watch /uploads --interval 5
"""
from __future__ import annotations

import json
import logging
import signal
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


@dataclass
class ScanEvent:
    path: str
    event_type: str  # "created", "modified", "deleted"
    timestamp: float = field(default_factory=time.time)
    findings_count: int = 0
    risk_score: float = 0.0


class SentinelDaemon:
    """Background scanning daemon.

    Args:
        watch_paths: Directories to monitor.
        scan_fn: Callable that scans a file path → list of findings.
        interval: Poll interval in seconds (fallback if watchdog unavailable).
        extensions: File extensions to monitor (default: all).
        on_findings: Callback ``(path, findings) -> None`` for new findings.
        log_path: Path for daemon event log (JSONL).
    """

    def __init__(
        self,
        watch_paths: list[str],
        scan_fn: Callable[[str], list[Any]],
        interval: float = 5.0,
        extensions: list[str] | None = None,
        on_findings: Optional[Callable[[str, list[Any]], None]] = None,
        log_path: Optional[str] = None,
    ) -> None:
        self._watch_paths = [Path(p).resolve() for p in watch_paths]
        self._scan_fn = scan_fn
        self._interval = interval
        self._extensions = set(extensions) if extensions else None
        self._on_findings = on_findings
        self._log_path = log_path
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._events: list[ScanEvent] = []
        self._file_mtimes: dict[str, float] = {}
        self._lock = threading.Lock()

    def start(self, background: bool = True) -> None:
        """Start the daemon.

        Args:
            background: Run in a background thread (default True).
                If False, blocks the calling thread.
        """
        if self._running:
            logger.warning("Daemon is already running")
            return

        self._running = True
        logger.info(
            "Sentinel daemon starting — watching %s",
            [str(p) for p in self._watch_paths],
        )

        if self._try_watchdog():
            return

        if background:
            self._thread = threading.Thread(target=self._poll_loop, daemon=True)
            self._thread.start()
        else:
            self._poll_loop()

    def stop(self) -> None:
        """Stop the daemon gracefully."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=self._interval + 1)
        logger.info("Sentinel daemon stopped.")

    @property
    def events(self) -> list[ScanEvent]:
        with self._lock:
            return list(self._events)

    @property
    def is_running(self) -> bool:
        return self._running

    def _poll_loop(self) -> None:
        """Fallback polling loop when watchdog is not available."""
        self._snapshot_mtimes()
        while self._running:
            try:
                self._check_changes()
            except Exception:
                logger.exception("Error during daemon poll cycle")
            time.sleep(self._interval)

    def _snapshot_mtimes(self) -> None:
        for root in self._watch_paths:
            if not root.is_dir():
                continue
            for p in root.rglob("*"):
                if p.is_file() and self._should_scan(p):
                    self._file_mtimes[str(p)] = p.stat().st_mtime

    def _check_changes(self) -> None:
        current: dict[str, float] = {}
        for root in self._watch_paths:
            if not root.is_dir():
                continue
            for p in root.rglob("*"):
                if p.is_file() and self._should_scan(p):
                    current[str(p)] = p.stat().st_mtime

        new_files = set(current) - set(self._file_mtimes)
        for fp in new_files:
            self._handle_event(fp, "created")

        for fp, mtime in current.items():
            if fp in self._file_mtimes and mtime > self._file_mtimes[fp]:
                self._handle_event(fp, "modified")

        self._file_mtimes = current

    def _handle_event(self, path: str, event_type: str) -> None:
        logger.info("Daemon detected %s: %s", event_type, path)
        try:
            findings = self._scan_fn(path)
            event = ScanEvent(
                path=path,
                event_type=event_type,
                findings_count=len(findings),
                risk_score=max(
                    (getattr(f, "confidence", 0.0) for f in findings),
                    default=0.0,
                ),
            )
            with self._lock:
                self._events.append(event)

            if findings and self._on_findings:
                self._on_findings(path, findings)

            if self._log_path:
                self._write_log(event)

        except Exception:
            logger.exception("Scan error for %s", path)

    def _write_log(self, event: ScanEvent) -> None:
        try:
            with open(self._log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({
                    "path": event.path,
                    "event": event.event_type,
                    "ts": event.timestamp,
                    "findings": event.findings_count,
                    "risk": event.risk_score,
                }) + "\n")
        except Exception:
            logger.exception("Failed to write daemon log")

    def _should_scan(self, path: Path) -> bool:
        if self._extensions is None:
            return True
        return path.suffix.lstrip(".") in self._extensions

    def _try_watchdog(self) -> bool:
        """Try to use watchdog library for efficient filesystem monitoring."""
        try:
            from watchdog.events import FileSystemEventHandler
            from watchdog.observers import Observer

            class _Handler(FileSystemEventHandler):
                def __init__(self_, daemon: SentinelDaemon):
                    self_._daemon = daemon

                def on_created(self_, event):
                    if not event.is_directory and self_._daemon._should_scan(Path(event.src_path)):
                        self_._daemon._handle_event(event.src_path, "created")

                def on_modified(self_, event):
                    if not event.is_directory and self_._daemon._should_scan(Path(event.src_path)):
                        self_._daemon._handle_event(event.src_path, "modified")

            observer = Observer()
            handler = _Handler(self)
            for wp in self._watch_paths:
                if wp.is_dir():
                    observer.schedule(handler, str(wp), recursive=True)
            observer.start()
            logger.info("Using watchdog for efficient filesystem monitoring")

            def _stop_observer(signum=None, frame=None):
                self._running = False
                observer.stop()

            signal.signal(signal.SIGINT, _stop_observer)
            signal.signal(signal.SIGTERM, _stop_observer)
            return True
        except ImportError:
            logger.debug("watchdog not installed; falling back to polling")
            return False
