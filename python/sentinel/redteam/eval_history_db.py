"""Optional SQLite history store for eval run results."""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class EvalRunRecord:
    run_id: str
    config_id: str
    timestamp: float = field(default_factory=time.time)
    summary: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    results_json: str = ""


class EvalHistoryDB:
    """In-memory eval history with optional SQLite persistence."""

    def __init__(self, db_path: Path | None = None) -> None:
        self._records: list[EvalRunRecord] = []
        self._db_path = db_path
        if db_path and db_path.exists():
            self._load_from_file()

    def record(self, run: EvalRunRecord) -> None:
        self._records.append(run)
        if self._db_path:
            self._save_to_file()

    def get(self, run_id: str) -> EvalRunRecord | None:
        for r in self._records:
            if r.run_id == run_id:
                return r
        return None

    def list_runs(self, config_id: str | None = None, limit: int = 50) -> list[EvalRunRecord]:
        filtered = self._records
        if config_id:
            filtered = [r for r in filtered if r.config_id == config_id]
        return sorted(filtered, key=lambda r: -r.timestamp)[:limit]

    def compare(self, run_id_a: str, run_id_b: str) -> dict[str, Any]:
        a = self.get(run_id_a)
        b = self.get(run_id_b)
        if not a or not b:
            return {"error": "Run not found"}
        return {
            "run_a": run_id_a,
            "run_b": run_id_b,
            "summary_a": a.summary,
            "summary_b": b.summary,
            "timestamp_a": a.timestamp,
            "timestamp_b": b.timestamp,
        }

    @property
    def size(self) -> int:
        return len(self._records)

    def _save_to_file(self) -> None:
        if not self._db_path:
            return
        data = [
            {
                "run_id": r.run_id,
                "config_id": r.config_id,
                "timestamp": r.timestamp,
                "summary": r.summary,
                "metadata": r.metadata,
            }
            for r in self._records
        ]
        self._db_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _load_from_file(self) -> None:
        if not self._db_path or not self._db_path.exists():
            return
        try:
            data = json.loads(self._db_path.read_text(encoding="utf-8"))
            for item in data:
                self._records.append(EvalRunRecord(
                    run_id=item["run_id"],
                    config_id=item["config_id"],
                    timestamp=item.get("timestamp", 0),
                    summary=item.get("summary", {}),
                    metadata=item.get("metadata", {}),
                ))
        except Exception as e:
            logger.warning("Failed to load history from %s: %s", self._db_path, e)
