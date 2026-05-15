from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from sentinel.platform.formats import stable_sha256


def stable_id(kind: str, value: Any) -> str:
    return f"{kind}_{stable_sha256(value)[:24]}"


class RunStore:
    def __init__(self, path: str | Path = ".sentinel/runs/state.db") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self.init()

    def init(self) -> None:
        with self.lock:
            self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    id TEXT PRIMARY KEY,
                    schema_version TEXT NOT NULL,
                    name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    started_at REAL NOT NULL,
                    finished_at REAL,
                    config_json TEXT NOT NULL,
                    summary_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS cells (
                    id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    model TEXT NOT NULL,
                    prompt_id TEXT NOT NULL,
                    dataset_id TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    output TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS provider_calls (
                    id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    cell_id TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    model TEXT NOT NULL,
                    latency_ms INTEGER NOT NULL,
                    input_tokens INTEGER NOT NULL,
                    output_tokens INTEGER NOT NULL,
                    cost_usd REAL NOT NULL,
                    metadata_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS assertions (
                    id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    cell_id TEXT NOT NULL,
                    type TEXT NOT NULL,
                    passed INTEGER NOT NULL,
                    score REAL NOT NULL,
                    message TEXT NOT NULL,
                    evidence_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS traces (
                    id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    cell_id TEXT,
                    event_type TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    payload_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS baselines (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    summary_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS artifacts (
                    id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    path TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                );
                """
            )
            self.conn.commit()

    def put_run(self, run: dict[str, Any]) -> None:
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run["id"],
                    run["schema_version"],
                    run["name"],
                    run["status"],
                    run["fingerprint"],
                    run["started_at"],
                    run.get("finished_at"),
                    json.dumps(run["config"], sort_keys=True),
                    json.dumps(run.get("summary", {}), sort_keys=True),
                ),
            )
            self.conn.commit()

    def put_cell(self, cell: dict[str, Any]) -> None:
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO cells VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    cell["id"],
                    cell["run_id"],
                    cell["provider"],
                    cell["model"],
                    cell["prompt_id"],
                    cell["dataset_id"],
                    cell["record_id"],
                    cell["status"],
                    cell["output"],
                    json.dumps(cell.get("metadata", {}), sort_keys=True),
                ),
            )
            self.conn.commit()

    def put_provider_call(self, call: dict[str, Any]) -> None:
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO provider_calls VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    call["id"],
                    call["run_id"],
                    call["cell_id"],
                    call["provider"],
                    call["model"],
                    int(call["latency_ms"]),
                    int(call["input_tokens"]),
                    int(call["output_tokens"]),
                    float(call["cost_usd"]),
                    json.dumps(call.get("metadata", {}), sort_keys=True),
                ),
            )
            self.conn.commit()

    def put_assertion(self, assertion: dict[str, Any]) -> None:
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO assertions VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    assertion["id"],
                    assertion["run_id"],
                    assertion["cell_id"],
                    assertion["type"],
                    1 if assertion["passed"] else 0,
                    float(assertion["score"]),
                    assertion["message"],
                    json.dumps(assertion.get("evidence", {}), sort_keys=True),
                ),
            )
            self.conn.commit()

    def put_trace(self, run_id: str, event_type: str, payload: dict[str, Any], cell_id: str | None = None) -> str:
        trace_id = stable_id("trace", {"run_id": run_id, "event_type": event_type, "payload": payload, "time": time.time_ns()})
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO traces VALUES (?, ?, ?, ?, ?, ?)",
                (trace_id, run_id, cell_id, event_type, time.time(), json.dumps(payload, sort_keys=True)),
            )
            self.conn.commit()
        return trace_id

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self.lock:
            row = self.conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
            if not row:
                return None
            cells = [self._row_cell(item) for item in self.conn.execute("SELECT * FROM cells WHERE run_id = ? ORDER BY id", (run_id,)).fetchall()]
            assertions = [self._row_assertion(item) for item in self.conn.execute("SELECT * FROM assertions WHERE run_id = ? ORDER BY id", (run_id,)).fetchall()]
            traces = [self._row_trace(item) for item in self.conn.execute("SELECT * FROM traces WHERE run_id = ? ORDER BY timestamp", (run_id,)).fetchall()]
        if not row:
            return None
        return {
            "id": row["id"],
            "schema_version": row["schema_version"],
            "name": row["name"],
            "status": row["status"],
            "fingerprint": row["fingerprint"],
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
            "config": json.loads(row["config_json"]),
            "summary": json.loads(row["summary_json"]),
            "cells": cells,
            "assertions": assertions,
            "traces": traces,
        }

    def list_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute("SELECT * FROM runs ORDER BY started_at DESC LIMIT ?", (limit,)).fetchall()
        return [
            {
                "id": row["id"],
                "name": row["name"],
                "status": row["status"],
                "fingerprint": row["fingerprint"],
                "started_at": row["started_at"],
                "finished_at": row["finished_at"],
                "summary": json.loads(row["summary_json"]),
            }
            for row in rows
        ]

    def put_baseline(self, name: str, run_id: str, summary: dict[str, Any]) -> str:
        baseline_id = stable_id("baseline", {"name": name, "run_id": run_id})
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO baselines VALUES (?, ?, ?, ?, ?)",
                (baseline_id, name, run_id, time.time(), json.dumps(summary, sort_keys=True)),
            )
            self.conn.commit()
        return baseline_id

    def _row_cell(self, row: sqlite3.Row) -> dict[str, Any]:
        return {**dict(row), "metadata": json.loads(row["metadata_json"])}

    def _row_assertion(self, row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        data["passed"] = bool(data["passed"])
        data["evidence"] = json.loads(data.pop("evidence_json"))
        return data

    def _row_trace(self, row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        data["payload"] = json.loads(data.pop("payload_json"))
        return data
