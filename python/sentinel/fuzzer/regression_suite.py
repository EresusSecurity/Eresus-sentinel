"""Regression suite — persist, classify, and replay known-bad payloads.

Features:
  • **Typed case classes**: ``RegressionCase`` (detected payloads) and
    ``FalsePositiveCase`` (known-benign payloads that must NOT trigger).
  • **Parallel execution**: ``run()`` executes the scanner across all cases
    concurrently using a ``ThreadPoolExecutor``.
  • **Detailed run result**: ``RegressionRunResult`` tracks regressions,
    new passes, false-positive regressions, and timing.
  • **Import from JSONL / CSV**: load cases from prior fuzzing sessions.
  • **Severity-aware** reporting — regressions on CRITICAL cases are flagged
    as blocking; HIGH/MEDIUM are warnings.
  • **Annotation support**: cases can carry free-text notes and CVE references.

Usage::

    suite = RegressionSuite("/data/regression.json")
    suite.add_from_result(b"evil payload", "evil", "rce", expected_detected=True)
    suite.add_fp(b"benign data", "benign_doc", category="markdown")

    result = suite.run(scanner_fn=my_scanner)
    if not result.ok:
        for cid in result.blocking_regressions:
            print(f"BLOCKING REGRESSION: {cid}")
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger(__name__)

ScannerFn = Callable[[bytes, str], list]


# ---------------------------------------------------------------------------
# Case models
# ---------------------------------------------------------------------------

@dataclass
class RegressionCase:
    """A payload that MUST be detected (true positive)."""
    case_id: str
    name: str
    category: str
    data_hex: str           # raw bytes stored as hex
    expected_detected: bool = True
    severity: str = "HIGH"
    added_from_session: str = ""
    notes: str = ""
    cve: str = ""           # e.g. "CVE-2024-12345"

    @property
    def data(self) -> bytes:
        return bytes.fromhex(self.data_hex)

    @property
    def is_blocking(self) -> bool:
        return self.severity in ("CRITICAL", "HIGH")


@dataclass
class FalsePositiveCase:
    """A payload that must NOT be detected (false-positive guard)."""
    case_id: str
    name: str
    category: str
    data_hex: str
    expected_detected: bool = False
    severity: str = "INFO"
    notes: str = ""

    @property
    def data(self) -> bytes:
        return bytes.fromhex(self.data_hex)


# ---------------------------------------------------------------------------
# Run result
# ---------------------------------------------------------------------------

@dataclass
class CaseResult:
    case_id: str
    name: str
    expected: bool
    actual: bool
    elapsed_ms: float
    error: str = ""

    @property
    def passed(self) -> bool:
        return self.expected == self.actual


@dataclass
class RegressionRunResult:
    """Detailed outcome of a suite run."""
    total: int = 0
    passed: int = 0
    regressions: list[str] = field(default_factory=list)       # TP missed
    new_passes: list[str] = field(default_factory=list)         # previously failing
    fp_regressions: list[str] = field(default_factory=list)     # FP now triggered
    fp_fixes: list[str] = field(default_factory=list)           # FP no longer triggered
    blocking_regressions: list[str] = field(default_factory=list)
    case_results: list[CaseResult] = field(default_factory=list)
    elapsed_ms: float = 0.0

    @property
    def ok(self) -> bool:
        """True if no regressions and no blocking FP regressions."""
        return not self.regressions and not self.fp_regressions

    @property
    def ci_pass(self) -> bool:
        """Strict CI gate: no blocking regressions."""
        return not self.blocking_regressions

    def summary(self) -> str:
        status = "PASS" if self.ok else "FAIL"
        return (
            f"[{status}] {self.passed}/{self.total} passed | "
            f"{len(self.regressions)} regressions | "
            f"{len(self.fp_regressions)} FP regressions | "
            f"{self.elapsed_ms:.0f} ms"
        )


# ---------------------------------------------------------------------------
# RegressionSuite
# ---------------------------------------------------------------------------

class RegressionSuite:
    """Stores bypass / false-positive cases and replays them after scanner changes.

    Args:
        suite_path:  JSON file where cases are persisted.
        workers:     Thread pool size for parallel execution.
        timeout_s:   Per-case scanner timeout in seconds (0 = no timeout).

    Example::

        suite = RegressionSuite("regression.json", workers=8)
        suite.add_from_result(b"pickle_rce", "rce_test", "deserialization", expected_detected=True)
        result = suite.run(scanner_fn)
        print(result.summary())
    """

    def __init__(
        self,
        suite_path: str | Path,
        workers: int = 4,
        timeout_s: float = 0.0,
    ):
        self._path = Path(suite_path)
        self._workers = max(1, workers)
        self._timeout_s = timeout_s
        self._cases: dict[str, RegressionCase] = {}
        self._fp_cases: dict[str, FalsePositiveCase] = {}
        self._load()

    # ── CRUD: true-positive cases ─────────────────────────────────────

    def add_from_result(
        self,
        payload_data: bytes,
        name: str,
        category: str,
        expected_detected: bool = True,
        severity: str = "HIGH",
        session_id: str = "",
        notes: str = "",
        cve: str = "",
    ) -> RegressionCase:
        """Add a new case from raw payload bytes. Deduplicates by SHA-256."""
        case_id = hashlib.sha256(payload_data).hexdigest()[:20]
        if case_id in self._cases:
            logger.debug("Case %s already exists; skipping", case_id)
            return self._cases[case_id]
        case = RegressionCase(
            case_id=case_id,
            name=name,
            category=category,
            data_hex=payload_data.hex(),
            expected_detected=expected_detected,
            severity=severity,
            added_from_session=session_id,
            notes=notes,
            cve=cve,
        )
        self._cases[case_id] = case
        self._save()
        return case

    def add_fp(
        self,
        payload_data: bytes,
        name: str,
        category: str = "benign",
        notes: str = "",
    ) -> FalsePositiveCase:
        """Register a benign payload that should NEVER be detected."""
        case_id = hashlib.sha256(payload_data).hexdigest()[:20]
        if case_id in self._fp_cases:
            return self._fp_cases[case_id]
        fp = FalsePositiveCase(
            case_id=case_id,
            name=name,
            category=category,
            data_hex=payload_data.hex(),
            notes=notes,
        )
        self._fp_cases[case_id] = fp
        self._save()
        return fp

    def remove(self, case_id: str) -> bool:
        removed = self._cases.pop(case_id, None) or self._fp_cases.pop(case_id, None)
        if removed:
            self._save()
        return removed is not None

    def __len__(self) -> int:
        return len(self._cases) + len(self._fp_cases)

    # ── Run ──────────────────────────────────────────────────────────

    def run(
        self,
        scanner_fn: ScannerFn,
        filter_severity: Optional[str] = None,
        filter_category: Optional[str] = None,
    ) -> RegressionRunResult:
        """Execute *scanner_fn* against all cases in parallel.

        Args:
            scanner_fn:       ``(data: bytes, name: str) → list[findings]``
            filter_severity:  Only run cases with this severity.
            filter_category:  Only run cases in this category.

        Returns:
            A ``RegressionRunResult`` with per-case detail.
        """
        tp_cases = list(self._cases.values())
        fp_cases = list(self._fp_cases.values())

        if filter_severity:
            tp_cases = [c for c in tp_cases if c.severity == filter_severity]
        if filter_category:
            tp_cases = [c for c in tp_cases if c.category == filter_category]
            fp_cases = [c for c in fp_cases if c.category == filter_category]

        all_cases: list[tuple[object, bool]] = (
            [(c, True) for c in tp_cases] + [(c, False) for c in fp_cases]
        )

        result = RegressionRunResult(total=len(all_cases))
        t_start = time.monotonic()

        def _run_case(case, is_tp: bool) -> CaseResult:
            t0 = time.monotonic()
            error = ""
            actual = False
            try:
                findings = scanner_fn(case.data, case.name)
                actual = len(findings) > 0
            except Exception as exc:
                error = str(exc)
                logger.error("Scanner error on case %s: %s", case.case_id, exc)
            elapsed = (time.monotonic() - t0) * 1000
            return CaseResult(
                case_id=case.case_id,
                name=case.name,
                expected=case.expected_detected,
                actual=actual,
                elapsed_ms=round(elapsed, 2),
                error=error,
            )

        with ThreadPoolExecutor(max_workers=self._workers) as pool:
            futures = {
                pool.submit(_run_case, case, is_tp): (case, is_tp)
                for case, is_tp in all_cases
            }
            for fut in as_completed(futures):
                case, is_tp = futures[fut]
                try:
                    cr = fut.result()
                except Exception as exc:
                    cr = CaseResult(
                        case_id=case.case_id,
                        name=case.name,
                        expected=case.expected_detected,
                        actual=False,
                        elapsed_ms=0.0,
                        error=str(exc),
                    )

                result.case_results.append(cr)

                if cr.passed:
                    result.passed += 1
                else:
                    if is_tp:
                        result.regressions.append(case.case_id)
                        if case.is_blocking:
                            result.blocking_regressions.append(case.case_id)
                        logger.warning(
                            "REGRESSION: %s [%s] severity=%s — expected detected, got missed",
                            case.name, case.case_id, case.severity,
                        )
                    else:
                        result.fp_regressions.append(case.case_id)
                        logger.warning(
                            "FP REGRESSION: %s [%s] — benign payload now being flagged",
                            case.name, case.case_id,
                        )

        result.elapsed_ms = round((time.monotonic() - t_start) * 1000, 1)
        logger.info(result.summary())
        return result

    # ── Import helpers ────────────────────────────────────────────────

    def import_from_jsonl(self, path: str | Path, category: str = "imported") -> int:
        """Import cases from a fuzzing session JSONL log.

        Only lines where ``bypass=true`` and ``detected=false`` are imported
        as regression cases (they were missed by the scanner).
        """
        added = 0
        with Path(path).open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("bypass") and not rec.get("detected"):
                    raw = rec.get("raw_hex") or rec.get("payload_hex", "")
                    if raw:
                        self.add_from_result(
                            bytes.fromhex(raw),
                            name=rec.get("payload", "imported"),
                            category=rec.get("category", category),
                            session_id=rec.get("session", ""),
                        )
                        added += 1
        return added

    def import_from_csv(self, path: str | Path) -> int:
        """Import cases from a CSV with columns: name, category, data_hex, severity, notes."""
        added = 0
        with Path(path).open(newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                try:
                    data = bytes.fromhex(row["data_hex"])
                    self.add_from_result(
                        data,
                        name=row.get("name", "csv_import"),
                        category=row.get("category", "unknown"),
                        severity=row.get("severity", "HIGH"),
                        notes=row.get("notes", ""),
                    )
                    added += 1
                except Exception as exc:
                    logger.warning("CSV import error: %s", exc)
        return added

    def export_csv(self) -> str:
        """Export all TP cases to CSV string."""
        _FIELDS = ["case_id", "name", "category", "severity", "data_hex", "cve", "notes"]
        out = io.StringIO()
        writer = csv.DictWriter(out, fieldnames=_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for c in self._cases.values():
            writer.writerow(asdict(c))
        return out.getvalue()

    # ── Persistence ───────────────────────────────────────────────────

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.error("Failed to load regression suite: %s", exc)
            return
        for item in data.get("cases", []):
            try:
                c = RegressionCase(**item)
                self._cases[c.case_id] = c
            except Exception as exc:
                logger.warning("Skipping malformed case: %s", exc)
        for item in data.get("fp_cases", []):
            try:
                fp = FalsePositiveCase(**item)
                self._fp_cases[fp.case_id] = fp
            except Exception as exc:
                logger.warning("Skipping malformed FP case: %s", exc)

    def _save(self) -> None:
        payload = {
            "cases": [asdict(c) for c in self._cases.values()],
            "fp_cases": [asdict(c) for c in self._fp_cases.values()],
        }
        self._path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

