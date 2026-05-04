"""RAG Hubness Scanner — CLI-friendly wrapper around supply_chain.hubness_detector.

Exposes HubnessScanner as a sentinel.finding.Finding producer so it integrates
with the standard scan pipeline and all output formatters.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class RAGScanResult:
    index_path: str
    total_vectors: int
    findings: list  # list[Finding]
    stats: dict
    error: Optional[str] = None


class RAGHubnessScanner:
    """Scan a vector store or embedding file for adversarial hubs.

    Supported inputs:
    - JSON/JSONL file with {"id": ..., "values": [...]}
    - NumPy .npy file (2D array, each row = one vector)
    - CSV file (first column = id, remaining = float values)
    - Directory containing any of the above

    Args:
        k: k-NN neighbours to consider for hubness scoring.
        hubness_threshold: z-score threshold for flagging a hub (default 3.0).
        near_dup_threshold: cosine similarity threshold for near-duplicates.
        min_vectors: Skip scan if fewer vectors than this.
    """

    def __init__(
        self,
        k: int = 10,
        hubness_threshold: float = 3.0,
        near_dup_threshold: float = 0.995,
        min_vectors: int = 10,
    ) -> None:
        self._k = k
        self._hub_thresh = hubness_threshold
        self._dup_thresh = near_dup_threshold
        self._min = min_vectors

    def scan_path(self, path: str | Path) -> RAGScanResult:
        """Scan a file or directory for adversarial embedding anomalies."""
        p = Path(path)
        if not p.exists():
            return RAGScanResult(
                index_path=str(path),
                total_vectors=0,
                findings=[],
                stats={},
                error=f"path not found: {path}",
            )

        files = [p] if p.is_file() else list(p.rglob("*.json")) + list(p.rglob("*.jsonl")) + list(p.rglob("*.npy")) + list(p.rglob("*.csv"))

        all_findings: list = []
        total = 0
        all_stats: dict = {}

        for f in files:
            try:
                vectors, ids = self._load_vectors(f)
                if len(vectors) < self._min:
                    logger.debug("Skipping %s — only %d vectors (min %d)", f, len(vectors), self._min)
                    continue
                total += len(vectors)
                findings, stats = self._detect(str(f), vectors, ids)
                all_findings.extend(findings)
                all_stats[str(f)] = stats
            except Exception as exc:
                logger.warning("Failed to scan %s: %s", f, exc)

        return RAGScanResult(
            index_path=str(path),
            total_vectors=total,
            findings=all_findings,
            stats=all_stats,
        )

    def _detect(self, source: str, vectors: list[list[float]], ids: list[str]) -> tuple[list, dict]:
        """Delegate to supply_chain.hubness_detector then convert to Finding objects."""
        from sentinel.supply_chain.hubness_detector import EmbeddingVector, HubnessDetector
        from sentinel.finding import Finding, Severity, Module

        embedding_vectors = [
            EmbeddingVector(vector_id=vid, values=vec)
            for vid, vec in zip(ids, vectors, strict=True)
        ]

        detector = HubnessDetector(
            k=min(self._k, len(embedding_vectors) - 1),
            hubness_threshold=self._hub_thresh,
            robust_z_threshold=self._hub_thresh,
        )
        raw_findings = detector.detect(embedding_vectors)

        findings = []
        for rf in raw_findings:
            sev_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
                "info": Severity.INFO,
            }
            sev = sev_map.get(rf.severity.lower(), Severity.MEDIUM)
            rule_id = f"RAG-{rf.anomaly_type.name}"
            findings.append(Finding(
                rule_id=rule_id,
                module=Module.SUPPLY_CHAIN.value,
                title=f"RAG anomaly: {rf.anomaly_type.name.replace('_', ' ').title()}",
                description=rf.description,
                severity=sev,
                confidence=min(1.0, rf.score / max(rf.threshold, 0.001)),
                category="Vector Store Security",
                target=source,
                evidence=f"vectors={rf.vector_ids[:5]!r}, score={rf.score:.3f}, threshold={rf.threshold:.3f}",
                remediation=(
                    "Audit flagged vectors. Remove or re-embed adversarial entries. "
                    "Re-evaluate retrieval pipeline."
                ),
                tags=["rag", "vector-store", f"anomaly:{rf.anomaly_type.name.lower()}"],
            ))

        stats = {
            "vectors_scanned": len(vectors),
            "anomalies_found": len(raw_findings),
        }
        return findings, stats

    def _load_vectors(self, path: Path) -> tuple[list[list[float]], list[str]]:
        """Load vectors from file. Returns (vectors, ids)."""
        suffix = path.suffix.lower()
        if suffix in (".json", ".jsonl"):
            return self._load_json(path)
        if suffix == ".npy":
            return self._load_npy(path)
        if suffix == ".csv":
            return self._load_csv(path)
        raise ValueError(f"Unsupported format: {suffix}")

    def _load_json(self, path: Path) -> tuple[list[list[float]], list[str]]:
        vectors, ids = [], []
        text = path.read_text(encoding="utf-8")
        # Try JSONL first
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        if len(lines) > 1:
            for i, line in enumerate(lines):
                try:
                    entry = json.loads(line)
                    vec = entry.get("values") or entry.get("embedding") or entry.get("vector")
                    if vec and isinstance(vec, list):
                        vectors.append([float(x) for x in vec])
                        ids.append(str(entry.get("id", i)))
                except Exception:
                    pass
        else:
            data = json.loads(text)
            if isinstance(data, list):
                for i, entry in enumerate(data):
                    if isinstance(entry, dict):
                        vec = entry.get("values") or entry.get("embedding") or entry.get("vector")
                        if vec:
                            vectors.append([float(x) for x in vec])
                            ids.append(str(entry.get("id", i)))
                    elif isinstance(entry, list):
                        vectors.append([float(x) for x in entry])
                        ids.append(str(i))
        return vectors, ids

    def _load_npy(self, path: Path) -> tuple[list[list[float]], list[str]]:
        try:
            import numpy as np
            arr = np.load(str(path))
            if arr.ndim == 2:
                return arr.tolist(), [str(i) for i in range(len(arr))]
            raise ValueError(f"Expected 2D array, got shape {arr.shape}")
        except ImportError:
            raise RuntimeError("numpy required for .npy files — pip install numpy")

    def _load_csv(self, path: Path) -> tuple[list[list[float]], list[str]]:
        import csv
        vectors, ids = [], []
        with path.open(encoding="utf-8") as f:
            reader = csv.reader(f)
            for i, row in enumerate(reader):
                if not row:
                    continue
                try:
                    first = row[0].strip()
                    if i == 0 and not first.replace(".", "").replace("-", "").isdigit():
                        continue
                    try:
                        float(first)
                        vec = [float(x) for x in row]
                        ids.append(str(i))
                    except ValueError:
                        vec = [float(x) for x in row[1:]]
                        ids.append(first)
                    vectors.append(vec)
                except Exception:
                    pass
        return vectors, ids
