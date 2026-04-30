"""Vector database adapters for adversarial hubness scanning.

Fetches embedding vectors from Pinecone, Qdrant, Weaviate, and FAISS
and returns them as ``EmbeddingVector`` objects ready for hubness analysis.

Usage::

    from sentinel.supply_chain.hubness_adapters import (
        PineconeAdapter, QdrantAdapter, WeaviateAdapter, FAISSAdapter,
        AdversarialHubnessScannerWithAdapters,
    )

    # Scan a Pinecone index
    adapter = PineconeAdapter(api_key="...", index_name="my-index")
    vectors = adapter.fetch_vectors(sample_size=1000)

    from sentinel.supply_chain.hubness_detector import HubnessDetector
    findings = HubnessDetector().detect(vectors)

    # Or use the all-in-one scanner
    scanner = AdversarialHubnessScannerWithAdapters("pinecone", api_key="...", index_name="my-index")
    findings = scanner.scan(sample_size=1000)
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from sentinel.supply_chain.hubness_detector import (
    ConceptAwareHubnessDetector,
    EmbeddingVector,
    HubnessDetector,
    HubnessFinding,
    ModalityAwareHubnessDetector,
)

logger = logging.getLogger(__name__)


class VectorDBAdapter(ABC):
    """Abstract base class for vector database adapters."""

    @abstractmethod
    def fetch_vectors(self, sample_size: int = 500) -> list[EmbeddingVector]:
        """Fetch up to *sample_size* vectors from the database."""
        ...

    @property
    @abstractmethod
    def backend_name(self) -> str:
        ...


# ── Pinecone ─────────────────────────────────────────────────────────


class PineconeAdapter(VectorDBAdapter):
    """Adapter for Pinecone vector database.

    Requires ``pinecone-client`` package (``pip install pinecone-client``).

    Args:
        api_key: Pinecone API key (falls back to PINECONE_API_KEY env var).
        index_name: Name of the Pinecone index to scan.
        environment: Pinecone environment (e.g. "us-east1-gcp").
        namespace: Pinecone namespace (optional).
    """

    backend_name = "pinecone"

    def __init__(
        self,
        api_key: str = "",
        index_name: str = "",
        environment: str = "",
        namespace: str = "",
    ) -> None:
        import os
        self._api_key = api_key or os.environ.get("PINECONE_API_KEY", "")
        self._index_name = index_name
        self._environment = environment or os.environ.get("PINECONE_ENVIRONMENT", "")
        self._namespace = namespace

    def fetch_vectors(self, sample_size: int = 500) -> list[EmbeddingVector]:
        try:
            import pinecone  # type: ignore[import]
        except ImportError as exc:
            raise RuntimeError("pinecone-client not installed") from exc

        pc = pinecone.Pinecone(api_key=self._api_key)
        index = pc.Index(self._index_name)
        stats = index.describe_index_stats()
        total = stats.get("total_vector_count", 0)
        if total == 0:
            logger.warning("Pinecone index %r is empty", self._index_name)
            return []

        # Use list + fetch for sampling
        vectors: list[EmbeddingVector] = []
        try:
            listed = index.list(namespace=self._namespace, limit=min(sample_size, total))
            ids_batch = [item for item in listed]
            if not ids_batch:
                return []
            fetch_result = index.fetch(ids=ids_batch[:sample_size], namespace=self._namespace)
            for vid, vdata in fetch_result.vectors.items():
                vectors.append(EmbeddingVector(
                    vector_id=vid,
                    values=list(vdata.values),
                    metadata=vdata.metadata or {},
                ))
        except Exception as exc:
            logger.error("Pinecone fetch failed: %s", exc)

        return vectors


# ── Qdrant ───────────────────────────────────────────────────────────


class QdrantAdapter(VectorDBAdapter):
    """Adapter for Qdrant vector database.

    Requires ``qdrant-client`` package (``pip install qdrant-client``).

    Args:
        url: Qdrant server URL (defaults to http://localhost:6333).
        api_key: Qdrant API key (optional; for Qdrant Cloud).
        collection_name: Name of the collection to scan.
    """

    backend_name = "qdrant"

    def __init__(
        self,
        url: str = "http://localhost:6333",
        api_key: str = "",
        collection_name: str = "",
    ) -> None:
        import os
        self._url = url or os.environ.get("QDRANT_URL", "http://localhost:6333")
        self._api_key = api_key or os.environ.get("QDRANT_API_KEY", "")
        self._collection_name = collection_name

    def fetch_vectors(self, sample_size: int = 500) -> list[EmbeddingVector]:
        try:
            from qdrant_client import QdrantClient  # type: ignore[import]
            from qdrant_client.models import PointStruct  # type: ignore[import]
        except ImportError as exc:
            raise RuntimeError("qdrant-client not installed") from exc

        kwargs: dict[str, Any] = {"url": self._url}
        if self._api_key:
            kwargs["api_key"] = self._api_key
        client = QdrantClient(**kwargs)

        try:
            points, _next = client.scroll(
                collection_name=self._collection_name,
                limit=sample_size,
                with_vectors=True,
                with_payload=True,
            )
        except Exception as exc:
            logger.error("Qdrant scroll failed: %s", exc)
            return []

        vectors: list[EmbeddingVector] = []
        for point in points:
            vec = point.vector
            if vec is None:
                continue
            if isinstance(vec, dict):
                # Named vectors — use the first one
                vec = next(iter(vec.values()), [])
            vectors.append(EmbeddingVector(
                vector_id=str(point.id),
                values=list(vec),
                metadata=point.payload or {},
            ))
        return vectors


# ── Weaviate ─────────────────────────────────────────────────────────


class WeaviateAdapter(VectorDBAdapter):
    """Adapter for Weaviate vector database.

    Requires ``weaviate-client`` package (``pip install weaviate-client``).

    Args:
        url: Weaviate server URL (defaults to http://localhost:8080).
        api_key: Weaviate API key (optional).
        class_name: Name of the Weaviate class (collection) to scan.
        concept_field: Metadata field used as concept label.
    """

    backend_name = "weaviate"

    def __init__(
        self,
        url: str = "http://localhost:8080",
        api_key: str = "",
        class_name: str = "",
        concept_field: str = "category",
    ) -> None:
        import os
        self._url = url or os.environ.get("WEAVIATE_URL", "http://localhost:8080")
        self._api_key = api_key or os.environ.get("WEAVIATE_API_KEY", "")
        self._class_name = class_name
        self._concept_field = concept_field

    def fetch_vectors(self, sample_size: int = 500) -> list[EmbeddingVector]:
        try:
            import weaviate  # type: ignore[import]
        except ImportError as exc:
            raise RuntimeError("weaviate-client not installed") from exc

        auth = weaviate.auth.AuthApiKey(api_key=self._api_key) if self._api_key else None
        client = weaviate.connect_to_custom(
            http_host=self._url.split("://")[-1].split(":")[0],
            http_port=int(self._url.split(":")[-1]) if ":" in self._url.split("://")[-1] else 8080,
            http_secure="https" in self._url,
            grpc_host=None,
            auth_credentials=auth,
        )

        vectors: list[EmbeddingVector] = []
        try:
            collection = client.collections.get(self._class_name)
            for item in collection.iterator(include_vector=True):
                if len(vectors) >= sample_size:
                    break
                vec = item.vector.get("default") if isinstance(item.vector, dict) else item.vector
                if vec is None:
                    continue
                metadata = dict(item.properties) if item.properties else {}
                label = str(metadata.get(self._concept_field, ""))
                vectors.append(EmbeddingVector(
                    vector_id=str(item.uuid),
                    values=list(vec),
                    metadata=metadata,
                    label=label,
                ))
        except Exception as exc:
            logger.error("Weaviate fetch failed: %s", exc)
        finally:
            client.close()

        return vectors


# ── FAISS ────────────────────────────────────────────────────────────


class FAISSAdapter(VectorDBAdapter):
    """Adapter for FAISS index files.

    Requires ``faiss-cpu`` or ``faiss-gpu`` package.

    Args:
        index_path: Path to the ``.faiss`` index file.
        metadata_path: Optional path to a JSONL file with per-vector metadata.
    """

    backend_name = "faiss"

    def __init__(self, index_path: str = "", metadata_path: str = "") -> None:
        self._index_path = index_path
        self._metadata_path = metadata_path

    def fetch_vectors(self, sample_size: int = 500) -> list[EmbeddingVector]:
        try:
            import faiss  # type: ignore[import]
            import numpy as np  # type: ignore[import]
        except ImportError as exc:
            raise RuntimeError("faiss-cpu and numpy not installed") from exc

        import json

        index = faiss.read_index(self._index_path)
        n = index.ntotal
        if n == 0:
            return []

        sample_n = min(sample_size, n)
        # Reconstruct a contiguous block of vectors
        try:
            vectors_np = np.zeros((sample_n, index.d), dtype="float32")
            for i in range(sample_n):
                index.reconstruct(i, vectors_np[i])
        except Exception as exc:
            logger.error("FAISS reconstruct failed: %s", exc)
            return []

        # Load metadata if provided
        meta_rows: list[dict[str, Any]] = []
        if self._metadata_path:
            try:
                with open(self._metadata_path, encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if line:
                            meta_rows.append(json.loads(line))
            except Exception as exc:
                logger.warning("Could not load FAISS metadata: %s", exc)

        embedding_vectors: list[EmbeddingVector] = []
        for i in range(sample_n):
            meta = meta_rows[i] if i < len(meta_rows) else {}
            embedding_vectors.append(EmbeddingVector(
                vector_id=str(i),
                values=vectors_np[i].tolist(),
                metadata=meta,
                label=str(meta.get("label", meta.get("category", ""))),
            ))
        return embedding_vectors


# ── All-in-one scanner ───────────────────────────────────────────────


@dataclass
class HubnessAdapterScanResult:
    backend: str
    source: str
    vectors_scanned: int
    findings: list[HubnessFinding] = field(default_factory=list)
    error: str = ""

    @property
    def blocked(self) -> bool:
        return any(f.severity in ("CRITICAL", "HIGH") for f in self.findings)

    def summary(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "source": self.source,
            "vectors_scanned": self.vectors_scanned,
            "total_findings": len(self.findings),
            "blocked": self.blocked,
            "by_type": {
                t: sum(1 for f in self.findings if f.anomaly_type.name == t)
                for t in {f.anomaly_type.name for f in self.findings}
            },
            "error": self.error,
        }


_ADAPTER_REGISTRY: dict[str, type[VectorDBAdapter]] = {
    "pinecone": PineconeAdapter,
    "qdrant": QdrantAdapter,
    "weaviate": WeaviateAdapter,
    "faiss": FAISSAdapter,
}


class AdversarialHubnessScannerWithAdapters:
    """Fetch vectors from a supported vector DB and run full hubness analysis.

    Combines ``HubnessDetector``, ``ConceptAwareHubnessDetector``, and
    ``ModalityAwareHubnessDetector`` in a single scan pass.

    Args:
        backend: "pinecone", "qdrant", "weaviate", or "faiss".
        concept_field: Metadata field used for concept-aware detection.
        modality_field: Metadata field used for modality-aware detection.
        **adapter_kwargs: Forwarded to the selected adapter constructor.
    """

    def __init__(
        self,
        backend: str,
        concept_field: str = "concept",
        modality_field: str = "modality",
        **adapter_kwargs: Any,
    ) -> None:
        if backend not in _ADAPTER_REGISTRY:
            raise ValueError(f"Unknown backend {backend!r}. Available: {list(_ADAPTER_REGISTRY)}")
        self._adapter: VectorDBAdapter = _ADAPTER_REGISTRY[backend](**adapter_kwargs)
        self._concept_field = concept_field
        self._modality_field = modality_field

    def scan(self, sample_size: int = 500) -> HubnessAdapterScanResult:
        try:
            vectors = self._adapter.fetch_vectors(sample_size=sample_size)
        except Exception as exc:
            return HubnessAdapterScanResult(
                backend=self._adapter.backend_name,
                source="",
                vectors_scanned=0,
                error=str(exc),
            )

        if not vectors:
            return HubnessAdapterScanResult(
                backend=self._adapter.backend_name,
                source="",
                vectors_scanned=0,
            )

        findings: list[HubnessFinding] = []
        findings.extend(HubnessDetector().detect(vectors))
        findings.extend(ConceptAwareHubnessDetector().detect(vectors, self._concept_field))
        findings.extend(ModalityAwareHubnessDetector().detect(vectors, self._modality_field))

        return HubnessAdapterScanResult(
            backend=self._adapter.backend_name,
            source="",
            vectors_scanned=len(vectors),
            findings=findings,
        )


def list_adapters() -> list[str]:
    return list(_ADAPTER_REGISTRY.keys())
