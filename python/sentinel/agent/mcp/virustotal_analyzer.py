"""VirusTotal file-hash lookup for MCP server binaries.

Requires a VirusTotal API key (free tier: 4 req/min, 500 req/day).
Set ``VIRUSTOTAL_API_KEY`` environment variable or pass ``api_key`` directly.

All network calls are optional — the analyzer degrades gracefully when the
key is absent or the VT API is unreachable.
"""
from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_VT_URL = "https://www.virustotal.com/api/v3/files/{hash}"


@dataclass
class VTResult:
    file_path: str
    sha256: str
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    total_engines: int = 0
    verdict: str = "unknown"
    permalink: str = ""
    error: Optional[str] = None
    raw: dict = field(default_factory=dict)

    @property
    def is_clean(self) -> bool:
        return self.malicious == 0 and self.suspicious == 0 and self.error is None

    @property
    def detection_ratio(self) -> float:
        if self.total_engines == 0:
            return 0.0
        return (self.malicious + self.suspicious) / self.total_engines


class VirusTotalAnalyzer:
    """Look up file hashes against VirusTotal.

    Args:
        api_key: VT API key. Defaults to ``VIRUSTOTAL_API_KEY`` env var.
        timeout: HTTP request timeout in seconds.
        malicious_threshold: Detection count above which verdict = ``malicious``.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: int = 10,
        malicious_threshold: int = 3,
    ) -> None:
        self._api_key = api_key or os.environ.get("VIRUSTOTAL_API_KEY", "")
        self._timeout = timeout
        self._malicious_threshold = malicious_threshold

    @property
    def available(self) -> bool:
        return bool(self._api_key)

    def analyze_file(self, file_path: str) -> VTResult:
        """Compute SHA-256 of *file_path* and query VirusTotal."""
        path = Path(file_path)
        if not path.exists():
            return VTResult(
                file_path=file_path,
                sha256="",
                error=f"File not found: {file_path}",
            )

        sha256 = self._sha256(path)
        if not self.available:
            logger.debug("VirusTotal API key not set; skipping lookup for %s", file_path)
            return VTResult(
                file_path=file_path,
                sha256=sha256,
                verdict="skipped",
                error="No API key configured",
            )

        return self._query(file_path, sha256)

    def analyze_bytes(self, data: bytes, source: str = "<bytes>") -> VTResult:
        """Compute SHA-256 of *data* bytes and query VirusTotal."""
        sha256 = hashlib.sha256(data).hexdigest()
        if not self.available:
            return VTResult(
                file_path=source,
                sha256=sha256,
                verdict="skipped",
                error="No API key configured",
            )
        return self._query(source, sha256)

    def _query(self, source: str, sha256: str) -> VTResult:
        try:
            import json
            import urllib.request

            url = _VT_URL.format(hash=sha256)
            req = urllib.request.Request(
                url,
                headers={"x-apikey": self._api_key, "Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read())

            stats = (
                data.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            harmless = int(stats.get("harmless", 0))
            undetected = int(stats.get("undetected", 0))
            total = malicious + suspicious + harmless + undetected

            if malicious >= self._malicious_threshold:
                verdict = "malicious"
            elif suspicious > 0:
                verdict = "suspicious"
            elif total > 0:
                verdict = "clean"
            else:
                verdict = "unknown"

            permalink = (
                data.get("data", {})
                .get("links", {})
                .get("self", "")
            )

            return VTResult(
                file_path=source,
                sha256=sha256,
                malicious=malicious,
                suspicious=suspicious,
                harmless=harmless,
                undetected=undetected,
                total_engines=total,
                verdict=verdict,
                permalink=permalink,
                raw=data,
            )

        except Exception as exc:
            logger.warning("VirusTotal lookup failed for %s (%s): %s", source, sha256, exc)
            return VTResult(
                file_path=source,
                sha256=sha256,
                verdict="error",
                error=str(exc),
            )

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
