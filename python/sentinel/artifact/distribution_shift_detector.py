"""Distribution shift detector for model weight files.

Compares the empirical distribution of weight values against the expected
distribution for neural network parameters (typically Gaussian / Laplace
with zero mean).  Statistically significant deviations may indicate:

- Weight poisoning / backdoor implantation
- Adversarial fine-tuning on malicious data
- Bit-flip / hardware fault injection

Uses ``numpy`` and ``scipy.stats`` (both available under the ``[analysis]``
extra — no GPU required).
"""
from __future__ import annotations

import logging
import struct
from pathlib import Path
from typing import Optional

from sentinel.finding import Finding, Severity

logger = logging.getLogger(__name__)

_SAFETENSORS_HEADER_SIZE_MAX = 128 * 1024  # 128 KB


def _read_safetensors_weights(path: Path, max_floats: int = 100_000) -> Optional["np.ndarray"]:  # type: ignore[name-defined]
    """Extract a sample of float32 values from a safetensors file."""
    try:
        import numpy as np
        with open(path, "rb") as fh:
            # Header: 8-byte LE uint64 = header_size, then JSON header
            raw_size = fh.read(8)
            if len(raw_size) < 8:
                return None
            header_size = struct.unpack("<Q", raw_size)[0]
            if header_size > _SAFETENSORS_HEADER_SIZE_MAX:
                return None
            fh.seek(8 + header_size)
            # Read raw float32 data
            raw = fh.read(max_floats * 4)
        arr = np.frombuffer(raw[: (len(raw) // 4) * 4], dtype=np.float32)
        arr = arr[np.isfinite(arr)]  # Remove NaN/Inf
        return arr
    except Exception as exc:
        logger.debug("safetensors weight read failed: %s", exc)
        return None


def _read_torch_weights(path: Path, max_floats: int = 100_000) -> Optional["np.ndarray"]:  # type: ignore[name-defined]
    """Extract float32 weight samples from a PyTorch checkpoint (no torch dep)."""
    # PyTorch .pt/.pth are ZIP archives containing a pickle file + storage files
    try:
        import zipfile

        import numpy as np

        if not zipfile.is_zipfile(str(path)):
            return None

        with zipfile.ZipFile(str(path), "r") as zf:
            names = zf.namelist()
            # Look for data files (raw tensor storage)
            storage_files = [n for n in names if "/data/" in n or n.endswith(".storage")]
            if not storage_files:
                return None
            raw = zf.read(storage_files[0])
            arr = np.frombuffer(raw[: (len(raw) // 4) * 4], dtype=np.float32)
            arr = arr[np.isfinite(arr)]
            return arr[:max_floats]
    except Exception as exc:
        logger.debug("torch weight read failed: %s", exc)
        return None


def _analyze_distribution(weights: "np.ndarray") -> dict:  # type: ignore[name-defined]
    """Run KS-test against Gaussian and Laplace distributions."""
    import numpy as np
    from scipy import stats  # type: ignore[import]

    if len(weights) < 1000:
        return {"skip": True, "reason": "insufficient samples"}

    # Normalise to zero-mean unit-variance for comparison
    mean = float(np.mean(weights))
    std = max(float(np.std(weights)), 1e-9)
    norm = (weights - mean) / std

    ks_gauss, p_gauss = stats.kstest(norm, "norm")
    ks_laplace, p_laplace = stats.kstest(norm, "laplace")
    skew = float(stats.skew(norm))
    kurt = float(stats.kurtosis(norm))

    return {
        "n": len(weights),
        "mean": mean,
        "std": std,
        "skew": skew,
        "kurtosis": kurt,
        "ks_gaussian": ks_gauss,
        "p_gaussian": p_gauss,
        "ks_laplace": ks_laplace,
        "p_laplace": p_laplace,
    }


class DistributionShiftDetector:
    """Detects anomalous weight distributions in model files.

    Supported formats: ``.safetensors``, ``.pt``, ``.pth``, ``.bin``, ``.ckpt``

    A Kolmogorov-Smirnov test is run against both Gaussian and Laplace
    reference distributions.  If both p-values fall below 0.01 the weights
    are flagged.  Severity is scaled by the KS statistic.
    """

    SUPPORTED_EXTENSIONS = frozenset({
        ".safetensors", ".pt", ".pth", ".bin", ".ckpt",
    })

    # p-value threshold for flagging
    P_THRESHOLD = 0.01

    def scan_file(self, file_path: str | Path) -> list[Finding]:
        try:
            import numpy  # noqa: F401 — confirm numpy is available
            from scipy import stats  # noqa: F401
        except ImportError:
            logger.debug(
                "DistributionShiftDetector requires numpy + scipy — "
                "install with: pip install 'eresus-sentinel[analysis]'"
            )
            return []

        path = Path(file_path)
        if path.suffix.lower() not in self.SUPPORTED_EXTENSIONS:
            return []

        # Extract weight sample
        weights = None
        if path.suffix.lower() == ".safetensors":
            weights = _read_safetensors_weights(path)
        elif path.suffix.lower() in (".pt", ".pth", ".bin", ".ckpt"):
            weights = _read_torch_weights(path)

        if weights is None or len(weights) < 1000:
            return []

        stats_result = _analyze_distribution(weights)
        if stats_result.get("skip"):
            return []

        findings: list[Finding] = []

        p_gauss = stats_result["p_gaussian"]
        p_laplace = stats_result["p_laplace"]
        ks_gauss = stats_result["ks_gaussian"]
        skew = stats_result["skew"]
        kurt = stats_result["kurtosis"]

        # Both Gaussian and Laplace rejected → significant anomaly
        if p_gauss < self.P_THRESHOLD and p_laplace < self.P_THRESHOLD:
            severity = Severity.HIGH if ks_gauss > 0.15 else Severity.MEDIUM
            findings.append(Finding.artifact(
                rule_id="DIST-001",
                title="Anomalous weight distribution — possible weight poisoning",
                description=(
                    "The weight distribution deviates significantly from both Gaussian "
                    "and Laplace reference distributions (KS test p < 0.01). This may "
                    "indicate backdoor implantation, adversarial fine-tuning, or "
                    "bit-flip injection in model weights."
                ),
                severity=severity,
                target=str(path),
                evidence=(
                    f"n={stats_result['n']}, "
                    f"ks_gaussian={ks_gauss:.4f}, p_gaussian={p_gauss:.4e}, "
                    f"skewness={skew:.3f}, kurtosis={kurt:.3f}"
                ),
                confidence=0.7,
                cwe_ids=["CWE-506"],
            ))

        # High kurtosis alone → heavy-tailed (potential targeted weight spikes)
        elif abs(kurt) > 10:
            findings.append(Finding.artifact(
                rule_id="DIST-002",
                title="High weight kurtosis — possible targeted weight spikes",
                description=(
                    f"Excess kurtosis of {kurt:.1f} indicates heavy tails in the weight "
                    "distribution. Extremely large outlier weights can be signatures of "
                    "backdoor triggers or targeted adversarial modifications."
                ),
                severity=Severity.LOW,
                target=str(path),
                evidence=f"kurtosis={kurt:.3f}, skewness={skew:.3f}",
                confidence=0.45,
                cwe_ids=["CWE-506"],
            ))

        # Strong skew (weights biased in one direction)
        if abs(skew) > 2.0 and not findings:
            findings.append(Finding.artifact(
                rule_id="DIST-003",
                title="Skewed weight distribution",
                description=(
                    f"Weight distribution skewness ({skew:.2f}) exceeds ±2.0. "
                    "Strong asymmetry in weights can indicate adversarial bias injection."
                ),
                severity=Severity.LOW,
                target=str(path),
                evidence=f"skewness={skew:.3f}",
                confidence=0.35,
            ))

        return findings
