"""Weight distribution anomaly detection for ML model backdoor/trojan detection."""
from __future__ import annotations

import logging
from pathlib import Path

from ...finding import Finding, Severity

logger = logging.getLogger(__name__)

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False


class WeightDistributionScanner:
    """Statistical weight analysis — detects anomalous distributions indicating backdoors."""

    def scan_file(self, filepath: str) -> list[Finding]:
        if not HAS_NUMPY:
            return []
        findings: list[Finding] = []
        path = Path(filepath)
        tensors = self._load_tensors(path)
        if tensors:
            findings.extend(self.scan_tensors(tensors, filepath))
        return findings

    def scan_tensors(self, tensors: dict, filepath: str = "") -> list[Finding]:
        findings: list[Finding] = []
        layer_stats = {}
        for name, arr in tensors.items():
            if not isinstance(arr, np.ndarray) or arr.size == 0:
                continue
            flat = arr.flatten().astype(np.float64)
            stats = {
                "mean": float(np.mean(flat)),
                "std": float(np.std(flat)),
                "min": float(np.min(flat)),
                "max": float(np.max(flat)),
                "zero_ratio": float(np.sum(flat == 0) / flat.size),
                "near_zero_ratio": float(np.sum(np.abs(flat) < 1e-7) / flat.size),
                "size": flat.size,
            }
            n = flat.size
            if n > 3:
                m = stats["mean"]
                s = max(stats["std"], 1e-10)
                stats["kurtosis"] = float(np.mean(((flat - m) / s) ** 4) - 3.0)
                stats["skewness"] = float(np.mean(((flat - m) / s) ** 3))
            else:
                stats["kurtosis"] = 0.0
                stats["skewness"] = 0.0
            layer_stats[name] = stats

            if abs(stats["kurtosis"]) > 50:
                findings.append(Finding.artifact(
                    rule_id="WEIGHT-001", title=f"Extreme kurtosis in layer {name}",
                    description=f"Kurtosis={stats['kurtosis']:.1f} — may indicate backdoor trigger patch",
                    severity=Severity.HIGH, target=filepath, evidence=f"kurtosis={stats['kurtosis']:.2f}",
                ))
            if stats["std"] < 1e-10 and stats["size"] > 100:
                findings.append(Finding.artifact(
                    rule_id="WEIGHT-002", title=f"Zero-variance layer: {name}",
                    description="All weights identical — possibly corrupted or zeroed",
                    severity=Severity.MEDIUM, target=filepath,
                ))
            if stats["zero_ratio"] > 0.99 and stats["size"] > 1000:
                findings.append(Finding.artifact(
                    rule_id="WEIGHT-003", title=f"Near-empty layer: {name}",
                    description=f"{stats['zero_ratio']*100:.1f}% zeros",
                    severity=Severity.MEDIUM, target=filepath,
                ))
            max_abs = max(abs(stats["min"]), abs(stats["max"]))
            if max_abs > 1e6 and stats["std"] < 1:
                findings.append(Finding.artifact(
                    rule_id="WEIGHT-004", title=f"Outlier spike in layer {name}",
                    description=f"Max magnitude {max_abs:.0f} with std {stats['std']:.4f} — localized trigger",
                    severity=Severity.HIGH, target=filepath,
                ))

        if len(layer_stats) > 3:
            means = [s["mean"] for s in layer_stats.values() if s["size"] > 100]
            stds = [s["std"] for s in layer_stats.values() if s["size"] > 100]
            if means and stds:
                global_mean = sum(means) / len(means)
                global_std_of_means = (sum((m - global_mean)**2 for m in means) / len(means)) ** 0.5
                if global_std_of_means > 0:
                    for name, stats in layer_stats.items():
                        if stats["size"] > 100:
                            z = abs(stats["mean"] - global_mean) / max(global_std_of_means, 1e-10)
                            if z > 5:
                                findings.append(Finding.artifact(
                                    rule_id="WEIGHT-005", title=f"Statistical outlier layer: {name}",
                                    description=f"Layer mean deviates {z:.1f} sigma from other layers",
                                    severity=Severity.HIGH, target=filepath,
                                    evidence=f"z_score={z:.2f}",
                                ))
        return findings

    def _load_tensors(self, path: Path) -> dict:
        suffix = path.suffix.lower()
        if suffix == ".safetensors":
            return self._load_safetensors(path)
        if suffix in (".npy", ".npz"):
            return self._load_numpy(path)
        return {}

    def _load_safetensors(self, path: Path) -> dict:
        try:
            import safetensors.numpy
            return safetensors.numpy.load_file(str(path))
        except Exception:
            return {}

    def _load_numpy(self, path: Path) -> dict:
        try:
            if path.suffix == ".npz":
                data = np.load(str(path), allow_pickle=False)
                return dict(data)
            arr = np.load(str(path), allow_pickle=False)
            return {"array": arr}
        except Exception:
            return {}


class WeightAnomalyDetector:
    """Backdoor detection via weight anomaly patterns."""

    def scan_tensors(self, tensors: dict, filepath: str = "") -> list[Finding]:
        if not HAS_NUMPY:
            return []
        findings: list[Finding] = []
        for name, arr in tensors.items():
            if not isinstance(arr, np.ndarray) or arr.size < 100:
                continue
            flat = arr.flatten().astype(np.float64)
            mean, std = float(np.mean(flat)), float(np.std(flat))
            if std < 1e-10:
                continue
            outlier_mask = np.abs(flat - mean) > 5 * std
            outlier_ratio = float(np.sum(outlier_mask) / flat.size)
            if 0.0001 < outlier_ratio < 0.01:
                findings.append(Finding.artifact(
                    rule_id="WEIGHT-ANOMALY-001",
                    title=f"Potential trigger patch in {name}",
                    description=f"{outlier_ratio*100:.3f}% outliers (5σ) — consistent with backdoor insertion",
                    severity=Severity.HIGH, target=filepath,
                    evidence=f"outlier_ratio={outlier_ratio:.5f}",
                ))
        return findings


class WeightEntropyAnalyzer:
    """Shannon entropy per tensor layer."""

    def scan_tensors(self, tensors: dict, filepath: str = "") -> list[Finding]:
        if not HAS_NUMPY:
            return []
        findings: list[Finding] = []
        entropies = {}
        for name, arr in tensors.items():
            if not isinstance(arr, np.ndarray) or arr.size < 100:
                continue
            flat = arr.flatten()
            quantized = np.round(flat * 1000).astype(np.int64)
            unique, counts = np.unique(quantized, return_counts=True)
            probs = counts / counts.sum()
            entropy = -float(np.sum(probs * np.log2(probs + 1e-10)))
            entropies[name] = entropy

        if len(entropies) > 3:
            vals = list(entropies.values())
            mean_e = sum(vals) / len(vals)
            std_e = (sum((v - mean_e)**2 for v in vals) / len(vals)) ** 0.5
            for name, e in entropies.items():
                if std_e > 0 and abs(e - mean_e) > 3 * std_e:
                    findings.append(Finding.artifact(
                        rule_id="WEIGHT-ENTROPY-001",
                        title=f"Entropy anomaly in {name}",
                        description=f"Entropy={e:.2f} deviates from mean={mean_e:.2f}±{std_e:.2f}",
                        severity=Severity.MEDIUM, target=filepath,
                        evidence=f"entropy={e:.2f}",
                    ))
        return findings


class WeightClusteringDetector:
    """K-means clustering for trojan detection."""

    def scan_tensors(self, tensors: dict, filepath: str = "") -> list[Finding]:
        if not HAS_NUMPY:
            return []
        findings: list[Finding] = []
        for name, arr in tensors.items():
            if not isinstance(arr, np.ndarray) or arr.size < 1000:
                continue
            flat = arr.flatten().astype(np.float64)
            sample = flat[np.random.choice(flat.size, min(10000, flat.size), replace=False)]
            centers = self._kmeans_1d(sample, k=3, iterations=20)
            if centers is not None:
                sorted_c = sorted(centers)
                if len(sorted_c) == 3:
                    gap1 = sorted_c[1] - sorted_c[0]
                    gap2 = sorted_c[2] - sorted_c[1]
                    if gap1 > 0 and gap2 / max(gap1, 1e-10) > 10:
                        findings.append(Finding.artifact(
                            rule_id="WEIGHT-CLUSTER-001",
                            title=f"Asymmetric cluster in {name}",
                            description="Weight clusters show asymmetric gaps — possible trojan signature",
                            severity=Severity.MEDIUM, target=filepath,
                            evidence=f"centers={sorted_c}",
                        ))
        return findings

    def _kmeans_1d(self, data, k=3, iterations=20):
        try:
            n = len(data)
            if n < k:
                return None
            centers = np.array([data[int(i * n / k)] for i in range(k)])
            for _ in range(iterations):
                dists = np.abs(data[:, None] - centers[None, :])
                labels = np.argmin(dists, axis=1)
                new_centers = np.array([data[labels == i].mean() if np.sum(labels == i) > 0 else centers[i] for i in range(k)])
                if np.allclose(centers, new_centers):
                    break
                centers = new_centers
            return centers.tolist()
        except Exception:
            return None
