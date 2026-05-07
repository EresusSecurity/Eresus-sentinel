"""Weight distribution anomaly / trojan detection for model files.

Detects potential neural trojans via four statistical analyses:
  1. Z-score outlier detection on per-neuron weight norms
  2. Cosine similarity dissimilarity (isolated neurons)
  3. Extreme weight value detection (3σ anomalies)
  4. Spectral signature analysis (SVD — top singular value ratio)

Architecture classification prevents false positives on LLMs.

"""

from __future__ import annotations

import logging
import zipfile
from pathlib import Path

from ..finding import Finding, Location, Severity

logger = logging.getLogger(__name__)

# Known vocab sizes for LLM detection
_KNOWN_VOCAB_SIZES = frozenset({
    30522, 50257, 50265, 50304, 32000, 32001, 32128, 65024, 65536,
    100352, 128000, 128256, 151643, 151936, 152064,
})


def _is_power_of_two(n: int) -> bool:
    return n > 0 and (n & (n - 1)) == 0


class TrojanDetector:
    """Statistical anomaly detector for neural network weight matrices."""

    def __init__(
        self,
        z_score_threshold: float = 4.0,
        cosine_threshold: float = 0.7,
        magnitude_sigmas: float = 3.0,
        max_layers_to_scan: int = 50,
    ):
        self.z_score_threshold = z_score_threshold
        self.cosine_threshold = cosine_threshold
        self.magnitude_sigmas = magnitude_sigmas
        self.max_layers = max_layers_to_scan

    def scan_file(self, file_path: str | Path) -> list[Finding]:
        """Scan a model file for weight anomalies."""
        path = Path(file_path)
        source = str(path)
        suffix = path.suffix.lower()

        try:
            import numpy as np
        except ImportError:
            logger.debug("numpy not available, skipping trojan detection")
            return []

        findings: list[Finding] = []

        try:
            weight_tensors = self._load_weights(path, suffix)
        except Exception as exc:
            logger.debug("Could not load weights from %s: %s", path, exc)
            return []

        if not weight_tensors:
            return []

        # Classify architecture to adjust thresholds
        is_llm = self._detect_llm(weight_tensors)
        z_thresh = self.z_score_threshold * (2.5 if is_llm else 1.0)
        outlier_pct_limit = 0.0001 if is_llm else 0.01

        scanned = 0
        for layer_name, weights in weight_tensors.items():
            if scanned >= self.max_layers:
                break
            if weights.ndim < 2:
                continue
            scanned += 1

            layer_findings = self._analyze_layer(
                np.array(weights, dtype=np.float32),
                layer_name, source, z_thresh,
                outlier_pct_limit, is_llm,
            )
            findings.extend(layer_findings)

        return findings

    def _analyze_layer(
        self, weights, layer_name: str, source: str,
        z_thresh: float, outlier_pct_limit: float,
        is_llm: bool = False,
    ) -> list[Finding]:
        import numpy as np

        findings: list[Finding] = []
        n_outputs = weights.shape[-1] if weights.ndim >= 2 else weights.shape[0]
        if n_outputs < 2:
            return []

        # 1. Z-score outlier detection
        try:
            output_norms = np.linalg.norm(weights, axis=0) if weights.ndim >= 2 else np.abs(weights)
            mean_norm = np.mean(output_norms)
            std_norm = np.std(output_norms)
            if std_norm > 1e-8:
                z_scores = np.abs((output_norms - mean_norm) / std_norm)
                outlier_idx = np.where(z_scores > z_thresh)[0]
                outlier_pct = len(outlier_idx) / n_outputs

                if len(outlier_idx) > 0 and outlier_pct < outlier_pct_limit:
                    max_z = float(z_scores[outlier_idx].max())
                    findings.append(Finding.artifact(
                        rule_id="TROJAN-001",
                        title=f"Suspicious weight outlier in {layer_name}",
                        description=(
                            f"Layer '{layer_name}' has {len(outlier_idx)} neuron(s) "
                            f"with abnormally large weight norms (z-score>{z_thresh:.1f}). "
                            f"This pattern is consistent with a planted neural trojan/backdoor."
                        ),
                        severity=Severity.HIGH,
                        confidence=min(0.95, 0.6 + (max_z - z_thresh) * 0.05),
                        target=source,
                        evidence=(
                            f"max_z_score={max_z:.2f}, outlier_count={len(outlier_idx)}, "
                            f"outlier_pct={outlier_pct:.6f}, layer={layer_name}"
                        ),
                        location=Location(file=source),
                        cwe_ids=["CWE-506"],
                        tags=["mitre-atlas:AML.T0043", "trojan", "backdoor"],
                    ))
        except Exception:
            pass

        # 2. Cosine similarity dissimilarity (only for manageable layers)
        if n_outputs <= 1000 and weights.ndim >= 2:
            try:
                norms = np.linalg.norm(weights, axis=0, keepdims=True)
                norms = np.where(norms < 1e-8, 1.0, norms)
                normalized = weights / norms
                sim_matrix = np.dot(normalized.T, normalized)

                dissimilar = []
                for i in range(n_outputs):
                    other = np.concatenate([sim_matrix[i, :i], sim_matrix[i, i + 1:]])
                    if len(other) > 0 and np.max(np.abs(other)) < self.cosine_threshold:
                        dissimilar.append(i)

                if 0 < len(dissimilar) <= max(5, int(n_outputs * 0.01)):
                    findings.append(Finding.artifact(
                        rule_id="TROJAN-002",
                        title=f"Isolated neuron(s) in {layer_name}",
                        description=(
                            f"Layer '{layer_name}' has {len(dissimilar)} neuron(s) "
                            f"with very low cosine similarity to all other neurons "
                            f"(max sim < {self.cosine_threshold}). These neurons behave "
                            f"fundamentally differently, consistent with trojan insertion."
                        ),
                        severity=Severity.HIGH,
                        confidence=0.7,
                        target=source,
                        evidence=(
                            f"dissimilar_neurons={dissimilar[:10]}, "
                            f"count={len(dissimilar)}, layer={layer_name}"
                        ),
                        location=Location(file=source),
                        cwe_ids=["CWE-506"],
                        tags=["mitre-atlas:AML.T0043", "trojan", "backdoor"],
                    ))
            except Exception:
                pass

        # 3. Extreme weight values
        try:
            flat = weights.flatten()
            magnitudes = np.abs(flat)
            mean_mag = np.mean(magnitudes)
            std_mag = np.std(magnitudes)
            if std_mag > 1e-8:
                threshold = mean_mag + self.magnitude_sigmas * std_mag
                extreme_idx = np.where(magnitudes > threshold)[0]
                extreme_pct = len(extreme_idx) / len(flat)

                if len(extreme_idx) > 0 and extreme_pct < 0.001:
                    max_val = float(magnitudes[extreme_idx].max())
                    findings.append(Finding.artifact(
                        rule_id="TROJAN-003",
                        title=f"Extreme weight values in {layer_name}",
                        description=(
                            f"Layer '{layer_name}' contains {len(extreme_idx)} weight(s) "
                            f"exceeding {self.magnitude_sigmas}σ (max={max_val:.4f}). "
                            f"Concentrated extreme values can indicate trojan triggers."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=0.5,
                        target=source,
                        evidence=(
                            f"max_value={max_val:.4f}, extreme_count={len(extreme_idx)}, "
                            f"threshold={threshold:.4f}, layer={layer_name}"
                        ),
                        location=Location(file=source),
                        cwe_ids=["CWE-506"],
                        tags=["mitre-atlas:AML.T0043", "trojan"],
                    ))
        except Exception:
            pass

        # 4. Spectral signature analysis (SVD top singular value ratio)
        # Reference: Tran et al. "Spectral Signatures in Backdoor Attacks" NeurIPS 2018
        # A trojan-poisoned layer often has a dramatically dominant top singular value
        # compared to the others (rank-1 perturbation from the trigger pattern).
        if weights.ndim == 2 and min(weights.shape) >= 4 and max(weights.shape) <= 4096:
            try:
                s = np.linalg.svd(weights, compute_uv=False)
                if len(s) >= 2 and s[1] > 1e-8:
                    top_ratio = float(s[0] / s[1])
                    # Normal weight matrices rarely exceed ratio ~10–20.
                    # Backdoor injections tend to produce ratios > 50.
                    ratio_threshold = 100.0 if is_llm else 50.0
                    if top_ratio > ratio_threshold:
                        findings.append(Finding.artifact(
                            rule_id="TROJAN-004",
                            title=f"Spectral anomaly (dominant singular value) in {layer_name}",
                            description=(
                                f"Layer '{layer_name}' has a top/second singular value ratio "
                                f"of {top_ratio:.1f} (threshold: {ratio_threshold:.0f}). "
                                "A dominant rank-1 perturbation is a statistical signature of "
                                "backdoor/trojan injection (Tran et al., NeurIPS 2018)."
                            ),
                            severity=Severity.HIGH,
                            confidence=min(0.9, 0.55 + (top_ratio - ratio_threshold) / ratio_threshold * 0.1),
                            target=source,
                            evidence=(
                                f"sv_ratio={top_ratio:.2f}, s0={s[0]:.4f}, s1={s[1]:.4f}, "
                                f"shape={weights.shape}, layer={layer_name}"
                            ),
                            location=Location(file=source),
                            cwe_ids=["CWE-506"],
                            tags=["mitre-atlas:AML.T0043", "trojan", "spectral-signature"],
                        ))
            except Exception:
                pass

        # 5. Bimodal weight distribution (indicator of hidden neuron clusters)
        # Backdoor neurons often form a separate cluster with distinct mean.
        if weights.ndim >= 2 and min(weights.shape) <= 2048:
            try:
                flat = weights.flatten().astype(np.float64)
                if len(flat) >= 100:
                    # Split into two halves by sign and compare cluster means
                    pos = flat[flat > 0]
                    neg = flat[flat < 0]
                    if len(pos) > 10 and len(neg) > 10:
                        pos_mean, neg_mean = float(np.mean(pos)), float(np.mean(neg))
                        pos_std,  neg_std  = float(np.std(pos)),  float(np.std(neg))
                        overall_std = float(np.std(flat))
                        if overall_std > 1e-8:
                            bimodal_score = abs(pos_mean - neg_mean) / overall_std
                            # High bimodal score with asymmetric cluster sizes suggests hidden cluster
                            size_ratio = max(len(pos), len(neg)) / (min(len(pos), len(neg)) + 1)
                            if bimodal_score > 8.0 and size_ratio > 10.0:
                                findings.append(Finding.artifact(
                                    rule_id="TROJAN-005",
                                    title=f"Bimodal weight distribution anomaly in {layer_name}",
                                    description=(
                                        f"Layer '{layer_name}' shows a strongly bimodal weight "
                                        f"distribution (score={bimodal_score:.1f}, cluster_ratio={size_ratio:.1f}). "
                                        "Asymmetric clusters may indicate hidden backdoor neurons."
                                    ),
                                    severity=Severity.MEDIUM,
                                    confidence=0.55,
                                    target=source,
                                    evidence=(
                                        f"bimodal_score={bimodal_score:.2f}, "
                                        f"size_ratio={size_ratio:.1f}, layer={layer_name}"
                                    ),
                                    location=Location(file=source),
                                    cwe_ids=["CWE-506"],
                                    tags=["mitre-atlas:AML.T0043", "trojan", "bimodal"],
                                ))
            except Exception:
                pass

        return findings

    def _detect_llm(self, tensors: dict) -> bool:
        """Heuristic detection of LLM architecture."""
        total_params = 0
        has_vocab_dim = False
        for _name, w in tensors.items():
            import numpy as np
            if hasattr(w, 'shape'):
                total_params += int(np.prod(w.shape))
                for d in w.shape:
                    if d in _KNOWN_VOCAB_SIZES:
                        has_vocab_dim = True
        return total_params > 100_000_000 or has_vocab_dim

    def _load_weights(self, path: Path, suffix: str) -> dict:
        """Load weight tensors from a model file. Returns {name: ndarray}."""
        import numpy as np

        if suffix in (".pt", ".pth", ".bin"):
            return self._load_pytorch(path)
        elif suffix in (".safetensors",):
            return self._load_safetensors(path)
        elif suffix in (".onnx",):
            return self._load_onnx(path)
        elif suffix in (".h5", ".hdf5", ".keras"):
            return self._load_h5(path)
        elif suffix in (".npy",):
            arr = np.load(str(path), allow_pickle=False)
            return {"array": arr}
        elif suffix in (".npz",):
            data = np.load(str(path), allow_pickle=False)
            return dict(data)
        return {}

    def _load_pytorch(self, path: Path) -> dict:
        """Load PyTorch state_dict with weights_only=True."""
        import numpy as np
        try:
            import torch
            state = torch.load(str(path), map_location="cpu", weights_only=True)
            if isinstance(state, dict):
                return {k: v.cpu().numpy() for k, v in state.items()
                        if hasattr(v, 'numpy') and v.ndim >= 2}
        except Exception:
            pass
        # Fallback: try reading as numpy arrays from zip
        try:
            if zipfile.is_zipfile(str(path)):
                result = {}
                with zipfile.ZipFile(str(path)) as zf:
                    for name in zf.namelist():
                        if name.endswith('.npy'):
                            with zf.open(name) as f:
                                arr = np.load(f, allow_pickle=False)
                                if arr.ndim >= 2:
                                    result[name] = arr
                return result
        except Exception:
            pass
        return {}

    def _load_safetensors(self, path: Path) -> dict:
        """Load safetensors file."""
        try:
            from safetensors.numpy import load_file
            tensors = load_file(str(path))
            return {k: v for k, v in tensors.items() if v.ndim >= 2}
        except ImportError:
            pass
        return {}

    def _load_onnx(self, path: Path) -> dict:
        """Load ONNX model initializers."""
        try:
            import onnx
            from onnx import numpy_helper
            model = onnx.load(str(path))
            result = {}
            for init in model.graph.initializer:
                arr = numpy_helper.to_array(init)
                if arr.ndim >= 2:
                    result[init.name] = arr
            return result
        except ImportError:
            pass
        return {}

    def _load_h5(self, path: Path) -> dict:
        """Load HDF5/Keras weights."""
        import numpy as np
        try:
            import h5py
            result = {}
            with h5py.File(str(path), 'r') as f:
                def _visit(name, obj):
                    if isinstance(obj, h5py.Dataset):
                        arr = np.array(obj)
                        if arr.ndim >= 2:
                            result[name] = arr
                f.visititems(_visit)
            return result
        except ImportError:
            pass
        return {}
