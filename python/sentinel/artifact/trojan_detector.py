"""Weight distribution anomaly / trojan detection for model files.

Detects potential neural trojans via three statistical analyses:
  1. Z-score outlier detection on per-neuron weight norms
  2. Cosine similarity dissimilarity (isolated neurons)
  3. Extreme weight value detection (3σ anomalies)

Architecture classification prevents false positives on LLMs.

Inspired by: ModelAudit (promptfoo) weight analysis approach.
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
                outlier_pct_limit,
            )
            findings.extend(layer_findings)

        return findings

    def _analyze_layer(
        self, weights, layer_name: str, source: str,
        z_thresh: float, outlier_pct_limit: float,
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
