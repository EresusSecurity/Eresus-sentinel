"""
Eresus Sentinel — GPU Abuse Detector.

Detects malicious use of GPU resources in Python model files:
  - Cryptocurrency mining via CUDA (illicit compute theft)
  - Custom CUDA kernels with suspicious syscall patterns
  - VRAM exfiltration (reading other processes' GPU memory)
  - Triton/CUDA kernel injection
  - GPU-accelerated cryptography for C2 key generation

This is a NEW attack surface unique to AI environments:
ML inference environments have high-end GPUs that are valuable targets
for crypto mining, and CUDA enables memory access that can exfiltrate
data from co-located GPU workloads.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..finding import Finding, Severity

# ── Mining Patterns ───────────────────────────────────────────────────────────

_MINING_PATTERNS: list[tuple[str, str, str]] = [
    # Crypto mining keywords in CUDA/Python GPU code
    (r"(?i)stratum\+tcp://", "CRITICAL", "Stratum mining pool connection"),
    (r"(?i)stratum\+ssl://", "CRITICAL", "Stratum mining pool (SSL)"),
    (r"(?i)xmrig|xmr-stak|nbminer|t-rex|gminer|kawpow|ethash", "CRITICAL", "Known crypto miner software"),
    (r"(?i)monero|bitcoin|ethereum|zcash|ravencoin\s+(?:wallet|address|mine)", "HIGH", "Cryptocurrency reference in compute code"),
    (r"(?i)hash(?:rate|power)|nonce\s*\+\+|difficulty\s*=\s*0x", "HIGH", "Mining algorithm pattern"),
    (r"(?i)cuda.*(?:sha256|keccak|scrypt|argon2|randomx)", "HIGH", "CUDA crypto hash (mining algorithm)"),
    (r"(?i)(?:gpu|cuda).*(?:wallet|coin|mine|hash)", "HIGH", "GPU mining reference"),
    # CUDA abuse patterns
    (r"(?:torch|cupy)\.cuda\.(?:mem_get_info|memory_reserved|memory_allocated)", "MEDIUM", "GPU memory profiling"),
    (r"(?i)cudaMalloc.*\(.*,\s*\d{9,}", "HIGH", "Large CUDA memory allocation (>1GB)"),
    (r"(?i)cuMemcpyDtoH|cudaMemcpy.*cudaMemcpyDeviceToHost", "HIGH", "GPU-to-CPU memory copy (potential VRAM exfil)"),
    (r"(?i)pycuda\.driver\.mem_alloc", "HIGH", "PyCUDA raw memory allocation"),
    # Triton kernel abuse
    (r"@triton\.jit", "LOW", "Triton JIT kernel (verify behavior)"),
    (r"(?i)triton.*(?:os\.system|subprocess|socket|requests)", "CRITICAL", "Triton kernel with system calls"),
    (r"(?i)tl\.load.*(?:uint64|int64).*(?:0x[0-9a-f]{8,})", "HIGH", "Triton raw pointer dereference"),
    # cupy / numba GPU abuse
    (r"(?i)cupy\.RawKernel|cupy\.RawModule", "MEDIUM", "CuPy raw CUDA kernel"),
    (r"(?i)numba\.cuda\.(?:to_device|from_device).*(?:os|subprocess|socket)", "CRITICAL", "Numba CUDA with system access"),
    # Torch custom ops
    (r"torch\.ops\.load_library\s*\(", "CRITICAL", "torch.ops.load_library — native code execution"),
    (r"torch\.utils\.cpp_extension\.load\s*\(", "HIGH", "torch C++ extension loading"),
    (r"(?i)torch\.cuda\.(?:nvtx|profiler)", "LOW", "CUDA profiling (may be legitimate)"),
    # VRAM exfil patterns
    (r"(?i)cuda(?:Array|DevicePtr|MemcpyAsync).*(?:socket|requests|urllib)", "CRITICAL", "CUDA memory → network (VRAM exfil)"),
    (r"(?i)gpu.*(?:secret|key|token|password|credential)", "HIGH", "GPU processing credentials"),
]


class GPUAbuseDetector:
    """
    Detects GPU abuse patterns in Python source files.

    Targets:
    - Model loading files (.py) referenced by auto_map
    - Training scripts included in repos
    - Custom CUDA extension files
    """

    def scan_file(self, path: str | Path) -> list[Finding]:
        path = Path(path)
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []
        return self._scan_text(source, str(path))

    def scan_text(self, text: str, source: str) -> list[Finding]:
        return self._scan_text(text, source)

    def _scan_text(self, source: str, filepath: str) -> list[Finding]:
        findings = []

        for pattern, sev_str, desc in _MINING_PATTERNS:
            m = re.search(pattern, source)
            if m:
                severity = getattr(Severity, sev_str, Severity.MEDIUM)
                snippet = source[max(0, m.start() - 20):m.end() + 60].replace("\n", " ")
                findings.append(Finding.artifact(
                    rule_id="GPU-001",
                    title=f"GPU abuse pattern: {desc}",
                    description=(
                        f"Detected GPU/CUDA abuse pattern in Python file: {desc}. "
                        "This may indicate cryptocurrency mining, VRAM exfiltration, "
                        "or malicious use of the model host's GPU resources."
                    ),
                    severity=severity,
                    confidence=0.82,
                    target=filepath,
                    evidence=f"match={snippet!r:.120}",
                    remediation=(
                        "Investigate GPU usage pattern. Legitimate ML models should not "
                        "access mining pools, perform raw CUDA memory copies to network, "
                        "or load unverified native CUDA kernels."
                    ),
                ))

        return findings
