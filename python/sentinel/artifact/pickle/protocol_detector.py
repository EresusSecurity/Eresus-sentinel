"""Protocol-specific gadget detector for pickle streams.

Loads rules from rules/pickle_protocol_rules.yaml and evaluates them
against a PickleAnalysis object. Complements the opcode-level analyzer
with protocol-0 text-stream detection and proto-4/5-specific patterns.

Public API
----------
    detector = PickleProtocolDetector()
    findings = detector.scan(data, source, analysis)
"""

from __future__ import annotations

import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from ...finding import Finding, Severity

logger = logging.getLogger(__name__)

_RULES_PATH = Path(__file__).parent.parent.parent.parent / "rules" / "pickle_protocol_rules.yaml"
# Fallback: check sentinel/rules symlink
_RULES_PATH_ALT = Path(__file__).parent.parent.parent / "rules" / "pickle_protocol_rules.yaml"


@lru_cache(maxsize=1)
def _load_rules() -> list[dict[str, Any]]:
    for path in (_RULES_PATH, _RULES_PATH_ALT):
        if path.exists():
            with open(path) as f:
                data = yaml.safe_load(f)
            return data.get("protocol_gadgets", [])
    logger.warning("pickle_protocol_rules.yaml not found at %s", _RULES_PATH)
    return []


# ── Protocol-0 text-stream scanner ───────────────────────────

_PROTO0_DANGEROUS = [
    # (pattern_bytes, signal_name)
    (b"cos\nsystem\n",          "proto0_os_system"),
    (b"cposix\nsystem\n",       "proto0_posix_system"),
    (b"cnt\nsystem\n",          "proto0_nt_system"),
    (b"csubprocess\nPopen\n",   "proto0_subprocess_popen"),
    (b"cbuiltins\nexec\n",      "proto0_builtins_exec"),
    (b"cbuiltins\neval\n",      "proto0_builtins_eval"),
    (b"c__builtin__\nexec\n",   "proto0_builtin_exec"),
    (b"c__builtin__\napply\n",  "proto0_builtin_apply"),
    (b"ios\nsystem\n",          "proto0_inst_os_system"),
    (b"isubprocess\nPopen\n",   "proto0_inst_subprocess"),
    (b"ibuiltins\nexec\n",      "proto0_inst_builtins_exec"),
]

# Pattern for generic protocol-0 GLOBAL: c<printable_module>\n<printable_name>\n
_PROTO0_GLOBAL_RE = re.compile(
    rb"c([A-Za-z0-9_.]+)\n([A-Za-z0-9_.]+)\n"
)
_DANGEROUS_MODULES_PROTO0 = frozenset({
    b"os", b"posix", b"nt", b"subprocess", b"builtins", b"__builtin__",
    b"importlib", b"importlib._bootstrap", b"importlib._bootstrap_external",
    b"ctypes", b"cffi", b"ctypes.cdll", b"socket",
})


class PickleProtocolDetector:
    """Detect protocol-specific pickle gadgets."""

    def scan(
        self,
        data: bytes,
        source: str,
        protocol: int = -1,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Proto-0 text-based scan (no binary magic header to check)
        if protocol == 0 or protocol == -1:
            findings.extend(self._scan_proto0(data, source))

        # Generic: memo ratio, nested, proto-4/5 indicators
        findings.extend(self._scan_structural(data, source, protocol))

        return findings

    # ─── Protocol-0 ──────────────────────────────────────────

    def _scan_proto0(self, data: bytes, source: str) -> list[Finding]:
        findings: list[Finding] = []

        # Check known dangerous text-encoded globals
        for pattern, signal in _PROTO0_DANGEROUS:
            if pattern in data:
                findings.append(Finding.artifact(
                    rule_id="PICKLE-PROTO-001",
                    title=f"Protocol-0 dangerous global: {signal}",
                    description=(
                        f"Text-encoded protocol-0 GLOBAL/INST opcode importing "
                        f"a dangerous callable. Pattern: {pattern!r}. "
                        "Protocol-0 streams evade binary magic-byte scanners."
                    ),
                    severity=Severity.CRITICAL,
                    target=source,
                    confidence=0.95,
                    tags=["pickle", "proto0", "rce", signal],
                ))

        # Generic sweep: any GLOBAL to a dangerous module
        for m in _PROTO0_GLOBAL_RE.finditer(data):
            module = m.group(1)
            name = m.group(2)
            if module in _DANGEROUS_MODULES_PROTO0:
                findings.append(Finding.artifact(
                    rule_id="PICKLE-PROTO-001",
                    title=f"Protocol-0 GLOBAL: {module.decode()}.{name.decode()}",
                    description=(
                        f"Protocol-0 text-encoded GLOBAL importing "
                        f"{module.decode()}.{name.decode()} — may execute arbitrary code."
                    ),
                    severity=Severity.CRITICAL,
                    target=source,
                    confidence=0.90,
                    tags=["pickle", "proto0", "global"],
                ))

        return findings

    # ─── Structural / cross-protocol ─────────────────────────

    def _scan_structural(
        self, data: bytes, source: str, protocol: int
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Protocol-5 out-of-band buffer opcodes (0x97 NEXT_BUFFER, 0x98 READONLY_BUFFER)
        # Only flag for actual protocol-5 streams; 0x97 appears naturally
        # in binary payload data of lower-protocol pickles (e.g. numpy arrays).
        if protocol == 5 and data.count(b"\x97") > 50:
            count = data.count(b"\x97")
            findings.append(
                Finding.artifact(
                    rule_id="PICKLE-PROTO-010",
                    title="Protocol-5 excessive NEXT_BUFFER opcodes",
                    description=(
                        "Found {} NEXT_BUFFER (0x97) opcodes. ".format(count)
                        + "Protocol-5 out-of-band buffers can bypass in-band content scanners."
                    ),
                    severity=Severity.HIGH,
                    target=source,
                    confidence=0.75,
                    tags=["pickle", "proto5", "oob_buffer"],
                )
            )

        # Protocol-4 excessive FRAME opcodes (0x95)
        # Use ratio-aware threshold: raw 0x95 appears ~1/256 in binary
        # payload data, so only flag when count far exceeds random expectation.
        frame_count = data.count(b"\x95")
        expected_random = max(100, len(data) // 128)
        if protocol == 4 and frame_count > expected_random:
            findings.append(Finding.artifact(
                rule_id="PICKLE-PROTO-009",
                title=f"Protocol-4 excessive FRAME opcodes ({frame_count})",
                description=(
                    "Abnormally high FRAME opcode count may indicate parser confusion attack."
                ),
                severity=Severity.MEDIUM,
                target=source,
                confidence=0.65,
                tags=["pickle", "proto4", "frame_bomb"],
            ))

        # Protocol downgrade: outer proto 4/5 but inner text (proto-0) stream after STOP
        if protocol >= 4:
            last_stop = data.rfind(b"\x2e")
            if last_stop > 0:
                remaining = data[last_stop + 1:]
                # Look for proto-0 GLOBAL after STOP
                if _PROTO0_GLOBAL_RE.search(remaining):
                    findings.append(Finding.artifact(
                        rule_id="PICKLE-PROTO-014",
                        title="Protocol downgrade: proto-0 stream embedded in proto-4/5 outer",
                        description=(
                            "A protocol-0 text-encoded GLOBAL was found after the STOP opcode "
                            "of a protocol-4/5 stream. This evades scanners that only check "
                            "the outermost protocol header."
                        ),
                        severity=Severity.HIGH,
                        target=source,
                        confidence=0.85,
                        tags=["pickle", "proto_downgrade", "nested"],
                    ))

        return findings
