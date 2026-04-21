#!/usr/bin/env python3
"""
GGUF Header Overflow & SSTI Detection Demo
===========================================

Demonstrates Sentinel's GGUF-specific vulnerability detection:

1. Crafted GGUF header with n_kv overflow (heap overflow trigger)
2. Normal GGUF header as control
3. Jinja2 SSTI payload in chat_template metadata

This mirrors the real Huntr vulnerability where llama.cpp
allocates malloc(n_kv * sizeof(kv)) without overflow checking.
"""

import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))

from sentinel.artifact.gguf_analyzer import GGUFAnalyzer


# ─── GGUF file creation helpers ──────────────────────────────────

def write_gguf_string(buf: bytearray, s: str):
    """Write a GGUF string (uint64 length + data)."""
    encoded = s.encode("utf-8")
    buf.extend(struct.pack("<Q", len(encoded)))
    buf.extend(encoded)


def write_gguf_kv_string(buf: bytearray, key: str, value: str):
    """Write a GGUF key-value pair with string value (type 8)."""
    write_gguf_string(buf, key)
    buf.extend(struct.pack("<I", 8))  # GGUF_TYPE_STRING
    write_gguf_string(buf, value)


def write_gguf_kv_uint32(buf: bytearray, key: str, value: int):
    """Write a GGUF key-value pair with uint32 value (type 4)."""
    write_gguf_string(buf, key)
    buf.extend(struct.pack("<I", 4))  # GGUF_TYPE_UINT32
    buf.extend(struct.pack("<I", value))


def create_safe_gguf() -> bytes:
    """Create a valid GGUF file with normal metadata."""
    buf = bytearray()

    # Header: magic(4) + version(4) + n_tensors(8) + n_kv(8)
    buf.extend(b"GGUF")
    buf.extend(struct.pack("<I", 3))      # version 3
    buf.extend(struct.pack("<Q", 0))      # n_tensors = 0
    buf.extend(struct.pack("<Q", 3))      # n_kv = 3

    # Metadata
    write_gguf_kv_string(buf, "general.name", "safe-model-v1")
    write_gguf_kv_string(buf, "general.author", "sentinel-demo")
    write_gguf_kv_string(buf, "tokenizer.chat_template",
        "{% for message in messages %}"
        "{{ message['role'] }}: {{ message['content'] }}\n"
        "{% endfor %}")

    return bytes(buf)


def create_overflow_gguf() -> bytes:
    """
    Create a GGUF file with n_kv set to trigger integer overflow.

    Attack: n_kv = 0xFFFFFFFFFFFFFFFF
    When llama.cpp does: malloc(n_kv * sizeof(gguf_kv))
    The multiplication overflows to a small value, but the
    parsing loop writes n_kv entries → heap corruption.
    """
    buf = bytearray()

    buf.extend(b"GGUF")
    buf.extend(struct.pack("<I", 3))                    # version 3
    buf.extend(struct.pack("<Q", 0))                    # n_tensors
    buf.extend(struct.pack("<Q", 0xFFFFFFFFFFFFFFFF))   # n_kv = MAX

    # No actual metadata — the overflow is in the header
    return bytes(buf)


def create_ssti_gguf() -> bytes:
    """
    Create a GGUF file with Jinja2 SSTI in chat_template.

    Attack: The chat_template contains object traversal patterns
    that achieve RCE when processed by a vulnerable Jinja2 env:
      {{ self.__class__.__mro__[2].__subclasses__() }}
    """
    buf = bytearray()

    buf.extend(b"GGUF")
    buf.extend(struct.pack("<I", 3))
    buf.extend(struct.pack("<Q", 0))
    buf.extend(struct.pack("<Q", 2))  # n_kv = 2

    write_gguf_kv_string(buf, "general.name", "ssti-payload-model")
    write_gguf_kv_string(buf, "tokenizer.chat_template",
        "{% for message in messages %}"
        "{{ message['content'] }}"
        "{% endfor %}"
        "{{ self.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}")

    return bytes(buf)


# ─── Main ────────────────────────────────────────────────────────

def main():
    analyzer = GGUFAnalyzer()

    print("=" * 60)
    print("  Eresus Sentinel — GGUF Vulnerability Detection Demo")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        # Test 1: Safe GGUF
        print("\n[1/3] Scanning SAFE GGUF file...")
        safe_path = os.path.join(tmpdir, "safe_model.gguf")
        with open(safe_path, "wb") as f:
            f.write(create_safe_gguf())

        safe_findings = analyzer.scan_file(safe_path)
        critical_safe = [f for f in safe_findings if f.severity.value == "critical"]
        print(f"  → Total findings: {len(safe_findings)}")
        print(f"  → Critical: {len(critical_safe)}")
        if not critical_safe:
            print("  ✅ Clean — no critical issues")

        # Test 2: Overflow GGUF
        print("\n[2/3] Scanning OVERFLOW GGUF (n_kv = 0xFFFFFFFFFFFFFFFF)...")
        overflow_path = os.path.join(tmpdir, "overflow.gguf")
        with open(overflow_path, "wb") as f:
            f.write(create_overflow_gguf())

        overflow_findings = analyzer.scan_file(overflow_path)
        critical_overflow = [f for f in overflow_findings if f.severity.value == "critical"]
        print(f"  → Total findings: {len(overflow_findings)}")
        print(f"  → Critical: {len(critical_overflow)}")
        if critical_overflow:
            print("  🚨 CRITICAL: Heap overflow detected!")
            for finding in critical_overflow:
                print(f"     [{finding.rule_id}] {finding.title}")

        # Test 3: SSTI GGUF
        print("\n[3/3] Scanning SSTI GGUF (Jinja2 payload in chat_template)...")
        ssti_path = os.path.join(tmpdir, "ssti.gguf")
        with open(ssti_path, "wb") as f:
            f.write(create_ssti_gguf())

        ssti_findings = analyzer.scan_file(ssti_path)
        critical_ssti = [f for f in ssti_findings if f.severity.value == "critical"]
        print(f"  → Total findings: {len(ssti_findings)}")
        print(f"  → Critical: {len(critical_ssti)}")
        if critical_ssti:
            print("  🚨 CRITICAL: SSTI detected!")
            for finding in critical_ssti:
                print(f"     [{finding.rule_id}] {finding.title}")

    # Summary
    print("\n" + "=" * 60)
    print("  Summary")
    print("=" * 60)
    print(f"  Safe GGUF:     {len(critical_safe)} critical")
    print(f"  Overflow GGUF: {len(critical_overflow)} critical")
    print(f"  SSTI GGUF:     {len(critical_ssti)} critical")

    all_pass = (
        len(critical_safe) == 0
        and len(critical_overflow) > 0
        and len(critical_ssti) > 0
    )
    if all_pass:
        print("\n  ✅ All tests passed!")
    else:
        print("\n  ⚠️  Review output above")


if __name__ == "__main__":
    main()
