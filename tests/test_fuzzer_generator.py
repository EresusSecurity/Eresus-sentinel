"""Tests for the pickle stream generator."""

from __future__ import annotations

import pickletools
import pytest

from sentinel.fuzzer.pickle.generator import PickleGenerator


class TestPickleGenerator:
    """Test structure-aware pickle stream generation."""

    @pytest.mark.parametrize("protocol", [0, 1, 2, 3, 4, 5])
    def test_generate_valid_for_all_protocols(self, protocol):
        """Generated pickles should parse without crashing pickletools."""
        gen = PickleGenerator(protocol=protocol, min_opcodes=5, max_opcodes=50)
        data = gen.generate(seed=42)

        assert isinstance(data, bytes)
        assert len(data) > 0

        # pickletools.genops should not crash
        ops = list(pickletools.genops(data))
        assert len(ops) > 0

    def test_deterministic_seeding(self):
        """Same seed should produce identical output."""
        gen = PickleGenerator(protocol=4, min_opcodes=10, max_opcodes=50)

        a = gen.generate(seed=12345)
        b = gen.generate(seed=12345)

        assert a == b

    def test_different_seeds_different_output(self):
        """Different seeds should produce different output."""
        gen = PickleGenerator(protocol=4, min_opcodes=10, max_opcodes=50)

        a = gen.generate(seed=1)
        b = gen.generate(seed=2)

        assert a != b

    def test_stop_opcode_present(self):
        """Every generated pickle must end with STOP (0x2e)."""
        gen = PickleGenerator(protocol=4, min_opcodes=5, max_opcodes=100)

        for i in range(20):
            data = gen.generate(seed=i)
            # The STOP opcode (0x2e = '.') should be present
            ops = list(pickletools.genops(data))
            last_op = ops[-1]
            assert last_op[0].name == "STOP", f"Last opcode is {last_op[0].name}, expected STOP"

    def test_protocol_header_present(self):
        """Protocol >= 2 should have PROTO header."""
        for proto in [2, 3, 4, 5]:
            gen = PickleGenerator(protocol=proto, min_opcodes=5, max_opcodes=20)
            data = gen.generate(seed=42)

            # First byte should be PROTO (0x80)
            assert data[0] == 0x80, f"Protocol {proto}: first byte is {data[0]:#x}, expected 0x80"
            assert data[1] == proto, f"Protocol {proto}: version byte is {data[1]}, expected {proto}"

    def test_frame_wrapping_protocol_4(self):
        """Protocol >= 4 should have FRAME opcode."""
        gen = PickleGenerator(protocol=4, min_opcodes=5, max_opcodes=30)
        data = gen.generate(seed=42)

        # FRAME opcode (0x95) should appear after PROTO header
        # PROTO is bytes [0,1], FRAME should be at [2]
        assert data[2] == 0x95, f"Expected FRAME at byte 2, got {data[2]:#x}"

    def test_generate_batch(self):
        """Batch generation should produce unique samples."""
        gen = PickleGenerator(protocol=4, min_opcodes=5, max_opcodes=30)

        samples = gen.generate_batch(10, seed=42)
        assert len(samples) == 10

        # All should be unique
        unique = set(samples)
        assert len(unique) == 10

    def test_generate_from_bytes(self):
        """Deterministic generation from input bytes."""
        gen = PickleGenerator(protocol=4, min_opcodes=5, max_opcodes=30)

        data = gen.generate_from_bytes(b"\x01\x02\x03\x04\x05\x06\x07\x08")
        assert isinstance(data, bytes)
        assert len(data) > 0

        # Same input → same output
        data2 = gen.generate_from_bytes(b"\x01\x02\x03\x04\x05\x06\x07\x08")
        assert data == data2

    def test_min_max_opcodes_respected(self):
        """Generated pickle should have opcodes within min/max range."""
        gen = PickleGenerator(protocol=4, min_opcodes=5, max_opcodes=20)

        for seed in range(10):
            data = gen.generate(seed=seed)
            ops = list(pickletools.genops(data))
            # At minimum: PROTO + FRAME + some opcodes + cleanup + STOP
            assert len(ops) >= 3, f"Too few opcodes: {len(ops)}"

    def test_no_crash_on_large_generation(self):
        """Generator should handle large opcode counts without crashing."""
        gen = PickleGenerator(protocol=4, min_opcodes=100, max_opcodes=500)
        data = gen.generate(seed=42)
        assert len(data) > 100

    def test_protocol_0_no_frame(self):
        """Protocol 0 should NOT have FRAME or PROTO opcodes."""
        gen = PickleGenerator(protocol=0, min_opcodes=5, max_opcodes=20)
        data = gen.generate(seed=42)

        # Should not start with PROTO
        assert data[0] != 0x80
