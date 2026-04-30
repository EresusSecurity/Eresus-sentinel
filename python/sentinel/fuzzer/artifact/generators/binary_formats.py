"""Binary model format generators: GGUF, SafeTensors, NPY, NPZ, ONNX, TFLite."""

from __future__ import annotations

import io
import json
import random
import struct
import zipfile

from .base import pickle_rce_payload


def gen_gguf(rng: random.Random) -> bytes:
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


def gen_safetensors(rng: random.Random) -> bytes:
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


def gen_onnx_stub(rng: random.Random) -> bytes:
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


def gen_tflite_stub(rng: random.Random) -> bytes:
    """Generate malformed TFLite FlatBuffer bytes."""
    if rng.random() < 0.5:
        root_offset = rng.choice([0x7FFFFFF0, 0xFFFFFFFF])
    else:
        root_offset = rng.choice([8, 12, 16])
    payload = rng.choice([
        b"CustomOp\x00/bin/sh\x00",
        b"FlexDelegate\x00__import__('os').system('id')",
        b"metadata\x00http://169.254.169.254/latest/meta-data/",
    ])
    return struct.pack("<I", root_offset) + b"TFL3" + payload + b"\x00" * 32


def gen_numpy_npy(rng: random.Random) -> bytes:
    """Generate NumPy .npy bytes with object dtype and oversized shape."""
    shape = rng.choice([
        "(1,)",
        "(999999999999, 999999999999)",
        "(2147483647, 2147483647)",
    ])
    header = (
        "{'descr': '|O', 'fortran_order': False, "
        f"'shape': {shape}, "
        "'note': \"__import__('os').system('id')\", }"
    ).encode("latin1")
    padding = (16 - ((10 + len(header) + 1) % 16)) % 16
    header = header + b" " * padding + b"\n"
    return (
        b"\x93NUMPY\x01\x00"
        + struct.pack("<H", len(header))
        + header
        + pickle_rce_payload()
    )


def gen_numpy_npz(rng: random.Random) -> bytes:
    """Generate NumPy .npz ZIP containing adversarial arrays and pickle."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("weights.npy", gen_numpy_npy(rng))
        zf.writestr("payload.pkl", pickle_rce_payload())
        if rng.random() < 0.5:
            zf.writestr("../npz_escape", b"escape")
    return buf.getvalue()


def gen_onnx_external_data(rng: random.Random) -> bytes:
    """Generate ONNX protobuf-like bytes with external_data path abuse."""
    location = rng.choice([
        b"../../../../etc/passwd",
        b"file:///etc/shadow",
        b"http://169.254.169.254/latest/meta-data/",
    ])
    buf = io.BytesIO()
    buf.write(gen_onnx_stub(rng))
    buf.write(b"external_data")
    buf.write(b"\x12")
    buf.write(struct.pack("B", min(len(location), 127)))
    buf.write(location[:127])
    buf.write(b"data_location=EXTERNAL")
    return buf.getvalue()
