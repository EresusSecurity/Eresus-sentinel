"""Materialize binary adversarial samples from textual specs.

Safe to run: every payload is structurally representative but
non-functional. Pickle REDUCE chains resolve to `builtins.print` or
non-existent attributes. No sample executes anything meaningful if
someone accidentally deserializes it.

Usage:
    python tests/adversarial_corpus/_generate.py

This writes:
  benign/pickle_benign_numpy_stub.pkl
  malicious/pickle_copyreg_memo_indirection.pkl
  malicious/pickle_build_setstate_gadget.pkl
  malicious/pickle_protocol0_legacy.pkl
  malicious/zipbomb_lied_size.zip
  malicious/nested_archive.tar.gz
  malicious/polyglot_pickle_head.bin
  malicious/torchscript_code_payload.zip
  malicious/gguf_malicious_kv.gguf

Idempotent: re-running overwrites.
"""

from __future__ import annotations

import io
import os
import pickle
import pickletools
import struct
import tarfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
BENIGN = HERE / "benign"
MALICIOUS = HERE / "malicious"
BENIGN.mkdir(exist_ok=True)
MALICIOUS.mkdir(exist_ok=True)


# ─────────────────────────────────────────────────────────────────────
# 1. Benign numpy-style pickle (plain dict, no REDUCE)
# ─────────────────────────────────────────────────────────────────────

def gen_benign_pickle() -> None:
    payload = {
        "model_name": "stub",
        "version": 1,
        "tensors": {"w": [0.0, 1.0, 2.0]},
    }
    out = BENIGN / "pickle_benign_numpy_stub.pkl"
    with open(out, "wb") as f:
        pickle.dump(payload, f, protocol=4)


# ─────────────────────────────────────────────────────────────────────
# 2. copyreg + memo indirection — hides add_extension args from the
#    scanner's last-3-strings lookahead.
#
# Layout (protocol 2):
#   PROTO 2
#   SHORT_BINUNICODE "builtins"   PUT 1
#   SHORT_BINUNICODE "print"      PUT 2
#   BININT1 240                   PUT 3
#   POP  POP  POP                 (drop so recent_strings gets flushed)
#   <240 filler SHORT_BINUNICODE "x" POP pairs to push recent_strings past>
#   GET 1  GET 2  GET 3
#   c copyreg\nadd_extension\n    (STACK_GLOBAL equivalent)
#   TUPLE3  REDUCE
#   EMPTY_TUPLE  REDUCE           (unused return)
#   STOP
#
# Ship as a hand-assembled pickle using pickletools opcodes directly.
# ─────────────────────────────────────────────────────────────────────

def gen_copyreg_memo_indirection() -> None:
    # Use pickle protocol 2 opcodes directly.
    buf = io.BytesIO()
    buf.write(b"\x80\x02")  # PROTO 2
    # Push and memoize three args
    buf.write(b"U\x08builtins")  # SHORT_BINSTRING
    buf.write(b"q\x01")           # BINPUT 1
    buf.write(b"U\x05print")
    buf.write(b"q\x02")           # BINPUT 2
    buf.write(b"K\xf0")           # BININT1 240
    buf.write(b"q\x03")           # BINPUT 3
    # Drop them from the stack so recent_strings flushes
    buf.write(b"0" * 3)           # POP POP POP
    # Flood recent_strings with filler short strings + pops
    for _ in range(8):
        buf.write(b"U\x01x0")     # SHORT_BINSTRING 'x' + POP
    # Rehydrate args via GET
    buf.write(b"h\x01")           # BINGET 1
    buf.write(b"h\x02")           # BINGET 2
    buf.write(b"h\x03")           # BINGET 3
    # Build a 3-tuple
    buf.write(b"\x87")            # TUPLE3
    # Import copyreg.add_extension via GLOBAL
    buf.write(b"ccopy_reg\nadd_extension\n")  # py2 name; also GLOBAL op
    # Swap tuple + callable for REDUCE
    buf.write(b"\x85")            # TUPLE1 (wrap tuple again? keep simple)
    # Simpler path: use REDUCE directly via different layout
    buf.write(b"R")               # REDUCE
    buf.write(b"N")               # NONE
    buf.write(b".")               # STOP
    (MALICIOUS / "pickle_copyreg_memo_indirection.pkl").write_bytes(buf.getvalue())


# ─────────────────────────────────────────────────────────────────────
# 3. BUILD / __setstate__ gadget. Uses `collections.OrderedDict` (not on
#    the pickle scanner's dangerous-module blocklist) with a BUILD op
#    triggering state application. REDUCE target is `builtins.print`.
# ─────────────────────────────────────────────────────────────────────

def gen_build_setstate_gadget() -> None:
    # Hand-assembled protocol 2 pickle.
    buf = io.BytesIO()
    buf.write(b"\x80\x02")
    # GLOBAL collections OrderedDict
    buf.write(b"ccollections\nOrderedDict\n")
    buf.write(b")")               # EMPTY_TUPLE
    buf.write(b"\x81")            # NEWOBJ (OrderedDict())
    # State dict with one item
    buf.write(b"}")               # EMPTY_DICT
    buf.write(b"U\x04key1")
    buf.write(b"U\x06value1")
    buf.write(b"s")               # SETITEM
    # BUILD — triggers __setstate__
    buf.write(b"b")               # BUILD
    buf.write(b".")
    (MALICIOUS / "pickle_build_setstate_gadget.pkl").write_bytes(buf.getvalue())


# ─────────────────────────────────────────────────────────────────────
# 4. Protocol-0 legacy pickle. No PROTO opcode → structural checks
#    that look for duplicate/misplaced PROTO never fire. GLOBAL chain
#    points to `builtins.print` (benign) but the *structural* detection
#    gap is what this sample measures.
# ─────────────────────────────────────────────────────────────────────

def gen_protocol0_legacy() -> None:
    # Protocol 0 text-format pickle
    data = (
        b"cbuiltins\nprint\n"     # GLOBAL builtins.print
        b"(S'hello from proto 0'\n"  # MARK + STRING
        b"tR"                     # TUPLE + REDUCE
        b".\n"
    )
    (MALICIOUS / "pickle_protocol0_legacy.pkl").write_bytes(data)


# ─────────────────────────────────────────────────────────────────────
# 5. Zipbomb with lied central-directory sizes.
#
# Build a zip containing one entry. We set the ZipInfo.file_size and
# compress_size to tiny values (1024) by manipulating the central
# directory after-the-fact, while the actual stored bytes are larger
# (but still safe/bounded for test — 256 KB of 'A'). A real bomb would
# use deflate to compress e.g. 1 GB of zeroes to 1 MB; we ship a safe
# structural analog that still falsifies the ratio check (trusted CD
# says 1 KB uncompressed, actual DEFLATE stream decompresses to 256 KB).
# ─────────────────────────────────────────────────────────────────────

def gen_zipbomb_lied_size() -> None:
    out = MALICIOUS / "zipbomb_lied_size.zip"
    payload = b"A" * (256 * 1024)  # 256 KB actual
    # Build legit zip first
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zi = zipfile.ZipInfo("model.bin")
        zi.compress_type = zipfile.ZIP_DEFLATED
        zf.writestr(zi, payload)
    raw = bytearray(buf.getvalue())

    # Patch central directory: find CD signature and rewrite file_size fields
    # to lie (advertise 1024 uncompressed while actual is 256 KB).
    cd_sig = b"PK\x01\x02"
    idx = raw.find(cd_sig)
    if idx >= 0:
        # compressed_size @ offset +20, uncompressed_size @ +24 (little-endian u32)
        struct.pack_into("<I", raw, idx + 20, 1024)
        struct.pack_into("<I", raw, idx + 24, 1024)
    out.write_bytes(bytes(raw))


# ─────────────────────────────────────────────────────────────────────
# 6. Nested archive: outer.tar.gz → inner.zip → innermost.tar with a
#    path-traversal entry. Sentinel's archive_slip scans only the
#    outermost layer.
# ─────────────────────────────────────────────────────────────────────

def gen_nested_archive() -> None:
    # innermost tar with ../../../etc/passwd
    inner_tar = io.BytesIO()
    with tarfile.open(fileobj=inner_tar, mode="w") as tf:
        info = tarfile.TarInfo(name="../../../etc/passwd_stub")
        data = b"traversal-target\n"
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    inner_tar_bytes = inner_tar.getvalue()

    # mid zip containing the tar
    mid_zip = io.BytesIO()
    with zipfile.ZipFile(mid_zip, "w") as zf:
        zf.writestr("innermost.tar", inner_tar_bytes)
    mid_zip_bytes = mid_zip.getvalue()

    # outer tar.gz containing the zip
    out = MALICIOUS / "nested_archive.tar.gz"
    with tarfile.open(out, "w:gz") as tf:
        info = tarfile.TarInfo(name="mid.zip")
        info.size = len(mid_zip_bytes)
        tf.addfile(info, io.BytesIO(mid_zip_bytes))


# ─────────────────────────────────────────────────────────────────────
# 7. Polyglot sample: pickle magic at head, ZIP sentinel later.
#
# Sentinel's _detect_format checks ZIP first only if header[:4] == PK,
# but pickle is checked at protocol-2 marker 0x80 0x02. A file that
# begins with pickle bytes and contains PK magic at a deeper offset
# exercises the polyglot detector; the dispatcher still routes to one
# scanner, missing the other.
# ─────────────────────────────────────────────────────────────────────

def gen_polyglot_pickle_head() -> None:
    pickle_head = b"\x80\x02]q\x00."  # minimal empty-list pickle
    # Append padding + a fake PK sentinel + more padding
    fake_zip = b"PK\x03\x04" + b"\x00" * 32
    out = MALICIOUS / "polyglot_pickle_head.bin"
    out.write_bytes(pickle_head + b"X" * 128 + fake_zip + b"Y" * 128)


# ─────────────────────────────────────────────────────────────────────
# 8. TorchScript `code/` payload.
# ─────────────────────────────────────────────────────────────────────

def gen_torchscript_code_payload() -> None:
    out = MALICIOUS / "torchscript_code_payload.zip"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("archive/data.pkl", b"\x80\x02}q\x00.")
        zf.writestr("code/__torch__/model.py", (
            "import torch\n"
            "# payload reference (non-functional):\n"
            "# eval(compile(..., 'exec'))\n"
            "def forward(self, x):\n"
            "    return x\n"
        ))


# ─────────────────────────────────────────────────────────────────────
# 9. GGUF with malicious kv (structural scaffold — not a valid GGUF for
#    inference; sufficient for scanner dispatch).
#
# GGUF v3 header:
#   magic "GGUF" (4)
#   version u32
#   tensor_count u64
#   metadata_kv_count u64
#   then kv pairs: key (length-prefixed str) + type + value
#
# We embed a `chat_template` string kv containing Jinja2 SSTI.
# ─────────────────────────────────────────────────────────────────────

def gen_gguf_malicious_kv() -> None:
    GGUF_MAGIC = b"GGUF"
    VERSION = 3
    # Value type codes from GGUF spec: STRING = 8
    STRING_TYPE = 8

    key = b"chat_template"
    value = b"{{ __import__('os').popen('id').read() }}"  # Jinja2 SSTI

    buf = io.BytesIO()
    buf.write(GGUF_MAGIC)
    buf.write(struct.pack("<I", VERSION))
    buf.write(struct.pack("<Q", 0))     # tensor_count
    buf.write(struct.pack("<Q", 1))     # metadata_kv_count
    # kv entry
    buf.write(struct.pack("<Q", len(key)))
    buf.write(key)
    buf.write(struct.pack("<I", STRING_TYPE))
    buf.write(struct.pack("<Q", len(value)))
    buf.write(value)

    (MALICIOUS / "gguf_malicious_kv.gguf").write_bytes(buf.getvalue())


# ─────────────────────────────────────────────────────────────────────

def main() -> None:
    gen_benign_pickle()
    gen_copyreg_memo_indirection()
    gen_build_setstate_gadget()
    gen_protocol0_legacy()
    gen_zipbomb_lied_size()
    gen_nested_archive()
    gen_polyglot_pickle_head()
    gen_torchscript_code_payload()
    gen_gguf_malicious_kv()
    print("Generated binary adversarial samples in", MALICIOUS, "and", BENIGN)


if __name__ == "__main__":
    main()
