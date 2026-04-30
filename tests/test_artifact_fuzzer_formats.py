"""Tests for extended artifact fuzzer format generation."""

from __future__ import annotations

import io
import tarfile
import zipfile

import pytest

from sentinel.artifact.catboost_scanner import CatBoostScanner
from sentinel.artifact.coreml_scanner import CoreMLScanner
from sentinel.artifact.keras_scanner import KerasScanner
from sentinel.artifact.lightgbm_scanner import LightGBMScanner
from sentinel.artifact.nemo_scanner import NeMoScanner
from sentinel.artifact.numpy_scanner import NumpyScanner
from sentinel.artifact.openvino_scanner import OpenVINOScanner
from sentinel.artifact.pmml_scanner import PMMLScanner
from sentinel.artifact.skops_scanner import SkopsScanner
from sentinel.artifact.tflite_scanner import TFLiteScanner
from sentinel.artifact.xgboost_scanner import XGBoostScanner
from sentinel.fuzzer.artifact.generator import ArtifactGenerator


def _findings(result):
    return result.findings if hasattr(result, "findings") else result


def test_supported_formats_include_scanner_backed_artifacts():
    formats = set(ArtifactGenerator.supported_formats())

    assert {
        "keras",
        "keras_h5",
        "tflite",
        "coreml",
        "skops",
        "nemo",
        "openvino_xml",
        "pmml",
        "npy",
        "xgboost",
        "lightgbm",
        "catboost",
    }.issubset(formats)


def test_generator_aliases_are_supported():
    assert ArtifactGenerator(format="h5").generate(seed=1).startswith(b"\x89HDF")
    assert ArtifactGenerator(format="litert").generate(seed=1)[4:8] == b"TFL3"
    assert ArtifactGenerator(format="xgb").generate(seed=1).startswith(b"binf")


def test_archive_formats_have_expected_container_shape():
    keras_data = ArtifactGenerator(format="keras").generate(seed=2)
    skops_data = ArtifactGenerator(format="skops").generate(seed=2)
    nemo_data = ArtifactGenerator(format="nemo").generate(seed=2)

    with zipfile.ZipFile(io.BytesIO(keras_data), "r") as zf:
        assert {"config.json", "metadata.json", "model.weights.h5"}.issubset(zf.namelist())

    with zipfile.ZipFile(io.BytesIO(skops_data), "r") as zf:
        assert {"schema.json", "payload.pkl"}.issubset(zf.namelist())

    with tarfile.open(fileobj=io.BytesIO(nemo_data), mode="r:*") as tf:
        names = {member.name for member in tf.getmembers()}
        assert {"model_config.yaml", "model_weights.ckpt"}.issubset(names)


@pytest.mark.parametrize(
    ("fmt", "suffix", "scanner"),
    [
        ("keras", ".keras", KerasScanner()),
        ("keras_h5", ".h5", KerasScanner()),
        ("tflite", ".tflite", TFLiteScanner()),
        ("coreml", ".mlpackage", CoreMLScanner()),
        ("mlmodel", ".mlmodel", CoreMLScanner()),
        ("skops", ".skops", SkopsScanner()),
        ("nemo", ".nemo", NeMoScanner()),
        ("openvino_xml", ".xml", OpenVINOScanner()),
        ("pmml", ".pmml", PMMLScanner()),
        ("npy", ".npy", NumpyScanner()),
        ("xgboost", ".xgb", XGBoostScanner()),
        ("lightgbm", ".lgb", LightGBMScanner()),
        ("catboost", ".cbm", CatBoostScanner()),
    ],
)
def test_generated_artifacts_exercise_existing_scanners(tmp_path, fmt, suffix, scanner):
    path = tmp_path / f"sample{suffix}"
    path.write_bytes(ArtifactGenerator(format=fmt).generate(seed=7))

    findings = _findings(scanner.scan_file(str(path)))

    assert findings, f"{fmt} sample did not exercise {scanner.__class__.__name__}"
