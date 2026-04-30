from __future__ import annotations

import hashlib
import io
import tarfile
import zipfile

from sentinel.finding import Severity


def test_artifact_scan_file_include_exclude_and_strict(tmp_path):
    from sentinel.artifact import ArtifactScanOptions, scan_file

    model_path = tmp_path / "evil.pkl"
    model_path.write_bytes(b"\x80\x02cos\nsystem\n(S'echo parity'\ntR.")
    unknown_path = tmp_path / "unknown.weights"
    unknown_path.write_bytes(b"opaque")

    excluded = scan_file(model_path, options=ArtifactScanOptions(exclude=("pickle",)))
    included = scan_file(model_path, options=ArtifactScanOptions(include=("pickle",)))
    unsupported = scan_file(unknown_path, strict=True)

    assert excluded == []
    assert any(f.severity == Severity.CRITICAL for f in included)
    assert any(f.rule_id == "ARTIFACT-091" for f in unsupported)


def test_artifact_scan_file_warns_on_unsafe_format_and_hash_mismatch(tmp_path):
    from sentinel.artifact import scan_file

    model_path = tmp_path / "weights.bin"
    model_path.write_bytes(b"not-a-real-model")

    findings = scan_file(model_path, include=("torch",), expected_sha256="0" * 64)

    assert any(f.rule_id == "ARTIFACT-090" for f in findings)
    assert any(f.rule_id == "ARTIFACT-092" for f in findings)


def test_artifact_scan_file_content_hash_cache_is_stable(tmp_path):
    from sentinel.artifact import ArtifactScanOptions, scan_file

    model_path = tmp_path / "hash.pkl"
    payload = b"\x80\x02cos\nsystem\n(S'echo cache'\ntR."
    model_path.write_bytes(payload)
    expected = hashlib.sha256(payload).hexdigest()
    options = ArtifactScanOptions(cache=True, expected_sha256=expected)

    first = scan_file(model_path, options=options)
    second = scan_file(model_path, options=options)

    assert [f.rule_id for f in first] == [f.rule_id for f in second]
    assert not any(f.rule_id == "ARTIFACT-092" for f in first)


def test_artifact_scan_directory_uses_public_options(tmp_path):
    from sentinel.artifact import ArtifactScanOptions, scan_directory

    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "evil.pkl").write_bytes(b"\x80\x02cos\nsystem\n(S'echo dir'\ntR.")
    (nested / "notes.txt").write_text("not a model", encoding="utf-8")

    findings = scan_directory(tmp_path, options=ArtifactScanOptions(include=("pickle",)))

    assert any(f.severity == Severity.CRITICAL for f in findings)
    assert all(f.target.endswith(".pkl") for f in findings)


def test_dispatch_artifact_handles_compound_tar_gz(tmp_path):
    from sentinel.cli_dispatch import dispatch_artifact

    archive_path = tmp_path / "nested.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tf:
        data = b"evil"
        info = tarfile.TarInfo(name="../../etc/passwd")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))

    findings = dispatch_artifact(str(archive_path))

    assert any(f.rule_id == "ARCHSLIP-004" for f in findings)


def test_dispatch_artifact_scans_torchscript_zip_payload(tmp_path):
    from sentinel.cli_dispatch import dispatch_artifact

    archive_path = tmp_path / "torchscript_payload.zip"
    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.writestr("code/__torch__/model.py", "x = eval('malicious_code')\n")

    findings = dispatch_artifact(str(archive_path))

    assert any(f.rule_id == "TS-010" for f in findings)


def test_archive_slip_recurses_into_nested_archives(tmp_path):
    from sentinel.cli_dispatch import dispatch_artifact

    inner_tar = io.BytesIO()
    with tarfile.open(fileobj=inner_tar, mode="w") as tf:
        data = b"traversal"
        info = tarfile.TarInfo(name="../../../etc/passwd_stub")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))

    mid_zip = io.BytesIO()
    with zipfile.ZipFile(mid_zip, "w") as zf:
        zf.writestr("innermost.tar", inner_tar.getvalue())

    outer_path = tmp_path / "outer.tar.gz"
    with tarfile.open(outer_path, "w:gz") as tf:
        data = mid_zip.getvalue()
        info = tarfile.TarInfo(name="mid.zip")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))

    findings = dispatch_artifact(str(outer_path))

    assert any(f.rule_id == "ARCHSLIP-004" for f in findings)
