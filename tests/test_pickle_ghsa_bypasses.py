"""Comprehensive GHSA bypass test suite for PickleScanner.

Tests every known pickle bypass technique from fickling + picklescan
security advisories. Each test creates a real pickle payload using
raw opcode construction and verifies our scanner detects it.
"""

from __future__ import annotations

import io
import pickle
import pickletools
import struct
import unittest

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))

from sentinel.artifact.pickle_scanner import PickleScanner
from sentinel.finding import Severity


def _build_pickle(*opcodes: bytes) -> bytes:
    """Build a pickle from raw opcode bytes."""
    return b"".join(opcodes)


# ── Opcode helpers ─────────────────────────────────────────────
# Protocol 4 PROTO
PROTO4 = b"\x80\x04"
PROTO5 = b"\x80\x05"
# STOP
STOP = b"."
# REDUCE
REDUCE = b"R"
# GLOBAL (protocol 0): "cmodule\nname\n"
def GLOBAL(module: str, name: str) -> bytes:
    return f"c{module}\n{name}\n".encode()
# STACK_GLOBAL
STACK_GLOBAL = b"\x93"
# SHORT_BINUNICODE
def SBU(s: str) -> bytes:
    encoded = s.encode("utf-8")
    return b"\x8c" + struct.pack("<B", len(encoded)) + encoded
# MEMOIZE
MEMOIZE = b"\x94"
# TUPLE1/TUPLE2/TUPLE3
TUPLE1 = b"\x85"
TUPLE2 = b"\x86"
TUPLE3 = b"\x87"
# EMPTY_TUPLE / EMPTY_LIST / EMPTY_DICT
EMPTY_TUPLE = b")"
EMPTY_LIST = b"]"
EMPTY_DICT = b"}"
# MARK
MARK = b"("
# TUPLE (with MARK)
TUPLE = b"t"
# POP
POP = b"0"
# PUT / GET (protocol 0)
def PUT(n: int) -> bytes: return f"p{n}\n".encode()
def GET(n: int) -> bytes: return f"g{n}\n".encode()
# BINPUT / BINGET
def BINPUT(n: int) -> bytes: return b"q" + struct.pack("<B", n)
def BINGET(n: int) -> bytes: return b"h" + struct.pack("<B", n)
# STRING (protocol 0)
def STRING(s: str) -> bytes: return f"S'{s}'\n".encode()
# NONE
NONE = b"N"
# NEWTRUE
NEWTRUE = b"\x88"
# OBJ (protocol 0)
OBJ = b"o"
# BUILD
BUILD = b"b"
# LIST (with MARK)
LIST = b"l"
# APPENDS
APPENDS = b"e"
# SHORT_BINBYTES
def SBB(data: bytes) -> bytes:
    return b"C" + struct.pack("<B", len(data)) + data
# BININT1
def BININT1(n: int) -> bytes: return b"K" + struct.pack("<B", n)
# BININT2
def BININT2(n: int) -> bytes: return b"M" + struct.pack("<H", n)
# FRAME (protocol 4)
def FRAME(n: int) -> bytes: return b"\x95" + struct.pack("<Q", n)
# INST (protocol 0)
def INST(module: str, name: str) -> bytes:
    return f"(i{module}\n{name}\n".encode()


class TestGHSABypasses(unittest.TestCase):
    """Test that our scanner catches every known GHSA bypass."""

    def setUp(self):
        self.scanner = PickleScanner()

    def _assert_flagged(self, data: bytes, msg: str = ""):
        """Assert that the scanner finds at least one dangerous finding."""
        findings = self.scanner.scan_bytes(data, source=f"<test:{msg}>")
        dangerous = [
            f for f in findings
            if f.severity in (Severity.HIGH, Severity.CRITICAL)
        ]
        self.assertTrue(
            len(dangerous) > 0,
            f"Expected dangerous findings for {msg}, got: "
            f"{[f.title for f in findings]}",
        )
        return findings

    def _assert_not_flagged(self, data: bytes, msg: str = ""):
        """Assert no HIGH/CRITICAL findings."""
        findings = self.scanner.scan_bytes(data, source=f"<test:{msg}>")
        dangerous = [
            f for f in findings
            if f.severity in (Severity.HIGH, Severity.CRITICAL)
        ]
        self.assertEqual(
            len(dangerous), 0,
            f"Expected NO dangerous findings for {msg}, got: "
            f"{[f.title for f in dangerous]}",
        )

    # ─── GHSA-r7v6: pty.spawn ──────────────────────────────────────
    def test_pty_spawn(self):
        payload = _build_pickle(
            PROTO4, FRAME(26),
            SBU("pty"), MEMOIZE,
            SBU("spawn"), MEMOIZE,
            STACK_GLOBAL, MEMOIZE,
            SBU("id"), MEMOIZE,
            TUPLE1, MEMOIZE,
            REDUCE, MEMOIZE,
            STOP,
        )
        self._assert_flagged(payload, "pty.spawn")

    # ─── GHSA-565g: marshal.loads + types.FunctionType ──────────────
    def test_marshal_types_codetype(self):
        payload = _build_pickle(
            PROTO4, FRAME(0),
            SBU("marshal"), SBU("loads"), STACK_GLOBAL, MEMOIZE,
            SBU("types"), SBU("FunctionType"), STACK_GLOBAL, MEMOIZE,
            STOP,
        )
        self._assert_flagged(payload, "marshal.loads+types.FunctionType")

    # ─── GHSA-wfq2 / GHSA-q5qq: runpy.run_path ────────────────────
    def test_runpy_run_path(self):
        payload = _build_pickle(
            PROTO5, FRAME(46),
            SBU("runpy"), MEMOIZE,
            SBU("run_path"), MEMOIZE,
            STACK_GLOBAL, MEMOIZE,
            SBU("/tmp/malicious.py"), MEMOIZE,
            TUPLE1, MEMOIZE,
            REDUCE, MEMOIZE,
            STOP,
        )
        self._assert_flagged(payload, "runpy.run_path")

    # ─── GHSA-p523: cProfile.run ───────────────────────────────────
    def test_cprofile_run(self):
        payload = _build_pickle(
            PROTO5, FRAME(58),
            SBU("cProfile"), MEMOIZE,
            SBU("run"), MEMOIZE,
            STACK_GLOBAL, MEMOIZE,
            SBU("print('RCE')"), MEMOIZE,
            TUPLE1, MEMOIZE,
            REDUCE, MEMOIZE,
            STOP,
        )
        self._assert_flagged(payload, "cProfile.run")

    # ─── GHSA-q5qq / GHSA-5hvc: ctypes.CDLL ───────────────────────
    def test_ctypes_cdll(self):
        payload = _build_pickle(
            PROTO5,
            SBU("ctypes"), MEMOIZE,
            SBU("CDLL"), MEMOIZE,
            STACK_GLOBAL, MEMOIZE,
            SBU("libc.dylib"), MEMOIZE,
            TUPLE1, MEMOIZE,
            REDUCE, MEMOIZE,
            STOP,
        )
        self._assert_flagged(payload, "ctypes.CDLL")

    # ─── GHSA-5hvc: pydoc.locate ──────────────────────────────────
    def test_pydoc_locate(self):
        payload = _build_pickle(
            PROTO5,
            SBU("pydoc"), MEMOIZE,
            SBU("locate"), MEMOIZE,
            STACK_GLOBAL, MEMOIZE,
            SBU("os.system"), MEMOIZE,
            TUPLE1, MEMOIZE,
            REDUCE, MEMOIZE,
            STOP,
        )
        self._assert_flagged(payload, "pydoc.locate")

    # ─── GHSA-q5qq: importlib.import_module ────────────────────────
    def test_importlib_import_module(self):
        payload = _build_pickle(
            PROTO5,
            SBU("importlib"), MEMOIZE,
            SBU("import_module"), MEMOIZE,
            STACK_GLOBAL, MEMOIZE,
            SBU("os"), MEMOIZE,
            TUPLE1, MEMOIZE,
            REDUCE, MEMOIZE,
            STOP,
        )
        self._assert_flagged(payload, "importlib.import_module")

    # ─── GHSA-q5qq: code.InteractiveInterpreter ────────────────────
    def test_code_interactive_interpreter(self):
        payload = _build_pickle(
            PROTO5,
            SBU("code"), MEMOIZE,
            SBU("InteractiveInterpreter"), MEMOIZE,
            STACK_GLOBAL, MEMOIZE,
            EMPTY_TUPLE, MEMOIZE,
            REDUCE, MEMOIZE,
            STOP,
        )
        self._assert_flagged(payload, "code.InteractiveInterpreter")

    # ─── GHSA-q5qq: multiprocessing.util.spawnv_passfds ─────────────
    def test_multiprocessing_spawnv(self):
        payload = _build_pickle(
            PROTO5, FRAME(74),
            SBU("multiprocessing.util"), MEMOIZE,
            SBU("spawnv_passfds"), MEMOIZE,
            STACK_GLOBAL, MEMOIZE,
            SBB(b"/bin/sh"), MEMOIZE,
            EMPTY_LIST, MEMOIZE,
            EMPTY_TUPLE,
            TUPLE3, MEMOIZE,
            REDUCE, MEMOIZE,
            STOP,
        )
        self._assert_flagged(payload, "multiprocessing.util.spawnv_passfds")

    # ─── GHSA-h4rm: builtins.__import__ + getattr chain ─────────────
    def test_builtins_import_getattr_chain(self):
        payload = _build_pickle(
            GLOBAL("builtins", "__import__"),
            STRING("os"), TUPLE1, REDUCE,
            PUT(0), POP,
            GLOBAL("builtins", "getattr"),
            GET(0), STRING("system"), TUPLE2, REDUCE,
            PUT(1), POP,
            GET(1), STRING("whoami"), TUPLE1, REDUCE,
            STOP,
        )
        self._assert_flagged(payload, "builtins.__import__+getattr chain")

    # ─── GHSA-955r: operator.methodcaller bypass ────────────────────
    def test_operator_methodcaller(self):
        payload = _build_pickle(
            PROTO4,
            SBU("_operator"), MEMOIZE,
            SBU("methodcaller"), MEMOIZE,
            STACK_GLOBAL, MEMOIZE,
            SBU("system"), MEMOIZE,
            SBU("echo pwned"), MEMOIZE,
            TUPLE2, MEMOIZE,
            REDUCE, MEMOIZE,
            STOP,
        )
        self._assert_flagged(payload, "_operator.methodcaller")

    # ─── GHSA-m273: distutils.file_util.write_file ──────────────────
    def test_distutils_write_file(self):
        payload = _build_pickle(
            PROTO4,
            SBU("distutils.file_util"), SBU("write_file"),
            STACK_GLOBAL,
            SBU("/tmp/malicious.txt"),
            MARK, SBU("evil content"), LIST,
            TUPLE2, REDUCE,
            STOP,
        )
        self._assert_flagged(payload, "distutils.file_util.write_file")

    # ─── _io.FileIO bypass ──────────────────────────────────────────
    def test_io_fileio(self):
        payload = _build_pickle(
            PROTO4,
            SBU("_io"), SBU("FileIO"), STACK_GLOBAL,
            SBU("/etc/passwd"), TUPLE1, REDUCE,
            STOP,
        )
        self._assert_flagged(payload, "_io.FileIO")

    # ─── GHSA-r8g5: numpy.f2py.crackfortran.getlincoef ──────────────
    def test_numpy_f2py_getlincoef(self):
        payload = _build_pickle(
            PROTO4,
            SBU("numpy.f2py.crackfortran"), SBU("getlincoef"),
            STACK_GLOBAL,
            SBU("__import__('os').system('id')"),
            EMPTY_DICT, TUPLE2, REDUCE,
            STOP,
        )
        self._assert_flagged(payload, "numpy.f2py.crackfortran.getlincoef")

    # ─── GHSA-f7qq: asyncio.unix_events subprocess ──────────────────
    def test_asyncio_subprocess(self):
        payload = _build_pickle(
            PROTO4, FRAME(81),
            SBU("asyncio.unix_events"), MEMOIZE,
            SBU("_UnixSubprocessTransport._start"), MEMOIZE,
            STACK_GLOBAL, MEMOIZE,
            MARK,
            EMPTY_DICT, MEMOIZE,
            SBU("whoami"), MEMOIZE,
            NEWTRUE, NONE, NONE, NONE,
            BININT1(0),
            TUPLE, MEMOIZE,
            REDUCE, MEMOIZE,
            STOP,
        )
        self._assert_flagged(payload, "asyncio.unix_events subprocess")

    # ─── GHSA-5hwf: uuid._get_command_stdout ─────────────────────────
    def test_uuid_get_command_stdout(self):
        payload = _build_pickle(
            PROTO4,
            SBU("uuid"), SBU("_get_command_stdout"),
            STACK_GLOBAL,
            SBU("echo"), SBU("PROOF"), TUPLE2, REDUCE,
            STOP,
        )
        self._assert_flagged(payload, "uuid._get_command_stdout")

    # ─── GHSA-5hwf: _aix_support._read_cmd_output ───────────────────
    def test_aix_support(self):
        payload = _build_pickle(
            PROTO4,
            SBU("_aix_support"), SBU("_read_cmd_output"),
            STACK_GLOBAL,
            SBU("echo PROOF"), TUPLE1, REDUCE,
            STOP,
        )
        self._assert_flagged(payload, "_aix_support._read_cmd_output")

    # ─── GHSA-5hwf: _osx_support._find_build_tool ───────────────────
    def test_osx_support(self):
        payload = _build_pickle(
            PROTO4,
            SBU("_osx_support"), SBU("_find_build_tool"),
            STACK_GLOBAL,
            SBU("x; echo INJECTED #"), TUPLE1, REDUCE,
            STOP,
        )
        self._assert_flagged(payload, "_osx_support._find_build_tool")

    # ─── Network SSRF vectors ───────────────────────────────────────
    def test_smtplib_smtp(self):
        payload = _build_pickle(
            PROTO4,
            SBU("smtplib"), SBU("SMTP"), STACK_GLOBAL,
            SBU("127.0.0.1"), BININT2(25), TUPLE2, REDUCE,
            STOP,
        )
        self._assert_flagged(payload, "smtplib.SMTP")

    def test_ftplib_ftp(self):
        payload = _build_pickle(
            PROTO4,
            SBU("ftplib"), SBU("FTP"), STACK_GLOBAL,
            SBU("127.0.0.1"), TUPLE1, REDUCE,
            STOP,
        )
        self._assert_flagged(payload, "ftplib.FTP")

    def test_poplib_pop3(self):
        payload = _build_pickle(
            PROTO4,
            SBU("poplib"), SBU("POP3"), STACK_GLOBAL,
            SBU("127.0.0.1"), BININT2(110), TUPLE2, REDUCE,
            STOP,
        )
        self._assert_flagged(payload, "poplib.POP3")

    def test_telnetlib_telnet(self):
        payload = _build_pickle(
            PROTO4,
            SBU("telnetlib"), SBU("Telnet"), STACK_GLOBAL,
            SBU("127.0.0.1"), BININT2(23), TUPLE2, REDUCE,
            STOP,
        )
        self._assert_flagged(payload, "telnetlib.Telnet")

    def test_nntplib_nntp(self):
        payload = _build_pickle(
            PROTO4,
            SBU("nntplib"), SBU("NNTP"), STACK_GLOBAL,
            SBU("127.0.0.1"), BININT2(119), TUPLE2, REDUCE,
            STOP,
        )
        self._assert_flagged(payload, "nntplib.NNTP")

    # ─── functools.partial / operator.attrgetter (our old bug) ──────
    def test_functools_partial(self):
        payload = _build_pickle(
            PROTO4,
            SBU("functools"), SBU("partial"), STACK_GLOBAL,
            STOP,
        )
        self._assert_flagged(payload, "functools.partial")

    def test_operator_attrgetter(self):
        payload = _build_pickle(
            PROTO4,
            SBU("operator"), SBU("attrgetter"), STACK_GLOBAL,
            SBU("system"), TUPLE1, REDUCE,
            STOP,
        )
        self._assert_flagged(payload, "operator.attrgetter")

    # ─── Classic os.system via GLOBAL (protocol 0) ──────────────────
    def test_os_system_protocol0(self):
        payload = _build_pickle(
            GLOBAL("os", "system"),
            STRING("echo pwned"),
            TUPLE1, REDUCE,
            STOP,
        )
        self._assert_flagged(payload, "os.system proto0")

    # ─── torch.storage._load_from_bytes ─────────────────────────────
    def test_torch_storage_load_from_bytes(self):
        payload = _build_pickle(
            PROTO4,
            SBU("torch.storage"), SBU("_load_from_bytes"),
            STACK_GLOBAL, MEMOIZE,
            SBB(b"malicious_pickle_bytes"),
            TUPLE1, REDUCE,
            STOP,
        )
        self._assert_flagged(payload, "torch.storage._load_from_bytes")

    # ─── shelve.open (database access with embedded pickle) ─────────
    def test_shelve_open(self):
        payload = _build_pickle(
            PROTO4,
            SBU("shelve"), SBU("open"), STACK_GLOBAL,
            SBU("/tmp/evil.db"), TUPLE1, REDUCE,
            STOP,
        )
        self._assert_flagged(payload, "shelve.open")

    # ─── pickle-in-pickle via _pickle.loads ─────────────────────────
    def test_pickle_in_pickle(self):
        payload = _build_pickle(
            PROTO4,
            SBU("_pickle"), SBU("loads"), STACK_GLOBAL,
            SBB(b"\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00N."),
            TUPLE1, REDUCE,
            STOP,
        )
        self._assert_flagged(payload, "_pickle.loads (pickle-in-pickle)")

    # ─── INST opcode (protocol 0) ──────────────────────────────────
    def test_inst_opcode(self):
        payload = _build_pickle(
            INST("os", "system"),
            STRING("id"),
            TUPLE1, REDUCE,
            STOP,
        )
        self._assert_flagged(payload, "INST os.system")


class TestMLAllowlist(unittest.TestCase):
    """Verify that safe ML imports are NOT flagged as dangerous."""

    def setUp(self):
        self.scanner = PickleScanner()

    def _assert_safe(self, data: bytes, msg: str):
        findings = self.scanner.scan_bytes(data, source=f"<test:{msg}>")
        dangerous = [
            f for f in findings
            if f.severity == Severity.CRITICAL
            and "Dangerous pickle import" in f.title
        ]
        self.assertEqual(
            len(dangerous), 0,
            f"Expected safe import {msg} NOT flagged, but got: "
            f"{[f.title for f in dangerous]}",
        )

    def test_collections_ordered_dict(self):
        payload = _build_pickle(
            PROTO4,
            SBU("collections"), SBU("OrderedDict"), STACK_GLOBAL,
            EMPTY_TUPLE, REDUCE, STOP,
        )
        self._assert_safe(payload, "collections.OrderedDict")

    def test_numpy_reconstruct(self):
        payload = _build_pickle(
            PROTO4,
            SBU("numpy.core.multiarray"), SBU("_reconstruct"),
            STACK_GLOBAL,
            STOP,
        )
        self._assert_safe(payload, "numpy.core.multiarray._reconstruct")

    def test_copyreg_reconstructor(self):
        payload = _build_pickle(
            PROTO4,
            SBU("copyreg"), SBU("_reconstructor"), STACK_GLOBAL,
            STOP,
        )
        self._assert_safe(payload, "copyreg._reconstructor")

    def test_torch_float_storage(self):
        payload = _build_pickle(
            PROTO4,
            SBU("torch"), SBU("FloatStorage"), STACK_GLOBAL,
            STOP,
        )
        self._assert_safe(payload, "torch.FloatStorage")

    def test_torch_rebuild_tensor_v2(self):
        payload = _build_pickle(
            PROTO4,
            SBU("torch._utils"), SBU("_rebuild_tensor_v2"),
            STACK_GLOBAL,
            STOP,
        )
        self._assert_safe(payload, "torch._utils._rebuild_tensor_v2")

    def test_builtins_dict_safe(self):
        payload = _build_pickle(
            GLOBAL("builtins", "dict"),
            EMPTY_TUPLE, REDUCE, STOP,
        )
        self._assert_safe(payload, "builtins.dict")

    def test_builtins_len_safe(self):
        payload = _build_pickle(
            GLOBAL("builtins", "len"),
            EMPTY_LIST, TUPLE1, REDUCE, STOP,
        )
        self._assert_safe(payload, "builtins.len")

    def test_io_bytesio_safe(self):
        payload = _build_pickle(
            PROTO4,
            SBU("_io"), SBU("BytesIO"), STACK_GLOBAL,
            STOP,
        )
        self._assert_safe(payload, "_io.BytesIO")

    def test_codecs_encode_safe(self):
        payload = _build_pickle(
            PROTO4,
            SBU("_codecs"), SBU("encode"), STACK_GLOBAL,
            STOP,
        )
        self._assert_safe(payload, "_codecs.encode")


if __name__ == "__main__":
    unittest.main()
