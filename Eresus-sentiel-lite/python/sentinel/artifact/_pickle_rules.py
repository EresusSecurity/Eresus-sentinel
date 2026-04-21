"""Pickle scanning rules — loads everything from artifact_blocklist.yaml."""

from __future__ import annotations

from ..finding import Severity
from ..rules import load_artifact_blocklist, load_artifact_allowlist


def load_default_rules() -> tuple[dict, dict]:
    """Load blocklist + allowlist from YAML. Zero hardcoded data."""
    blocklist = load_artifact_blocklist()
    allowlist = load_artifact_allowlist()
    return blocklist, allowlist


# ── Severity classification ───────────────────────────────────────────

_CRITICAL_NAMES = frozenset({
    "exec", "eval", "compile", "system", "popen",
    "Popen", "call", "check_output", "run",
    "__import__", "getattr", "execfile", "apply",
    "FunctionType", "CodeType",
    "loads",
    "spawnv_passfds", "_run_entry_point", "runstring",
    "_load_from_bytes", "add_extension",
    "__subclasses__", "__builtins__",
    "partial", "attrgetter", "methodcaller",
})

_CRITICAL_MODULES = frozenset({
    "marshal", "types",
    "mlflow.projects.backend.local",
    "torch.storage",
})

_NETWORK_MODULES = frozenset({
    "socket", "http.client", "http.server",
    "urllib", "urllib.request", "urllib.parse",
    "requests", "httpx", "aiohttp",
    "ftplib", "smtplib", "imaplib",
    "pandas.io.parsers.readers", "pandas.io.parsers",
})

_FFI_MODULES = frozenset({
    "ctypes", "cffi", "dl",
})

_FS_DESTRUCTIVE = frozenset({
    "rmtree", "remove", "unlink", "rename", "chmod", "chown",
})

_CONCURRENCY_MODULES = frozenset({
    "_thread", "threading", "multiprocessing",
})


def classify_severity(module: str, name: str) -> Severity:
    """Classify severity based on the import's capability."""
    if name in _CRITICAL_NAMES or name.startswith("exec"):
        return Severity.CRITICAL

    if module in _CRITICAL_MODULES:
        return Severity.CRITICAL

    if module in _NETWORK_MODULES:
        return Severity.HIGH

    if name in _FS_DESTRUCTIVE:
        return Severity.HIGH

    if module in _CONCURRENCY_MODULES:
        return Severity.HIGH

    if module in _FFI_MODULES:
        return Severity.HIGH

    return Severity.HIGH


# ── Match logic ───────────────────────────────────────────────────────

_UNIVERSAL_DANGEROUS = frozenset({
    "__import__", "getattr", "setattr", "delattr",
    "eval", "exec", "execfile", "apply",
    "__subclasses__", "__base__", "__mro__",
    "__globals__", "__builtins__",
    "__getattribute__", "__class__",
})

_HEURISTIC_KEYWORDS = (
    "exec", "eval", "system", "popen",
    "__subclasses__", "__builtins__", "__init__.__builtins__",
    "spawnv", "_run_entry", "runstring",
    "_load_from_bytes", "add_extension",
    "FunctionType", "CodeType",
    "timeit", "read_pickle",
)

# Modules where heuristic keyword substring matching should be suppressed
# because their attribute names legitimately contain those substrings.
_HEURISTIC_SAFE_CONTEXTS = frozenset({
    "re", "ast", "platform", "functools", "operator",
    "pathlib", "uuid", "signal", "math", "statistics",
    "collections", "itertools", "string", "textwrap",
    "dataclasses", "typing", "enum", "decimal", "fractions",
    "datetime", "calendar", "time", "locale", "copy",
    "json", "csv", "configparser", "logging", "unittest",
    "pprint", "heapq", "bisect", "array", "struct",
    "hashlib", "hmac", "secrets", "html", "xml",
    "email", "mimetypes", "difflib", "abc",
    "numpy", "numpy.core", "numpy.core.multiarray",
    "numpy._core.multiarray", "numpy.core.numeric",
    "torch", "torch._utils", "torch._tensor", "torch._C",
    "torch.nn.modules.module", "torch.nn.modules.linear",
    "sklearn", "pandas",
})


def is_dangerous(module: str, name: str, blocklist: dict, allowlist: dict) -> bool:
    """Check if a module.name is blocked (allowlist wins over blocklist)."""
    # Allowlist takes priority
    if _check_list(module, name, allowlist):
        return False

    # Blocklist
    if _check_list(module, name, blocklist):
        return True

    # Universal catch-all
    if name in _UNIVERSAL_DANGEROUS:
        return True

    # Heuristic fallback — skip if module is known-safe context
    if module not in _HEURISTIC_SAFE_CONTEXTS:
        name_lower = name.lower()
        if any(k in name_lower for k in _HEURISTIC_KEYWORDS):
            return True

    return False


def _check_list(module: str, name: str, rule_dict: dict) -> bool:
    """Check module.name against a blocklist/allowlist dict."""
    # Exact module match
    if module in rule_dict:
        for pattern in rule_dict[module]:
            if _matches_pattern(name, pattern):
                return True

    # Wildcard module match (e.g. "sklearn.*")
    for mod_pattern, names in rule_dict.items():
        if mod_pattern.endswith(".*"):
            prefix = mod_pattern[:-2]
            if module == prefix or module.startswith(prefix + "."):
                for pattern in names:
                    if _matches_pattern(name, pattern):
                        return True

    # Parent module wildcard propagation:
    # If os has "*", then os.path.join is also blocked.
    if "." in module:
        parts = module.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[:i])
            if parent in rule_dict:
                for pattern in rule_dict[parent]:
                    if pattern == "*":
                        return True

    return False


def _matches_pattern(name: str, pattern: str) -> bool:
    """Match function name against pattern. * = wildcard suffix."""
    if pattern == "*":
        return True
    if pattern.endswith("*"):
        return name.startswith(pattern[:-1])
    return name == pattern


# ── Rule ID mapping ──────────────────────────────────────────────────

_CATEGORY_MAP = {
    "builtins": "001", "__builtin__": "001",
    "os": "002", "nt": "021", "posixpath": "022",
    "subprocess": "003",
    "socket": "004", "http.client": "005", "http.server": "005",
    "webbrowser": "006",
    "shutil": "007", "pathlib": "007", "glob": "007",
    "ctypes": "008", "cffi": "008", "_ctypes": "008",
    "importlib": "009", "importlib.util": "009", "pkgutil": "009",
    "code": "010", "codeop": "010",
    "runpy": "011",
    "sys": "012",
    "signal": "013",
    "marshal": "014", "types": "014",
    "io": "015", "_io": "015",
    "ast": "016", "compile": "016",
    "compileall": "016",
    "base64": "018", "codecs": "019", "binascii": "019",
    "zlib": "019", "gzip": "019", "bz2": "019", "lzma": "019",
    "types": "020",
    "_thread": "023", "threading": "023",
    "multiprocessing": "024", "concurrent.futures": "024",
    "asyncio": "024",
    "pickle": "025", "_pickle": "025",
    "shelve": "025", "dill": "025", "cloudpickle": "025",
    "joblib": "025", "jsonpickle": "025", "yaml": "025",
    "tempfile": "026",
    "zipfile": "027", "tarfile": "028",
    "inspect": "029", "traceback": "029", "pdb": "029", "gc": "029",
    # Cloud / credential
    "boto3": "030", "botocore": "031",
    "google.auth": "032", "azure.identity": "033",
    # ML framework
    "torch.hub": "040", "torch.utils.model_zoo": "041",
    "transformers": "042", "huggingface_hub": "043",
    "tensorflow": "044",
    # Platform / environment
    "winreg": "050", "win32api": "050", "win32com.shell": "050",
    "mmap": "051", "resource": "051",
    "platform": "052", "getpass": "053", "pwd": "054", "grp": "054",
    # Class construction
    "functools": "060", "operator": "061", "itertools": "062",
    # Network extras
    "urllib.request": "004", "urllib.parse": "004",
    "requests": "004", "httpx": "004",
    "ftplib": "004", "smtplib": "004",
    "xmlrpc.client": "004",
    # File system extras
    "fnmatch": "007",
    "cloudpickle.cloudpickle": "025",
    "numpy.f2py": "070", "numpy.testing._private.utils": "070",
    "posix": "002",  # alias for os on Linux
    "aiohttp": "004", "httplib": "004", "requests.api": "004",
    "commands": "003",  # Python 2 subprocess
    "bdb": "029",
    "logging": "071",
    "pty": "072",
    "cProfile": "073", "profile": "073",
    "timeit": "074",
    "doctest": "075", "ensurepip": "076",
    "pip": "076",
    "pydoc": "077",
    "test": "078",
    "ssl": "079",
    "uuid": "080",
    "venv": "081",
    "imaplib": "004",
    "idlelib.autocomplete": "082", "idlelib.calltip": "082",
    "idlelib.debugobj": "082", "idlelib.pyshell": "082", "idlelib.run": "082",
    "lib2to3.pgen2.grammar": "083", "lib2to3.pgen2.pgen": "083",
    "trace": "084",
    "torch._dynamo.guards": "085", "torch._inductor.codecache": "085",
    "torch.fx.experimental.symbolic_shapes": "085",
    "torch.jit.unsupported_tensor_ops": "085",
    "torch.serialization": "085",
    "torch.utils._config_module": "085",
    "torch.utils.bottleneck.__main__": "085",
    "torch.utils.collect_env": "085",
    "torch.utils.data.datapipes.utils.decoder": "085",
    "multiprocessing.util": "024",
    "mlflow.projects.backend.local": "090",
    "pandas.io.parsers.readers": "091",
    "pandas.io.parsers": "091",
    "torch.storage": "085",
    "copyreg": "092",
    "copy": "093",
    "transformers.models.auto.auto_factory": "042",
    "transformers.models.auto.tokenization_auto": "042",
    "yaml.loader": "025",
    "pandas": "091",
    "pandas.compat.pickle_compat": "091",
    "timeit": "094",
    "signal": "095",
    "_signal": "095",
    "_operator": "061",
    "distutils.file_util": "086",
    "_osx_support": "087", "_aix_support": "087", "_pyrepl": "088",
}


def rule_id_for_module(module: str, opcode: str) -> str:
    """Generate a stable rule ID for a dangerous import type."""
    if opcode == "PARSE_ERROR":
        return "ARTIFACT-000"

    suffix = _CATEGORY_MAP.get(module, "099")
    return f"ARTIFACT-{suffix}"
