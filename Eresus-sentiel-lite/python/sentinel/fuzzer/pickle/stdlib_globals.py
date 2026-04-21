"""Standard library module/attribute pairs for GLOBAL opcode emission."""

from __future__ import annotations

# (module, attribute) pairs — curated from CPython stdlib
STDLIB_GLOBALS: list[tuple[str, str]] = [
    # builtins (high-value for RCE detection testing)
    ("builtins", "object"),
    ("builtins", "type"),
    ("builtins", "dict"),
    ("builtins", "list"),
    ("builtins", "tuple"),
    ("builtins", "set"),
    ("builtins", "frozenset"),
    ("builtins", "bytes"),
    ("builtins", "bytearray"),
    ("builtins", "str"),
    ("builtins", "int"),
    ("builtins", "float"),
    ("builtins", "bool"),
    ("builtins", "complex"),
    ("builtins", "range"),
    ("builtins", "slice"),
    ("builtins", "map"),
    ("builtins", "filter"),
    ("builtins", "zip"),
    ("builtins", "enumerate"),
    ("builtins", "reversed"),
    ("builtins", "sorted"),
    ("builtins", "getattr"),
    ("builtins", "setattr"),
    ("builtins", "hasattr"),
    ("builtins", "isinstance"),
    ("builtins", "issubclass"),
    ("builtins", "len"),
    ("builtins", "repr"),
    ("builtins", "print"),
    ("builtins", "globals"),
    ("builtins", "locals"),
    ("builtins", "__import__"),
    ("builtins", "eval"),
    ("builtins", "exec"),
    ("builtins", "compile"),
    ("builtins", "input"),
    ("builtins", "open"),
    ("builtins", "memoryview"),

    # collections
    ("collections", "OrderedDict"),
    ("collections", "defaultdict"),
    ("collections", "deque"),
    ("collections", "Counter"),
    ("collections", "ChainMap"),
    ("collections", "namedtuple"),

    # copy_reg / copyreg
    ("copyreg", "_reconstructor"),
    ("copyreg", "dispatch_table"),
    ("copyreg", "add_extension"),
    ("copyreg", "remove_extension"),
    ("copy_reg", "_reconstructor"),

    # os (dangerous — scanners must catch these)
    ("os", "system"),
    ("os", "popen"),
    ("os", "execve"),
    ("os", "execvp"),
    ("os", "forkpty"),
    ("os", "getenv"),
    ("os", "putenv"),
    ("os", "remove"),
    ("os", "unlink"),
    ("os", "rename"),
    ("os", "makedirs"),
    ("os", "listdir"),
    ("os", "getcwd"),
    ("os.path", "join"),
    ("os.path", "exists"),
    ("os.path", "abspath"),
    ("posixpath", "join"),
    ("ntpath", "join"),

    # subprocess (dangerous)
    ("subprocess", "Popen"),
    ("subprocess", "call"),
    ("subprocess", "check_output"),
    ("subprocess", "check_call"),
    ("subprocess", "run"),

    # sys
    ("sys", "exit"),
    ("sys", "modules"),
    ("sys", "path"),
    ("sys", "argv"),
    ("sys", "stdin"),
    ("sys", "stdout"),
    ("sys", "stderr"),

    # io
    ("io", "BytesIO"),
    ("io", "StringIO"),
    ("io", "open"),
    ("_io", "BytesIO"),
    ("_io", "StringIO"),

    # codecs
    ("_codecs", "encode"),
    ("_codecs", "decode"),
    ("codecs", "encode"),
    ("codecs", "decode"),

    # struct
    ("struct", "pack"),
    ("struct", "unpack"),
    ("struct", "Struct"),
    ("_struct", "Struct"),

    # array
    ("array", "array"),

    # pickle (nested deserialization)
    ("pickle", "loads"),
    ("pickle", "dumps"),
    ("_pickle", "loads"),
    ("_pickle", "dumps"),

    # marshal (code object hiding)
    ("marshal", "loads"),
    ("marshal", "dumps"),

    # types (code injection)
    ("types", "CodeType"),
    ("types", "FunctionType"),
    ("types", "ModuleType"),
    ("types", "MethodType"),
    ("types", "LambdaType"),
    ("types", "GeneratorType"),

    # importlib
    ("importlib", "import_module"),
    ("importlib", "__import__"),

    # ctypes (FFI)
    ("ctypes", "CDLL"),
    ("ctypes", "cdll"),
    ("ctypes", "pythonapi"),

    # socket (network)
    ("socket", "socket"),
    ("socket", "create_connection"),
    ("socket", "getaddrinfo"),

    # urllib (SSRF)
    ("urllib.request", "urlopen"),
    ("urllib.request", "Request"),
    ("urllib.request", "urlretrieve"),

    # http
    ("http.client", "HTTPConnection"),
    ("http.client", "HTTPSConnection"),
    ("http.server", "HTTPServer"),

    # shutil (destruction)
    ("shutil", "rmtree"),
    ("shutil", "copy2"),
    ("shutil", "move"),

    # signal
    ("signal", "signal"),
    ("signal", "alarm"),

    # threading
    ("threading", "Thread"),
    ("threading", "Timer"),

    # multiprocessing
    ("multiprocessing", "Process"),

    # runpy
    ("runpy", "run_module"),
    ("runpy", "run_path"),

    # tempfile
    ("tempfile", "NamedTemporaryFile"),
    ("tempfile", "mkdtemp"),

    # json / yaml
    ("json", "loads"),
    ("json", "dumps"),

    # base64 (obfuscation)
    ("base64", "b64decode"),
    ("base64", "b64encode"),
    ("base64", "b32decode"),

    # zlib (obfuscation)
    ("zlib", "decompress"),
    ("zlib", "compress"),

    # hashlib
    ("hashlib", "md5"),
    ("hashlib", "sha256"),

    # re
    ("re", "compile"),
    ("re", "match"),
    ("re", "search"),

    # functools
    ("functools", "reduce"),
    ("functools", "partial"),

    # operator
    ("operator", "attrgetter"),
    ("operator", "itemgetter"),
    ("operator", "methodcaller"),

    # itertools
    ("itertools", "chain"),
    ("itertools", "product"),

    # datetime
    ("datetime", "datetime"),
    ("datetime", "date"),
    ("datetime", "timedelta"),

    # decimal
    ("decimal", "Decimal"),

    # fractions
    ("fractions", "Fraction"),

    # pathlib
    ("pathlib", "Path"),
    ("pathlib", "PurePosixPath"),

    # uuid
    ("uuid", "UUID"),
    ("uuid", "uuid4"),

    # math
    ("math", "sqrt"),
    ("math", "sin"),

    # random
    ("random", "Random"),
    ("random", "seed"),

    # string
    ("string", "Template"),
    ("string", "Formatter"),

    # abc
    ("abc", "ABCMeta"),

    # weakref
    ("weakref", "ref"),
    ("weakref", "WeakValueDictionary"),

    # enum
    ("enum", "Enum"),
    ("enum", "IntEnum"),

    # dataclasses
    ("dataclasses", "dataclass"),

    # contextlib
    ("contextlib", "contextmanager"),

    # logging
    ("logging", "getLogger"),
    ("logging", "basicConfig"),

    # warnings
    ("warnings", "warn"),

    # traceback
    ("traceback", "format_exc"),

    # inspect
    ("inspect", "getmembers"),
    ("inspect", "stack"),

    # ast
    ("ast", "literal_eval"),
    ("ast", "parse"),

    # platform
    ("platform", "system"),
    ("platform", "node"),

    # requests (third-party but commonly seen)
    ("requests", "get"),
    ("requests", "post"),

    # numpy-style (common in ML pickles)
    ("numpy", "array"),
    ("numpy", "ndarray"),
    ("numpy.core.multiarray", "_reconstruct"),

    # torch-style (common in ML pickles)
    ("torch", "FloatTensor"),
    ("torch._utils", "_rebuild_tensor_v2"),

    # sklearn-style
    ("sklearn.tree", "DecisionTreeClassifier"),

    # pandas-style
    ("pandas.core.frame", "DataFrame"),
    ("pandas.core.series", "Series"),
]


def get_random_global(rng) -> tuple[str, str]:
    """Select a random stdlib global pair."""
    return rng.choice(STDLIB_GLOBALS)


# Pre-computed safe subset: globals that won't trigger the pickle scanner.
# This is used for benign pickle generation to avoid false positives.
_SAFE_GLOBALS: list[tuple[str, str]] | None = None


def get_random_safe_global(rng) -> tuple[str, str]:
    """Select a random global that won't trigger the pickle scanner.

    Used by the benign pickle generator so FPR measurement is accurate.
    """
    global _SAFE_GLOBALS
    if _SAFE_GLOBALS is None:
        from ...artifact._pickle_rules import is_dangerous, load_default_rules
        blocklist, allowlist = load_default_rules()
        _SAFE_GLOBALS = [
            (m, n) for m, n in STDLIB_GLOBALS
            if not is_dangerous(m, n, blocklist, allowlist)
        ]
        if not _SAFE_GLOBALS:
            # Fallback: absolute minimum safe set
            _SAFE_GLOBALS = [
                ("builtins", "int"), ("builtins", "float"),
                ("builtins", "str"), ("builtins", "list"),
                ("builtins", "dict"), ("builtins", "tuple"),
                ("builtins", "set"), ("builtins", "bool"),
                ("builtins", "object"), ("builtins", "bytes"),
                ("collections", "OrderedDict"),
                ("collections", "defaultdict"),
            ]
    return rng.choice(_SAFE_GLOBALS)


def get_globals_by_module(module: str) -> list[tuple[str, str]]:
    """Get all globals for a specific module."""
    return [(m, a) for m, a in STDLIB_GLOBALS if m == module]
