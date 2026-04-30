"""Safe code assertion runner — disabled by default, sandbox-only execution."""
from __future__ import annotations

import ast
import logging
from dataclasses import dataclass
from typing import Any

from sentinel.redteam.assertion_registry import AssertionResult, AssertionStatus

logger = logging.getLogger(__name__)

_FORBIDDEN_NODES = (
    ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal,
    ast.AsyncFunctionDef, ast.ClassDef,
)

_FORBIDDEN_NAMES = frozenset({
    "exec", "eval", "compile", "__import__", "open",
    "os", "sys", "subprocess", "shutil", "pathlib",
})


@dataclass
class CodeAssertionConfig:
    enabled: bool = False
    max_execution_ms: int = 1000
    max_output_chars: int = 10000
    allowed_builtins: frozenset[str] = frozenset({
        "len", "str", "int", "float", "bool", "list", "dict",
        "set", "tuple", "range", "enumerate", "zip", "map", "filter",
        "sorted", "reversed", "min", "max", "sum", "any", "all",
        "isinstance", "type", "hasattr", "getattr",
    })


def validate_code_safety(code: str) -> tuple[bool, str]:
    """Check if code is safe to execute in sandbox."""
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return False, f"Syntax error: {e}"

    for node in ast.walk(tree):
        if isinstance(node, _FORBIDDEN_NODES):
            return False, f"Forbidden node: {type(node).__name__}"
        if isinstance(node, ast.Name) and node.id in _FORBIDDEN_NAMES:
            return False, f"Forbidden name: {node.id}"
        if isinstance(node, ast.Attribute) and node.attr.startswith("__"):
            return False, f"Forbidden dunder access: {node.attr}"

    return True, "Code is safe"


def run_code_assertion(
    code: str,
    context: dict[str, Any],
    config: CodeAssertionConfig | None = None,
) -> AssertionResult:
    """Run a code-based assertion in a restricted environment."""
    cfg = config or CodeAssertionConfig()

    if not cfg.enabled:
        return AssertionResult(
            assertion_id="code-assertion",
            status=AssertionStatus.SKIP,
            message="Code assertions are disabled by default",
        )

    safe, reason = validate_code_safety(code)
    if not safe:
        return AssertionResult(
            assertion_id="code-assertion",
            status=AssertionStatus.ERROR,
            message=f"Unsafe code rejected: {reason}",
        )

    safe_builtins = {k: __builtins__[k] if isinstance(__builtins__, dict) else getattr(__builtins__, k) for k in cfg.allowed_builtins if hasattr(__builtins__, k) or (isinstance(__builtins__, dict) and k in __builtins__)}

    sandbox = {"__builtins__": safe_builtins}
    sandbox.update(context)

    try:
        exec(code, sandbox)  # noqa: S102 — intentional sandboxed exec
        result_val = sandbox.get("result")
        if result_val is True:
            return AssertionResult(
                assertion_id="code-assertion",
                status=AssertionStatus.PASS,
                message="Code assertion passed",
                actual=result_val,
            )
        elif result_val is False:
            return AssertionResult(
                assertion_id="code-assertion",
                status=AssertionStatus.FAIL,
                message="Code assertion failed",
                actual=result_val,
            )
        else:
            return AssertionResult(
                assertion_id="code-assertion",
                status=AssertionStatus.PASS,
                message=f"Code executed, result={result_val}",
                actual=result_val,
            )
    except Exception as e:
        return AssertionResult(
            assertion_id="code-assertion",
            status=AssertionStatus.ERROR,
            message=f"Execution error: {e}",
        )
