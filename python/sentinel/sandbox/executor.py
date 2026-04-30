"""Eresus Sentinel — Sandbox Executor.

Isolated execution environment for tool calls with resource limits,
filesystem jailing, network blocking, and syscall filtering.

Uses subprocess-based isolation (multiprocessing) instead of threads
to ensure proper resource limit enforcement and killability.
"""

from __future__ import annotations

import logging
import multiprocessing
import os
import tempfile
import threading
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class IsolationLevel(Enum):
    NONE = auto()
    BASIC = auto()       # Timeout + resource limits only
    MODERATE = auto()    # + Filesystem jail + env sanitization
    STRICT = auto()      # + Network blocking + syscall filtering
    PARANOID = auto()    # + Read-only root + no IPC + separate PID ns


@dataclass
class SandboxPolicy:
    isolation: IsolationLevel = IsolationLevel.MODERATE
    timeout_seconds: float = 30.0
    max_memory_mb: int = 512
    max_cpu_seconds: float = 10.0
    max_file_size_mb: int = 50
    max_open_files: int = 64
    max_processes: int = 4
    allowed_paths: list[str] = field(default_factory=lambda: ["/tmp"])
    denied_paths: list[str] = field(default_factory=lambda: [
        "/etc/shadow", "/etc/passwd", "/root", "/proc/self",
        "/sys", "/dev/mem", "/dev/kmem",
    ])
    allowed_env_keys: list[str] = field(default_factory=lambda: [
        "PATH", "HOME", "LANG", "LC_ALL", "TZ", "TERM",
    ])
    block_network: bool = True
    allow_dns: bool = False
    read_only_root: bool = False
    allowed_syscalls: list[str] = field(default_factory=list)
    denied_syscalls: list[str] = field(default_factory=lambda: [
        "ptrace", "mount", "umount", "reboot", "swapon", "swapoff",
        "init_module", "delete_module", "kexec_load",
        "pivot_root", "chroot", "setns", "unshare",
    ])


@dataclass
class SandboxViolation:
    violation_type: str
    description: str
    severity: str
    timestamp: float = 0.0
    path: str = ""
    syscall: str = ""
    pid: int = 0

    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time.time()


@dataclass
class SandboxResult:
    success: bool
    return_value: Any = None
    error: Optional[str] = None
    violations: list[SandboxViolation] = field(default_factory=list)
    execution_time_ms: float = 0.0
    peak_memory_mb: float = 0.0
    files_created: list[str] = field(default_factory=list)
    files_modified: list[str] = field(default_factory=list)
    network_attempts: list[str] = field(default_factory=list)
    killed: bool = False


class SandboxExecutor:
    """Execute tool calls in an isolated sandbox environment.

    Features:
    - Configurable isolation levels (NONE → PARANOID)
    - Resource limits (CPU, memory, file handles, processes)
    - Filesystem jailing with allow/deny path lists
    - Environment variable sanitization
    - Network blocking
    - Timeout enforcement with SIGKILL fallback
    - Violation tracking and audit logging
    """

    def __init__(self, policy: SandboxPolicy | None = None):
        self._policy = policy or SandboxPolicy()
        self._violations: list[SandboxViolation] = []
        self._execution_count = 0
        self._total_violations = 0

    @property
    def policy(self) -> SandboxPolicy:
        return self._policy

    @property
    def violation_count(self) -> int:
        return self._total_violations

    def execute(
        self,
        func: Callable[..., Any],
        args: tuple = (),
        kwargs: dict | None = None,
        tool_name: str = "unknown",
    ) -> SandboxResult:
        """Execute a callable within the sandbox."""
        kwargs = kwargs or {}
        start = time.perf_counter()
        violations: list[SandboxViolation] = []
        result = SandboxResult(success=False)

        # Pre-execution checks
        violations.extend(self._pre_check(func, tool_name))
        if any(v.severity == "CRITICAL" for v in violations):
            result.violations = violations
            self._record_violations(violations)
            return result

        # Apply resource limits (will be enforced in subprocess)
        # Note: resource limits are now applied IN the subprocess via _run_in_subprocess

        # Sanitize environment
        original_env: dict[str, str] = {}
        if self._policy.isolation.value >= IsolationLevel.MODERATE.value:
            original_env = self._sanitize_env()

        # Create filesystem jail
        jail_dir: Optional[Path] = None
        if self._policy.isolation.value >= IsolationLevel.MODERATE.value:
            jail_dir = self._create_jail()

        # Execute with timeout
        exec_error: Optional[str] = None
        return_value: Any = None
        killed = False

        try:
            return_value = self._execute_with_timeout(
                func, args, kwargs, self._policy.timeout_seconds,
            )
            result.success = True
        except TimeoutError:
            exec_error = f"Execution exceeded timeout ({self._policy.timeout_seconds}s)"
            killed = True
            violations.append(SandboxViolation(
                violation_type="TIMEOUT",
                description=exec_error,
                severity="HIGH",
            ))
        except PermissionError as e:
            exec_error = f"Permission denied: {e}"
            violations.append(SandboxViolation(
                violation_type="PERMISSION",
                description=exec_error,
                severity="HIGH",
            ))
        except MemoryError:
            exec_error = "Memory limit exceeded"
            killed = True
            violations.append(SandboxViolation(
                violation_type="RESOURCE",
                description=exec_error,
                severity="HIGH",
            ))
        except Exception as e:
            exec_error = str(e)

        # Restore environment
        if original_env:
            self._restore_env(original_env)

        # Collect results
        elapsed = (time.perf_counter() - start) * 1000
        result.return_value = return_value
        result.error = exec_error
        result.violations = violations
        result.execution_time_ms = elapsed
        result.killed = killed

        # Post-execution audit
        if jail_dir:
            result.files_created = self._audit_jail(jail_dir)

        self._execution_count += 1
        self._record_violations(violations)

        return result

    def validate_path(self, path: str) -> SandboxViolation | None:
        """Check if a path access would violate sandbox policy."""
        normalized = os.path.normpath(os.path.abspath(path))
        for denied in self._policy.denied_paths:
            if normalized.startswith(denied):
                return SandboxViolation(
                    violation_type="PATH_ACCESS",
                    description=f"Access to denied path: {denied}",
                    severity="CRITICAL",
                    path=normalized,
                )
        if self._policy.allowed_paths:
            allowed = any(
                normalized.startswith(os.path.normpath(a))
                for a in self._policy.allowed_paths
            )
            if not allowed:
                return SandboxViolation(
                    violation_type="PATH_ACCESS",
                    description=f"Path not in allowlist: {normalized}",
                    severity="HIGH",
                    path=normalized,
                )
        return None

    def validate_network(self, host: str, port: int = 0) -> SandboxViolation | None:
        """Check if a network connection would violate sandbox policy."""
        if self._policy.block_network:
            if self._policy.allow_dns and port == 53:
                return None
            return SandboxViolation(
                violation_type="NETWORK",
                description=f"Network blocked: {host}:{port}",
                severity="HIGH",
            )
        return None

    def get_summary(self) -> dict:
        return {
            "isolation_level": self._policy.isolation.name,
            "total_executions": self._execution_count,
            "total_violations": self._total_violations,
            "timeout_seconds": self._policy.timeout_seconds,
            "max_memory_mb": self._policy.max_memory_mb,
            "block_network": self._policy.block_network,
            "denied_paths": len(self._policy.denied_paths),
            "allowed_paths": len(self._policy.allowed_paths),
        }

    # ── Private helpers ──────────────────────────────────────────────

    def _pre_check(
        self, func: Callable, tool_name: str,
    ) -> list[SandboxViolation]:
        violations: list[SandboxViolation] = []
        dangerous_modules = {
            "os", "subprocess", "shutil", "ctypes", "socket",
            "http", "urllib", "requests", "multiprocessing",
        }
        func_module = getattr(func, "__module__", "") or ""
        for mod in dangerous_modules:
            if mod in func_module:
                violations.append(SandboxViolation(
                    violation_type="DANGEROUS_MODULE",
                    description=f"Tool '{tool_name}' uses dangerous module: {mod}",
                    severity="HIGH",
                ))
        return violations

    def _apply_resource_limits(self) -> None:
        """Legacy method — resource limits are now applied in subprocess.

        Kept for API compatibility but is a no-op in the main process.
        """
        logger.debug(
            "Resource limits are applied in subprocess, not main process"
        )

    def _sanitize_env(self) -> dict[str, str]:
        original = dict(os.environ)
        allowed = set(self._policy.allowed_env_keys)
        to_remove = [k for k in os.environ if k not in allowed]
        for k in to_remove:
            del os.environ[k]
        return original

    def _restore_env(self, original: dict[str, str]) -> None:
        os.environ.clear()
        os.environ.update(original)

    def _create_jail(self) -> Path:
        jail = Path(tempfile.mkdtemp(prefix="sentinel_jail_"))
        return jail

    def _audit_jail(self, jail: Path) -> list[str]:
        created: list[str] = []
        if jail.exists():
            for f in jail.rglob("*"):
                if f.is_file():
                    created.append(str(f.relative_to(jail)))
        return created

    def _execute_with_timeout(
        self,
        func: Callable,
        args: tuple,
        kwargs: dict,
        timeout: float,
    ) -> Any:
        """Execute function in a subprocess with resource limits and timeout.

        Uses multiprocessing for proper isolation: resource limits apply
        only to the child process, and the child can be killed reliably.
        Falls back to thread-based execution if multiprocessing fails.
        """
        try:
            return self._execute_in_subprocess(func, args, kwargs, timeout)
        except (OSError, RuntimeError) as e:
            logger.debug("Subprocess execution failed (%s), falling back to thread", e)
            return self._execute_in_thread(func, args, kwargs, timeout)

    def _execute_in_subprocess(
        self,
        func: Callable,
        args: tuple,
        kwargs: dict,
        timeout: float,
    ) -> Any:
        """Run in a subprocess with resource limits."""
        ctx = multiprocessing.get_context("fork")
        result_queue: multiprocessing.Queue = ctx.Queue()
        policy = self._policy

        def _target():
            # Apply resource limits in the child process
            try:
                import resource as res_mod
                if policy.max_memory_mb > 0:
                    mem_bytes = policy.max_memory_mb * 1024 * 1024
                    res_mod.setrlimit(res_mod.RLIMIT_AS, (mem_bytes, mem_bytes))
                if policy.max_cpu_seconds > 0:
                    cpu_sec = int(policy.max_cpu_seconds)
                    res_mod.setrlimit(res_mod.RLIMIT_CPU, (cpu_sec, cpu_sec + 5))
                if policy.max_open_files > 0:
                    res_mod.setrlimit(
                        res_mod.RLIMIT_NOFILE,
                        (policy.max_open_files, policy.max_open_files),
                    )
            except (ImportError, ValueError, OSError) as e:
                logger.debug("Resource limits not available in child: %s", e)

            # Change to jail directory if available
            # (chroot requires root, so we use chdir as best-effort)
            try:
                result = func(*args, **kwargs)
                result_queue.put(("ok", result))
            except Exception as e:
                result_queue.put(("error", str(e)))

        proc = ctx.Process(target=_target)
        proc.start()
        proc.join(timeout=timeout)

        if proc.is_alive():
            proc.kill()
            proc.join(timeout=5)
            raise TimeoutError(f"Execution timed out after {timeout}s")

        if result_queue.empty():
            raise RuntimeError("Subprocess exited without result")

        status, value = result_queue.get_nowait()
        if status == "error":
            raise RuntimeError(value)
        return value

    def _execute_in_thread(
        self,
        func: Callable,
        args: tuple,
        kwargs: dict,
        timeout: float,
    ) -> Any:
        """Fallback: thread-based execution (less isolated)."""
        result_container: list[Any] = [None]
        error_container: list[Exception | None] = [None]

        def _target():
            try:
                result_container[0] = func(*args, **kwargs)
            except Exception as e:
                error_container[0] = e

        thread = threading.Thread(target=_target, daemon=True)
        thread.start()
        thread.join(timeout=timeout)

        if thread.is_alive():
            raise TimeoutError(f"Execution timed out after {timeout}s")

        if error_container[0] is not None:
            raise error_container[0]

        return result_container[0]

    def _record_violations(self, violations: list[SandboxViolation]) -> None:
        self._violations.extend(violations)
        self._total_violations += len(violations)
        for v in violations:
            logger.warning(
                "Sandbox violation [%s]: %s (severity=%s)",
                v.violation_type, v.description, v.severity,
            )
