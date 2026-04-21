"""Eresus Sentinel — Syscall Filter & Security Profiles.

Generate seccomp BPF profiles and AppArmor policy fragments
for sandboxing tool execution at the OS level.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

logger = logging.getLogger(__name__)


class SeccompAction(Enum):
    ALLOW = "SCMP_ACT_ALLOW"
    KILL = "SCMP_ACT_KILL"
    KILL_PROCESS = "SCMP_ACT_KILL_PROCESS"
    TRAP = "SCMP_ACT_TRAP"
    ERRNO = "SCMP_ACT_ERRNO"
    LOG = "SCMP_ACT_LOG"


class ProfileType(Enum):
    MINIMAL = auto()       # Read-only, no network, no exec
    NETWORK_CLIENT = auto()  # Outbound TCP only, no listen
    FILE_PROCESSOR = auto()  # Read/write files, no network
    COMPUTE_ONLY = auto()    # CPU-bound, no I/O beyond stdio
    FULL_TOOL = auto()       # Most syscalls allowed, dangerous ones blocked
    CUSTOM = auto()


@dataclass
class SyscallRule:
    name: str
    action: SeccompAction = SeccompAction.ERRNO
    errno_value: int = 1  # EPERM
    args: list[dict[str, Any]] = field(default_factory=list)
    comment: str = ""


@dataclass
class SyscallProfile:
    profile_type: ProfileType
    name: str = ""
    description: str = ""
    default_action: SeccompAction = SeccompAction.ERRNO
    allowed_syscalls: list[str] = field(default_factory=list)
    denied_syscalls: list[str] = field(default_factory=list)
    custom_rules: list[SyscallRule] = field(default_factory=list)
    architectures: list[str] = field(default_factory=lambda: ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# BUILTIN PROFILES
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_BASE_ALLOWED = [
    "read", "write", "close", "fstat", "lstat", "stat", "lseek",
    "mmap", "mprotect", "munmap", "brk", "rt_sigaction", "rt_sigprocmask",
    "ioctl", "access", "pipe", "select", "sched_yield", "mremap",
    "msync", "mincore", "madvise", "dup", "dup2", "nanosleep",
    "getpid", "getuid", "getgid", "geteuid", "getegid", "getppid",
    "getpgrp", "getgroups", "getresuid", "getresgid",
    "clock_gettime", "clock_getres", "clock_nanosleep",
    "exit", "exit_group", "futex", "set_robust_list",
    "get_robust_list", "set_tid_address", "arch_prctl",
    "getrandom", "pread64", "pwrite64", "readv", "writev",
    "newfstatat", "openat", "fcntl", "getdents64",
    "poll", "ppoll", "epoll_create1", "epoll_ctl", "epoll_wait",
    "eventfd2", "signalfd4", "timerfd_create", "timerfd_settime",
]

_NETWORK_SYSCALLS = [
    "socket", "connect", "sendto", "recvfrom", "sendmsg", "recvmsg",
    "bind", "listen", "accept", "accept4", "getsockname", "getpeername",
    "setsockopt", "getsockopt", "shutdown",
]

_EXEC_SYSCALLS = [
    "execve", "execveat", "fork", "vfork", "clone", "clone3", "wait4", "waitid",
]

_DANGEROUS_SYSCALLS = [
    "ptrace", "mount", "umount2", "reboot", "swapon", "swapoff",
    "init_module", "finit_module", "delete_module", "kexec_load",
    "pivot_root", "chroot", "setns", "unshare",
    "keyctl", "request_key", "add_key",
    "kcmp", "bpf", "userfaultfd",
    "perf_event_open", "lookup_dcookie",
    "move_mount", "fsopen", "fsconfig", "fsmount",
    "open_tree", "mount_setattr",
    "io_uring_setup", "io_uring_enter", "io_uring_register",
]

_FILE_WRITE_SYSCALLS = [
    "openat", "open", "creat", "rename", "renameat", "renameat2",
    "mkdir", "mkdirat", "rmdir", "unlink", "unlinkat",
    "symlink", "symlinkat", "link", "linkat",
    "chmod", "fchmod", "fchmodat", "chown", "fchown", "fchownat",
    "truncate", "ftruncate", "fallocate",
]


BUILTIN_PROFILES: dict[ProfileType, SyscallProfile] = {
    ProfileType.MINIMAL: SyscallProfile(
        profile_type=ProfileType.MINIMAL,
        name="minimal",
        description="Read-only, no network, no exec — maximum isolation",
        default_action=SeccompAction.ERRNO,
        allowed_syscalls=_BASE_ALLOWED,
        denied_syscalls=_DANGEROUS_SYSCALLS + _NETWORK_SYSCALLS + _EXEC_SYSCALLS,
    ),
    ProfileType.NETWORK_CLIENT: SyscallProfile(
        profile_type=ProfileType.NETWORK_CLIENT,
        name="network_client",
        description="Outbound TCP only — blocks listen/accept/bind",
        default_action=SeccompAction.ERRNO,
        allowed_syscalls=_BASE_ALLOWED + ["socket", "connect", "sendto", "recvfrom", "sendmsg", "recvmsg", "getsockname", "getpeername", "setsockopt", "getsockopt", "shutdown"],
        denied_syscalls=_DANGEROUS_SYSCALLS + _EXEC_SYSCALLS + ["bind", "listen", "accept", "accept4"],
    ),
    ProfileType.FILE_PROCESSOR: SyscallProfile(
        profile_type=ProfileType.FILE_PROCESSOR,
        name="file_processor",
        description="File read/write allowed — no network, no exec",
        default_action=SeccompAction.ERRNO,
        allowed_syscalls=_BASE_ALLOWED + _FILE_WRITE_SYSCALLS,
        denied_syscalls=_DANGEROUS_SYSCALLS + _NETWORK_SYSCALLS + _EXEC_SYSCALLS,
    ),
    ProfileType.COMPUTE_ONLY: SyscallProfile(
        profile_type=ProfileType.COMPUTE_ONLY,
        name="compute_only",
        description="CPU-bound only — no file writes, no network, no exec",
        default_action=SeccompAction.ERRNO,
        allowed_syscalls=_BASE_ALLOWED,
        denied_syscalls=_DANGEROUS_SYSCALLS + _NETWORK_SYSCALLS + _EXEC_SYSCALLS + _FILE_WRITE_SYSCALLS,
    ),
    ProfileType.FULL_TOOL: SyscallProfile(
        profile_type=ProfileType.FULL_TOOL,
        name="full_tool",
        description="Most operations allowed — only kernel-level abuse blocked",
        default_action=SeccompAction.ALLOW,
        allowed_syscalls=[],
        denied_syscalls=_DANGEROUS_SYSCALLS,
    ),
}


class SyscallFilter:
    """Generate seccomp BPF and AppArmor profiles for tool sandboxing.

    Features:
    - Pre-built profiles (MINIMAL, NETWORK_CLIENT, FILE_PROCESSOR, COMPUTE_ONLY, FULL_TOOL)
    - Custom profile composition
    - OCI/Docker seccomp JSON export
    - AppArmor policy fragment generation
    - Profile validation and audit
    """

    def __init__(self, profile: SyscallProfile | ProfileType | None = None):
        if isinstance(profile, ProfileType):
            self._profile = BUILTIN_PROFILES[profile]
        elif isinstance(profile, SyscallProfile):
            self._profile = profile
        else:
            self._profile = BUILTIN_PROFILES[ProfileType.FULL_TOOL]

    @property
    def profile(self) -> SyscallProfile:
        return self._profile

    @classmethod
    def from_profile_name(cls, name: str) -> SyscallFilter:
        for _pt, prof in BUILTIN_PROFILES.items():
            if prof.name == name:
                return cls(prof)
        raise ValueError(f"Unknown profile: {name}. Available: {[p.name for p in BUILTIN_PROFILES.values()]}")

    def export_seccomp_json(self) -> str:
        """Export as OCI/Docker-compatible seccomp JSON profile."""
        profile: dict[str, Any] = {
            "defaultAction": self._profile.default_action.value,
            "architectures": self._profile.architectures,
            "syscalls": [],
        }

        if self._profile.allowed_syscalls:
            profile["syscalls"].append({
                "names": self._profile.allowed_syscalls,
                "action": SeccompAction.ALLOW.value,
            })

        if self._profile.denied_syscalls:
            profile["syscalls"].append({
                "names": self._profile.denied_syscalls,
                "action": SeccompAction.ERRNO.value,
                "errnoRet": 1,
            })

        for rule in self._profile.custom_rules:
            entry: dict[str, Any] = {
                "names": [rule.name],
                "action": rule.action.value,
            }
            if rule.action == SeccompAction.ERRNO:
                entry["errnoRet"] = rule.errno_value
            if rule.args:
                entry["args"] = rule.args
            profile["syscalls"].append(entry)

        return json.dumps(profile, indent=2)

    def export_apparmor(self, binary_path: str = "/usr/bin/python3") -> str:
        """Generate an AppArmor profile fragment."""
        lines = [
            f"# AppArmor profile generated by Eresus Sentinel",
            f"# Profile: {self._profile.name} ({self._profile.description})",
            f"",
            f"profile sentinel_sandbox {binary_path} flags=(enforce) {{",
            f"  #include <abstractions/base>",
            f"  #include <abstractions/python>",
            f"",
        ]

        if self._profile.profile_type == ProfileType.MINIMAL:
            lines.extend([
                "  # Deny all network access",
                "  deny network,",
                "",
                "  # Read-only filesystem",
                "  / r,",
                "  /usr/** r,",
                "  /lib/** r,",
                "  /tmp/** rw,",
                "",
                "  # Deny dangerous operations",
                "  deny /proc/*/mem rw,",
                "  deny /sys/** w,",
                "  deny /dev/** rw,",
                "  deny mount,",
                "  deny ptrace,",
            ])
        elif self._profile.profile_type == ProfileType.NETWORK_CLIENT:
            lines.extend([
                "  # Outbound network only",
                "  network tcp,",
                "  deny network raw,",
                "  deny network udp,",
                "",
                "  / r,",
                "  /usr/** r,",
                "  /lib/** r,",
                "  /tmp/** rw,",
            ])
        elif self._profile.profile_type == ProfileType.FILE_PROCESSOR:
            lines.extend([
                "  # Deny all network",
                "  deny network,",
                "",
                "  # File access",
                "  / r,",
                "  /usr/** r,",
                "  /lib/** r,",
                "  /tmp/** rw,",
                "  owner /home/*/** rw,",
            ])
        elif self._profile.profile_type == ProfileType.COMPUTE_ONLY:
            lines.extend([
                "  deny network,",
                "  / r,",
                "  /usr/** r,",
                "  /lib/** r,",
                "  deny /tmp/** w,",
            ])
        else:
            lines.extend([
                "  # Full tool access — restricted dangerous ops only",
                "  / r,",
                "  /usr/** rx,",
                "  /lib/** r,",
                "  /tmp/** rw,",
                "  owner /home/*/** rw,",
                "  network tcp,",
                "  network udp,",
                "",
                "  # Block kernel abuse",
                "  deny mount,",
                "  deny ptrace,",
                "  deny /proc/*/mem rw,",
                "  deny /sys/kernel/** w,",
            ])

        lines.extend(["", "}", ""])
        return "\n".join(lines)

    def validate_syscall(self, syscall_name: str) -> tuple[bool, str]:
        """Check if a syscall would be allowed under the current profile."""
        if syscall_name in self._profile.denied_syscalls:
            return False, f"Syscall '{syscall_name}' is explicitly denied"

        for rule in self._profile.custom_rules:
            if rule.name == syscall_name and rule.action in (SeccompAction.KILL, SeccompAction.ERRNO):
                return False, f"Syscall '{syscall_name}' blocked by custom rule: {rule.comment}"

        if self._profile.default_action == SeccompAction.ERRNO:
            if syscall_name not in self._profile.allowed_syscalls:
                return False, f"Syscall '{syscall_name}' not in allowlist (default: deny)"

        return True, "allowed"

    def get_summary(self) -> dict:
        return {
            "profile": self._profile.name,
            "type": self._profile.profile_type.name,
            "description": self._profile.description,
            "default_action": self._profile.default_action.value,
            "allowed_count": len(self._profile.allowed_syscalls),
            "denied_count": len(self._profile.denied_syscalls),
            "custom_rules": len(self._profile.custom_rules),
            "architectures": self._profile.architectures,
        }
