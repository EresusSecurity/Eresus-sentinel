"""Eresus Sentinel — Honeypot Engine.

Deploy decoy files, endpoints, environment variables, and credentials
to detect unauthorized access by malicious tools or compromised agents.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)


class TrapType(Enum):
    FILE = auto()           # Canary file on disk
    DIRECTORY = auto()      # Canary directory
    ENV_VAR = auto()        # Fake credential in env var
    API_KEY = auto()        # Fake API key planted in config
    ENDPOINT = auto()       # Fake HTTP endpoint marker
    DATABASE_ROW = auto()   # Canary database record
    DNS_RECORD = auto()     # Canary DNS subdomain
    CREDENTIAL = auto()     # Fake credential pair
    SSH_KEY = auto()        # Fake SSH key file
    AWS_KEY = auto()        # Fake AWS access key
    TOKEN = auto()          # Fake bearer/JWT token
    WEBHOOK = auto()        # Endpoint that captures requests


class AlertSeverity(Enum):
    INFO = auto()
    WARNING = auto()
    HIGH = auto()
    CRITICAL = auto()


@dataclass
class HoneypotTrap:
    trap_id: str
    trap_type: TrapType
    location: str
    description: str
    created_at: float = 0.0
    canary_token: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    active: bool = True

    def __post_init__(self):
        if self.created_at == 0.0:
            self.created_at = time.time()
        if not self.canary_token:
            self.canary_token = secrets.token_hex(16)


@dataclass
class HoneypotEvent:
    trap_id: str
    trap_type: TrapType
    event_type: str
    timestamp: float
    severity: AlertSeverity
    description: str
    source_info: dict[str, Any] = field(default_factory=dict)
    canary_token: str = ""

    def to_dict(self) -> dict:
        return {
            "trap_id": self.trap_id,
            "trap_type": self.trap_type.name,
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "severity": self.severity.name,
            "description": self.description,
            "source_info": self.source_info,
            "canary_token": self.canary_token,
        }


class HoneypotEngine:
    """Deploy and monitor honeypot traps for detecting malicious agent behavior.

    Features:
    - Canary files deployed to detect unauthorized file reads
    - Fake credentials planted in environment variables
    - Synthetic API keys that trigger alerts when used
    - Fake SSH keys, AWS keys, database credentials
    - Access monitoring via filesystem polling or inotify
    - Alert callbacks for real-time notification
    - Full audit trail of all trap interactions
    """

    def __init__(
        self,
        trap_dir: str | Path | None = None,
        alert_callback: Callable[[HoneypotEvent], None] | None = None,
    ):
        self._trap_dir = Path(trap_dir) if trap_dir else Path(tempfile.mkdtemp(prefix="sentinel_hp_"))
        self._trap_dir.mkdir(parents=True, exist_ok=True)
        self._alert_callback = alert_callback
        self._traps: dict[str, HoneypotTrap] = {}
        self._events: list[HoneypotEvent] = []
        self._file_checksums: dict[str, str] = {}

    @property
    def trap_count(self) -> int:
        return len(self._traps)

    @property
    def event_count(self) -> int:
        return len(self._events)

    @property
    def active_traps(self) -> list[HoneypotTrap]:
        return [t for t in self._traps.values() if t.active]

    # ── Trap deployment ──────────────────────────────────────────────

    def deploy_canary_file(
        self,
        filename: str = ".env.backup",
        content: str | None = None,
        directory: str | Path | None = None,
    ) -> HoneypotTrap:
        """Deploy a canary file that triggers alerts when read."""
        target_dir = Path(directory) if directory else self._trap_dir
        target_dir.mkdir(parents=True, exist_ok=True)
        filepath = target_dir / filename

        if content is None:
            token = secrets.token_hex(16)
            content = self._generate_fake_env_content(token)
        else:
            token = secrets.token_hex(16)

        filepath.write_text(content, encoding="utf-8")
        checksum = hashlib.sha256(content.encode()).hexdigest()
        self._file_checksums[str(filepath)] = checksum

        trap = HoneypotTrap(
            trap_id=f"file_{secrets.token_hex(8)}",
            trap_type=TrapType.FILE,
            location=str(filepath),
            description=f"Canary file: {filename}",
            canary_token=token,
            metadata={"checksum": checksum, "size": len(content)},
        )
        self._traps[trap.trap_id] = trap
        logger.info("Deployed canary file: %s", filepath)
        return trap

    def deploy_canary_credentials(self) -> list[HoneypotTrap]:
        """Deploy multiple fake credential traps."""
        traps: list[HoneypotTrap] = []

        cred_files = {
            ".aws/credentials": self._generate_fake_aws_credentials,
            ".ssh/id_rsa": self._generate_fake_ssh_key,
            ".docker/config.json": self._generate_fake_docker_config,
            ".kube/config": self._generate_fake_kube_config,
            ".npmrc": self._generate_fake_npmrc,
            ".pypirc": self._generate_fake_pypirc,
            ".git-credentials": self._generate_fake_git_credentials,
            ".netrc": self._generate_fake_netrc,
        }

        for rel_path, generator in cred_files.items():
            dirpath = self._trap_dir / Path(rel_path).parent
            dirpath.mkdir(parents=True, exist_ok=True)
            filepath = self._trap_dir / rel_path
            content, token = generator()
            filepath.write_text(content, encoding="utf-8")
            checksum = hashlib.sha256(content.encode()).hexdigest()
            self._file_checksums[str(filepath)] = checksum

            trap = HoneypotTrap(
                trap_id=f"cred_{secrets.token_hex(8)}",
                trap_type=TrapType.CREDENTIAL,
                location=str(filepath),
                description=f"Fake credential: {rel_path}",
                canary_token=token,
                metadata={"checksum": checksum, "credential_type": rel_path},
            )
            self._traps[trap.trap_id] = trap
            traps.append(trap)

        logger.info("Deployed %d credential traps", len(traps))
        return traps

    def deploy_env_trap(
        self,
        key: str = "DATABASE_URL",
        value: str | None = None,
    ) -> HoneypotTrap:
        """Plant a fake credential in an environment variable."""
        token = secrets.token_hex(16)
        if value is None:
            value = f"postgresql://admin:sentinel_canary_{token}@honeypot.internal:5432/production"

        os.environ[key] = value

        trap = HoneypotTrap(
            trap_id=f"env_{secrets.token_hex(8)}",
            trap_type=TrapType.ENV_VAR,
            location=f"${{env.{key}}}",
            description=f"Fake env credential: {key}",
            canary_token=token,
            metadata={"env_key": key},
        )
        self._traps[trap.trap_id] = trap
        logger.info("Deployed env trap: %s", key)
        return trap

    def deploy_api_key_trap(
        self,
        service: str = "openai",
    ) -> HoneypotTrap:
        """Deploy a fake API key canary token."""
        token = secrets.token_hex(16)
        fake_keys = {
            "openai": f"sk-sentinel{token[:32]}canary",
            "anthropic": f"sk-ant-sentinel{token[:28]}canary",
            "aws": f"AKIA{token[:16].upper()}CANARY",
            "stripe": f"sk_live_sentinel_{token[:24]}",
            "github": f"ghp_sentinel{token[:24]}Canary",
            "sendgrid": f"SG.sentinel.{token[:32]}",
            "slack": f"xoxb-sentinel-{token[:20]}-canary",
        }
        fake_key = fake_keys.get(service, f"{service}_sentinel_{token}")

        trap = HoneypotTrap(
            trap_id=f"apikey_{secrets.token_hex(8)}",
            trap_type=TrapType.API_KEY,
            location=f"api_key:{service}",
            description=f"Fake {service} API key",
            canary_token=token,
            metadata={"service": service, "fake_key": fake_key},
        )
        self._traps[trap.trap_id] = trap
        logger.info("Deployed API key trap for %s", service)
        return trap

    def deploy_full_honeypot(self) -> list[HoneypotTrap]:
        """Deploy a comprehensive honeypot with all trap types."""
        traps: list[HoneypotTrap] = []

        traps.append(self.deploy_canary_file(".env.backup"))
        traps.append(self.deploy_canary_file(".env.production"))
        traps.append(self.deploy_canary_file("secrets.yaml"))
        traps.append(self.deploy_canary_file("config/database.yml"))
        traps.extend(self.deploy_canary_credentials())
        traps.append(self.deploy_env_trap("DATABASE_URL"))
        traps.append(self.deploy_env_trap("REDIS_URL"))
        traps.append(self.deploy_env_trap("SECRET_KEY"))
        traps.append(self.deploy_api_key_trap("openai"))
        traps.append(self.deploy_api_key_trap("aws"))
        traps.append(self.deploy_api_key_trap("stripe"))
        traps.append(self.deploy_api_key_trap("github"))

        logger.info("Full honeypot deployed: %d traps active", len(traps))
        return traps

    # ── Monitoring & detection ───────────────────────────────────────

    def check_file_traps(self) -> list[HoneypotEvent]:
        """Poll file-based traps for access/modification."""
        events: list[HoneypotEvent] = []

        for trap in self._traps.values():
            if not trap.active:
                continue
            if trap.trap_type not in (TrapType.FILE, TrapType.CREDENTIAL):
                continue

            filepath = Path(trap.location)
            if not filepath.exists():
                event = HoneypotEvent(
                    trap_id=trap.trap_id,
                    trap_type=trap.trap_type,
                    event_type="FILE_DELETED",
                    timestamp=time.time(),
                    severity=AlertSeverity.CRITICAL,
                    description=f"Canary file deleted: {filepath}",
                    canary_token=trap.canary_token,
                )
                events.append(event)
                continue

            stat = filepath.stat()
            stored_checksum = self._file_checksums.get(str(filepath), "")
            if stored_checksum:
                current = hashlib.sha256(
                    filepath.read_bytes()
                ).hexdigest()
                if current != stored_checksum:
                    event = HoneypotEvent(
                        trap_id=trap.trap_id,
                        trap_type=trap.trap_type,
                        event_type="FILE_MODIFIED",
                        timestamp=time.time(),
                        severity=AlertSeverity.CRITICAL,
                        description=f"Canary file modified: {filepath}",
                        source_info={"stat_mtime": stat.st_mtime},
                        canary_token=trap.canary_token,
                    )
                    events.append(event)

            atime = stat.st_atime
            mtime = stat.st_mtime
            if atime > trap.created_at and atime > mtime:
                event = HoneypotEvent(
                    trap_id=trap.trap_id,
                    trap_type=trap.trap_type,
                    event_type="FILE_READ",
                    timestamp=time.time(),
                    severity=AlertSeverity.HIGH,
                    description=f"Canary file accessed: {filepath}",
                    source_info={"atime": atime, "mtime": mtime},
                    canary_token=trap.canary_token,
                )
                events.append(event)

        for evt in events:
            self._events.append(evt)
            if self._alert_callback:
                self._alert_callback(evt)

        return events

    def check_token_usage(self, text: str) -> list[HoneypotEvent]:
        """Scan text for canary tokens being used (exfiltrated)."""
        events: list[HoneypotEvent] = []

        for trap in self._traps.values():
            if not trap.active:
                continue
            if trap.canary_token in text:
                event = HoneypotEvent(
                    trap_id=trap.trap_id,
                    trap_type=trap.trap_type,
                    event_type="TOKEN_EXFILTRATED",
                    timestamp=time.time(),
                    severity=AlertSeverity.CRITICAL,
                    description=f"Canary token found in output: {trap.description}",
                    canary_token=trap.canary_token,
                )
                events.append(event)
                self._events.append(event)

            if trap.trap_type == TrapType.API_KEY:
                fake_key = trap.metadata.get("fake_key", "")
                if fake_key and fake_key in text:
                    event = HoneypotEvent(
                        trap_id=trap.trap_id,
                        trap_type=trap.trap_type,
                        event_type="API_KEY_USED",
                        timestamp=time.time(),
                        severity=AlertSeverity.CRITICAL,
                        description=f"Fake API key detected in output: {trap.description}",
                        canary_token=trap.canary_token,
                    )
                    events.append(event)
                    self._events.append(event)

        if events and self._alert_callback:
            for evt in events:
                self._alert_callback(evt)

        return events

    def deactivate_trap(self, trap_id: str) -> bool:
        trap = self._traps.get(trap_id)
        if trap:
            trap.active = False
            return True
        return False

    def cleanup(self) -> int:
        """Remove all deployed traps and clean up artifacts."""
        count = 0
        for trap in self._traps.values():
            if trap.trap_type in (TrapType.FILE, TrapType.CREDENTIAL):
                try:
                    Path(trap.location).unlink(missing_ok=True)
                    count += 1
                except OSError:
                    pass
            elif trap.trap_type == TrapType.ENV_VAR:
                key = trap.metadata.get("env_key", "")
                if key and key in os.environ:
                    del os.environ[key]
                    count += 1
            trap.active = False
        logger.info("Cleaned up %d traps", count)
        return count

    def get_events(
        self,
        severity: AlertSeverity | None = None,
        trap_type: TrapType | None = None,
    ) -> list[HoneypotEvent]:
        events = self._events
        if severity:
            events = [e for e in events if e.severity == severity]
        if trap_type:
            events = [e for e in events if e.trap_type == trap_type]
        return events

    def get_summary(self) -> dict:
        severity_counts = {}
        for e in self._events:
            severity_counts[e.severity.name] = severity_counts.get(e.severity.name, 0) + 1
        return {
            "total_traps": len(self._traps),
            "active_traps": len(self.active_traps),
            "total_events": len(self._events),
            "severity_distribution": severity_counts,
            "trap_types": {
                t.name: len([tr for tr in self._traps.values() if tr.trap_type == t])
                for t in TrapType
                if any(tr.trap_type == t for tr in self._traps.values())
            },
        }

    # ── Fake credential generators ───────────────────────────────────

    def _generate_fake_env_content(self, token: str) -> str:
        return (
            f"# Production environment — DO NOT COMMIT\n"
            f"DATABASE_URL=postgresql://admin:canary_{token[:16]}@db.internal:5432/prod\n"
            f"REDIS_URL=redis://default:canary_{token[16:]}@redis.internal:6379/0\n"
            f"SECRET_KEY={secrets.token_hex(32)}\n"
            f"AWS_ACCESS_KEY_ID=AKIA{''.join(secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(16))}\n"
            f"AWS_SECRET_ACCESS_KEY={secrets.token_hex(20)}\n"
            f"OPENAI_API_KEY=sk-canary{token}\n"
            f"STRIPE_SECRET_KEY=sk_live_canary_{secrets.token_hex(12)}\n"
        )

    def _generate_fake_aws_credentials(self) -> tuple[str, str]:
        token = secrets.token_hex(16)
        content = (
            f"[default]\n"
            f"aws_access_key_id = AKIA{''.join(secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(16))}\n"
            f"aws_secret_access_key = canary/{token}/{secrets.token_hex(20)}\n"
            f"region = us-east-1\n"
        )
        return content, token

    def _generate_fake_ssh_key(self) -> tuple[str, str]:
        token = secrets.token_hex(16)
        content = (
            f"-----BEGIN OPENSSH PRIVATE KEY-----\n"
            f"canary-sentinel-{token}-this-is-a-honeypot-key\n"
            f"{secrets.token_hex(64)}\n"
            f"{secrets.token_hex(64)}\n"
            f"{secrets.token_hex(64)}\n"
            f"-----END OPENSSH PRIVATE KEY-----\n"
        )
        return content, token

    def _generate_fake_docker_config(self) -> tuple[str, str]:
        token = secrets.token_hex(16)
        content = json.dumps({
            "auths": {
                "registry.internal:5000": {
                    "auth": f"canary:{token}",
                    "email": "admin@canary.internal",
                },
                "ghcr.io": {
                    "auth": f"sentinel:{secrets.token_hex(20)}",
                },
            },
        }, indent=2)
        return content, token

    def _generate_fake_kube_config(self) -> tuple[str, str]:
        token = secrets.token_hex(16)
        content = (
            f"apiVersion: v1\n"
            f"kind: Config\n"
            f"clusters:\n"
            f"- cluster:\n"
            f"    server: https://k8s.canary.internal:6443\n"
            f"    certificate-authority-data: canary-{token}\n"
            f"  name: prod-cluster\n"
            f"users:\n"
            f"- name: admin\n"
            f"  user:\n"
            f"    token: canary-bearer-{token}\n"
        )
        return content, token

    def _generate_fake_npmrc(self) -> tuple[str, str]:
        token = secrets.token_hex(16)
        content = (
            f"//registry.npmjs.org/:_authToken=npm_canary{token}\n"
            f"//npm.pkg.github.com/:_authToken=ghp_canary{secrets.token_hex(18)}\n"
        )
        return content, token

    def _generate_fake_pypirc(self) -> tuple[str, str]:
        token = secrets.token_hex(16)
        content = (
            f"[distutils]\nindex-servers = pypi\n\n"
            f"[pypi]\nusername = __token__\n"
            f"password = pypi-canary-{token}-sentinel\n"
        )
        return content, token

    def _generate_fake_git_credentials(self) -> tuple[str, str]:
        token = secrets.token_hex(16)
        content = (
            f"https://canary:{token}@github.com\n"
            f"https://sentinel:{secrets.token_hex(20)}@gitlab.com\n"
        )
        return content, token

    def _generate_fake_netrc(self) -> tuple[str, str]:
        token = secrets.token_hex(16)
        content = (
            f"machine github.com\n  login canary\n  password {token}\n"
            f"machine gitlab.com\n  login sentinel\n  password {secrets.token_hex(20)}\n"
        )
        return content, token
