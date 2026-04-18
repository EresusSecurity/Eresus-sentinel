"""Eresus Sentinel — Telemetry & Observability Pipeline.

Full export pipeline for Prometheus, OpenTelemetry, webhook alerting,
and dashboard-ready metrics. Extends the core MetricsCollector.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class AlertChannel(Enum):
    WEBHOOK = auto()
    SLACK = auto()
    PAGERDUTY = auto()
    OPSGENIE = auto()
    TEAMS = auto()
    EMAIL = auto()
    LOG = auto()


class AlertSeverity(Enum):
    INFO = auto()
    WARNING = auto()
    ERROR = auto()
    CRITICAL = auto()


@dataclass
class AlertRule:
    name: str
    condition: str             # "latency_avg > 5.0" | "block_rate > 0.5" | "critical_count > 10"
    severity: AlertSeverity = AlertSeverity.WARNING
    channels: list[AlertChannel] = field(default_factory=lambda: [AlertChannel.LOG])
    cooldown_seconds: float = 300.0
    description: str = ""
    last_fired: float = 0.0
    fire_count: int = 0


@dataclass
class Alert:
    rule_name: str
    severity: AlertSeverity
    message: str
    timestamp: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)
    acknowledged: bool = False

    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time.time()

    def to_dict(self) -> dict:
        return {
            "rule": self.rule_name,
            "severity": self.severity.name,
            "message": self.message,
            "timestamp": self.timestamp,
            "details": self.details,
            "acknowledged": self.acknowledged,
        }


@dataclass
class WebhookConfig:
    url: str
    method: str = "POST"
    headers: dict[str, str] = field(default_factory=lambda: {"Content-Type": "application/json"})
    timeout_seconds: float = 10.0
    retry_count: int = 2


@dataclass
class SlackConfig:
    webhook_url: str
    channel: str = "#sentinel-alerts"
    username: str = "Sentinel Bot"
    icon_emoji: str = ":shield:"


@dataclass
class PagerDutyConfig:
    integration_key: str
    severity_map: dict[str, str] = field(default_factory=lambda: {
        "INFO": "info",
        "WARNING": "warning",
        "ERROR": "error",
        "CRITICAL": "critical",
    })


class TelemetryPipeline:
    """Full observability pipeline with export and alerting.

    Features:
    - OTLP/gRPC trace and metric export (if opentelemetry installed)
    - Webhook-based alerting (generic, Slack, PagerDuty, OpsGenie, Teams)
    - Configurable alert rules with cooldowns
    - Prometheus push gateway support
    - Dashboard-ready JSON metrics snapshots
    - Alert history and audit trail
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._alert_rules: list[AlertRule] = []
        self._alert_history: list[Alert] = []
        self._webhook_configs: dict[str, WebhookConfig] = {}
        self._slack_config: Optional[SlackConfig] = None
        self._pagerduty_config: Optional[PagerDutyConfig] = None
        self._custom_handlers: dict[AlertChannel, Callable[[Alert], None]] = {}
        self._otel_initialized = False

    # ── Alert rule management ────────────────────────────────────────

    def add_alert_rule(self, rule: AlertRule) -> None:
        self._alert_rules.append(rule)

    def add_default_rules(self) -> None:
        self._alert_rules.extend([
            AlertRule(
                name="high_latency",
                condition="latency_avg > 5.0",
                severity=AlertSeverity.WARNING,
                description="Average scan latency exceeds 5 seconds",
            ),
            AlertRule(
                name="excessive_blocks",
                condition="block_rate > 0.5",
                severity=AlertSeverity.ERROR,
                description="More than 50% of requests are being blocked",
            ),
            AlertRule(
                name="critical_findings",
                condition="critical_count > 0",
                severity=AlertSeverity.CRITICAL,
                description="Critical security findings detected",
            ),
            AlertRule(
                name="scan_errors",
                condition="error_rate > 0.1",
                severity=AlertSeverity.ERROR,
                description="Scanner error rate exceeds 10%",
            ),
            AlertRule(
                name="honeypot_triggered",
                condition="honeypot_events > 0",
                severity=AlertSeverity.CRITICAL,
                description="Honeypot trap has been triggered",
            ),
            AlertRule(
                name="sandbox_violation",
                condition="sandbox_violations > 0",
                severity=AlertSeverity.CRITICAL,
                description="Sandbox security violation detected",
            ),
        ])

    # ── Channel configuration ────────────────────────────────────────

    def configure_webhook(self, name: str, config: WebhookConfig) -> None:
        self._webhook_configs[name] = config

    def configure_slack(self, config: SlackConfig) -> None:
        self._slack_config = config

    def configure_pagerduty(self, config: PagerDutyConfig) -> None:
        self._pagerduty_config = config

    def register_handler(self, channel: AlertChannel, handler: Callable[[Alert], None]) -> None:
        self._custom_handlers[channel] = handler

    # ── Alert evaluation ─────────────────────────────────────────────

    def evaluate_rules(self, metrics_snapshot: dict) -> list[Alert]:
        """Evaluate all alert rules against a metrics snapshot."""
        fired: list[Alert] = []
        now = time.time()

        for rule in self._alert_rules:
            if now - rule.last_fired < rule.cooldown_seconds:
                continue

            triggered = self._evaluate_condition(rule.condition, metrics_snapshot)
            if triggered:
                alert = Alert(
                    rule_name=rule.name,
                    severity=rule.severity,
                    message=rule.description or f"Alert: {rule.name}",
                    details={"condition": rule.condition, "snapshot": metrics_snapshot},
                )
                rule.last_fired = now
                rule.fire_count += 1
                fired.append(alert)
                self._alert_history.append(alert)

                self._dispatch_alert(alert, rule.channels)

        return fired

    def _evaluate_condition(self, condition: str, snapshot: dict) -> bool:
        """Evaluate a simple condition string against metrics."""
        try:
            parts = condition.split()
            if len(parts) != 3:
                return False
            metric_name, operator, threshold = parts
            value = self._resolve_metric(metric_name, snapshot)
            threshold_val = float(threshold)

            if operator == ">":
                return value > threshold_val
            elif operator == "<":
                return value < threshold_val
            elif operator == ">=":
                return value >= threshold_val
            elif operator == "<=":
                return value <= threshold_val
            elif operator == "==":
                return value == threshold_val
            return False
        except (ValueError, KeyError):
            return False

    def _resolve_metric(self, name: str, snapshot: dict) -> float:
        """Resolve a metric name to its value from a snapshot."""
        if name in snapshot:
            return float(snapshot[name])
        for section in snapshot.values():
            if isinstance(section, dict) and name in section:
                return float(section[name])
        return 0.0

    # ── Alert dispatch ───────────────────────────────────────────────

    def _dispatch_alert(self, alert: Alert, channels: list[AlertChannel]) -> None:
        for channel in channels:
            try:
                if channel == AlertChannel.LOG:
                    self._dispatch_log(alert)
                elif channel == AlertChannel.WEBHOOK:
                    self._dispatch_webhook(alert)
                elif channel == AlertChannel.SLACK:
                    self._dispatch_slack(alert)
                elif channel == AlertChannel.PAGERDUTY:
                    self._dispatch_pagerduty(alert)
                elif channel in self._custom_handlers:
                    self._custom_handlers[channel](alert)
                else:
                    logger.warning("No handler for channel: %s", channel.name)
            except Exception as e:
                logger.error("Failed to dispatch alert via %s: %s", channel.name, e)

    def _dispatch_log(self, alert: Alert) -> None:
        log_func = {
            AlertSeverity.INFO: logger.info,
            AlertSeverity.WARNING: logger.warning,
            AlertSeverity.ERROR: logger.error,
            AlertSeverity.CRITICAL: logger.critical,
        }.get(alert.severity, logger.warning)
        log_func("ALERT [%s] %s: %s", alert.severity.name, alert.rule_name, alert.message)

    def _dispatch_webhook(self, alert: Alert) -> None:
        payload = json.dumps(alert.to_dict()).encode("utf-8")
        for name, config in self._webhook_configs.items():
            try:
                req = urllib.request.Request(
                    config.url,
                    data=payload,
                    headers=config.headers,
                    method=config.method,
                )
                urllib.request.urlopen(req, timeout=config.timeout_seconds)
                logger.info("Webhook '%s' sent successfully", name)
            except Exception as e:
                logger.error("Webhook '%s' failed: %s", name, e)

    def _dispatch_slack(self, alert: Alert) -> None:
        if not self._slack_config:
            return

        severity_emoji = {
            AlertSeverity.INFO: ":information_source:",
            AlertSeverity.WARNING: ":warning:",
            AlertSeverity.ERROR: ":x:",
            AlertSeverity.CRITICAL: ":rotating_light:",
        }

        payload = json.dumps({
            "channel": self._slack_config.channel,
            "username": self._slack_config.username,
            "icon_emoji": self._slack_config.icon_emoji,
            "text": f"{severity_emoji.get(alert.severity, ':bell:')} *Sentinel Alert*\n"
                    f"*Rule:* {alert.rule_name}\n"
                    f"*Severity:* {alert.severity.name}\n"
                    f"*Message:* {alert.message}",
        }).encode("utf-8")

        try:
            req = urllib.request.Request(
                self._slack_config.webhook_url,
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=10)
        except Exception as e:
            logger.error("Slack dispatch failed: %s", e)

    def _dispatch_pagerduty(self, alert: Alert) -> None:
        if not self._pagerduty_config:
            return

        pd_severity = self._pagerduty_config.severity_map.get(
            alert.severity.name, "warning"
        )

        payload = json.dumps({
            "routing_key": self._pagerduty_config.integration_key,
            "event_action": "trigger",
            "payload": {
                "summary": f"[Sentinel] {alert.rule_name}: {alert.message}",
                "source": "eresus-sentinel",
                "severity": pd_severity,
                "custom_details": alert.details,
            },
        }).encode("utf-8")

        try:
            req = urllib.request.Request(
                "https://events.pagerduty.com/v2/enqueue",
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=10)
        except Exception as e:
            logger.error("PagerDuty dispatch failed: %s", e)

    # ── OTLP / OpenTelemetry ─────────────────────────────────────────

    def init_otel(
        self,
        service_name: str = "eresus-sentinel",
        otlp_endpoint: str = "http://localhost:4317",
    ) -> bool:
        """Initialize OpenTelemetry with OTLP exporter."""
        try:
            from opentelemetry import metrics as otel_metrics
            from opentelemetry import trace as otel_trace
            from opentelemetry.sdk.metrics import MeterProvider
            from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

            resource = Resource.create({"service.name": service_name})

            # Traces
            tracer_provider = TracerProvider(resource=resource)
            tracer_provider.add_span_processor(
                otel_trace.SpanProcessor(OTLPSpanExporter(endpoint=otlp_endpoint))  # type: ignore
            )
            otel_trace.set_tracer_provider(tracer_provider)

            # Metrics
            metric_exporter = OTLPMetricExporter(endpoint=otlp_endpoint)
            reader = PeriodicExportingMetricReader(metric_exporter, export_interval_millis=10000)
            meter_provider = MeterProvider(resource=resource, metric_readers=[reader])
            otel_metrics.set_meter_provider(meter_provider)

            self._otel_initialized = True
            logger.info("OpenTelemetry initialized: endpoint=%s", otlp_endpoint)
            return True

        except ImportError as e:
            logger.info("OpenTelemetry packages not available: %s", e)
            return False
        except Exception as e:
            logger.error("OpenTelemetry init failed: %s", e)
            return False

    # ── Prometheus push gateway ──────────────────────────────────────

    def push_to_prometheus(
        self,
        gateway_url: str,
        job_name: str = "sentinel",
        prometheus_text: str = "",
    ) -> bool:
        """Push metrics to Prometheus Pushgateway."""
        url = f"{gateway_url.rstrip('/')}/metrics/job/{job_name}"
        try:
            req = urllib.request.Request(
                url,
                data=prometheus_text.encode("utf-8"),
                headers={"Content-Type": "text/plain"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=10)
            logger.info("Pushed metrics to Prometheus gateway: %s", gateway_url)
            return True
        except Exception as e:
            logger.error("Prometheus push failed: %s", e)
            return False

    # ── Dashboard snapshot ───────────────────────────────────────────

    def create_dashboard_snapshot(self, metrics_data: dict) -> dict:
        """Create a dashboard-ready JSON snapshot with derived metrics."""
        return {
            "timestamp": time.time(),
            "service": "eresus-sentinel",
            "raw_metrics": metrics_data,
            "alerts": {
                "active": len([a for a in self._alert_history if not a.acknowledged]),
                "total": len(self._alert_history),
                "by_severity": {
                    sev.name: len([a for a in self._alert_history if a.severity == sev])
                    for sev in AlertSeverity
                },
            },
            "rules": {
                "total": len(self._alert_rules),
                "active": len([r for r in self._alert_rules if r.fire_count > 0]),
                "rules_summary": [
                    {"name": r.name, "fires": r.fire_count, "severity": r.severity.name}
                    for r in self._alert_rules
                ],
            },
            "otel_enabled": self._otel_initialized,
        }

    # ── History ──────────────────────────────────────────────────────

    def get_alert_history(
        self,
        severity: AlertSeverity | None = None,
        limit: int = 100,
    ) -> list[Alert]:
        alerts = self._alert_history
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        return alerts[-limit:]

    def acknowledge_alert(self, index: int) -> bool:
        if 0 <= index < len(self._alert_history):
            self._alert_history[index].acknowledged = True
            return True
        return False

    def get_summary(self) -> dict:
        return {
            "total_rules": len(self._alert_rules),
            "total_alerts_fired": len(self._alert_history),
            "unacknowledged": len([a for a in self._alert_history if not a.acknowledged]),
            "webhook_count": len(self._webhook_configs),
            "slack_configured": self._slack_config is not None,
            "pagerduty_configured": self._pagerduty_config is not None,
            "otel_initialized": self._otel_initialized,
        }
