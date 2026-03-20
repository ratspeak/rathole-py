"""
Alert rules engine — configurable condition → action mappings.

Rules match against incoming events and fire actions (log, webhook, command).
Cooldown prevents alert storms. Severity escalation on repeated triggers.

Config keys (under [alerts]):
  - enabled: Enable alert rules (default false)
  - rules: List of rule definitions (see below)

Rule definition:
  - name: Human-readable rule name
  - event_types: List of event type names to match (empty = all)
  - min_severity: Minimum severity to trigger ("WARNING", "ALERT", "CRITICAL")
  - action: "log" | "webhook" | "command"
  - action_target: URL for webhook, command string for command
  - cooldown: Seconds between repeated triggers (default 300)
  - escalate_after: Number of triggers before severity escalates (default 5)
"""

import time
import logging
from dataclasses import dataclass, field
from threading import Lock

from .events import SecurityEvent, EventSeverity

log = logging.getLogger("rathole.alerts")

_SEVERITY_ORDER = {
    EventSeverity.INFO: 0,
    EventSeverity.NOTICE: 1,
    EventSeverity.WARNING: 2,
    EventSeverity.ALERT: 3,
    EventSeverity.CRITICAL: 4,
}

_SEVERITY_BY_NAME = {s.name: s for s in EventSeverity}


@dataclass
class AlertRule:
    """A single alert rule."""
    name: str
    event_types: list[str] = field(default_factory=list)
    min_severity: str = "WARNING"
    action: str = "log"
    action_target: str = ""
    cooldown: float = 300.0
    escalate_after: int = 5

    # Runtime state
    trigger_count: int = 0
    last_triggered: float = 0.0


@dataclass
class AlertFiring:
    """Record of an alert that fired."""
    rule_name: str
    event: SecurityEvent
    timestamp: float
    escalated: bool = False


class AlertEngine:
    """
    Evaluates events against configured rules and fires actions.

    Usage:
        engine = AlertEngine(config)
        engine.evaluate(event)  # Checks all rules
    """

    def __init__(self, config: dict):
        self._enabled = config.get("enabled", False)
        self._lock = Lock()
        self._rules: list[AlertRule] = []
        self._firings: list[AlertFiring] = []
        self._max_firings = 1000

        # Parse rules from config
        for rule_def in config.get("rules", []):
            self._rules.append(AlertRule(
                name=rule_def.get("name", "unnamed"),
                event_types=rule_def.get("event_types", []),
                min_severity=rule_def.get("min_severity", "WARNING"),
                action=rule_def.get("action", "log"),
                action_target=rule_def.get("action_target", ""),
                cooldown=rule_def.get("cooldown", 300.0),
                escalate_after=rule_def.get("escalate_after", 5),
            ))

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def rules(self) -> list[AlertRule]:
        return list(self._rules)

    @property
    def firings(self) -> list[AlertFiring]:
        with self._lock:
            return list(self._firings)

    def evaluate(self, event: SecurityEvent) -> list[AlertFiring]:
        """Evaluate an event against all rules. Returns any new firings."""
        if not self._enabled:
            return []

        now = time.monotonic()
        new_firings = []

        for rule in self._rules:
            if not self._matches(rule, event):
                continue

            # Check cooldown
            if now - rule.last_triggered < rule.cooldown:
                continue

            # Fire!
            rule.trigger_count += 1
            rule.last_triggered = now

            escalated = rule.trigger_count >= rule.escalate_after
            firing = AlertFiring(
                rule_name=rule.name,
                event=event,
                timestamp=now,
                escalated=escalated,
            )

            self._execute_action(rule, event, escalated)

            with self._lock:
                self._firings.append(firing)
                if len(self._firings) > self._max_firings:
                    self._firings = self._firings[-self._max_firings:]

            new_firings.append(firing)

        return new_firings

    def summary(self) -> dict:
        """Summary for control interface."""
        with self._lock:
            return {
                "enabled": self._enabled,
                "rules": [
                    {
                        "name": r.name,
                        "action": r.action,
                        "trigger_count": r.trigger_count,
                        "cooldown": r.cooldown,
                        "min_severity": r.min_severity,
                    }
                    for r in self._rules
                ],
                "total_firings": len(self._firings),
                "recent_firings": [
                    {
                        "rule": f.rule_name,
                        "timestamp": f.timestamp,
                        "escalated": f.escalated,
                    }
                    for f in self._firings[-10:]
                ],
            }

    def _matches(self, rule: AlertRule, event: SecurityEvent) -> bool:
        """Check if an event matches a rule."""
        # Check event type
        if rule.event_types and event.event_type.name not in rule.event_types:
            return False

        # Check severity
        min_sev = _SEVERITY_BY_NAME.get(rule.min_severity, EventSeverity.WARNING)
        event_order = _SEVERITY_ORDER.get(event.severity, 0)
        min_order = _SEVERITY_ORDER.get(min_sev, 2)
        if event_order < min_order:
            return False

        return True

    def _execute_action(self, rule: AlertRule, event: SecurityEvent, escalated: bool):
        """Execute the rule's action."""
        prefix = "[ESCALATED] " if escalated else ""

        if rule.action == "log":
            log.warning(
                "%sALERT [%s]: %s — %s",
                prefix, rule.name, event.event_type.name, event.description,
            )
        elif rule.action == "webhook":
            self._fire_webhook(rule, event, escalated)
        elif rule.action == "command":
            self._fire_command(rule, event, escalated)

    def _fire_webhook(self, rule: AlertRule, event: SecurityEvent, escalated: bool):
        """Send a webhook notification (fire-and-forget)."""
        if not rule.action_target:
            return
        # Webhook implementation deferred — logged for now
        log.info(
            "Would fire webhook to %s for rule %s: %s",
            rule.action_target, rule.name, event.description,
        )

    def _fire_command(self, rule: AlertRule, event: SecurityEvent, escalated: bool):
        """Execute a shell command (fire-and-forget)."""
        if not rule.action_target:
            return
        # Command execution deferred — logged for now
        log.info(
            "Would execute command '%s' for rule %s: %s",
            rule.action_target, rule.name, event.description,
        )
