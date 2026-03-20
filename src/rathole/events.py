"""
Structured event system — typed security events for logging, alerting, and display.

SecurityEvent is the core event type. Events are stored in a bounded ring buffer
and can be consumed by the TUI, dashboard, alerting engine, and event store.

Event types mirror the things operators care about:
  - PACKET_DROPPED, PACKET_THROTTLED, PACKET_BLACKHOLED, PACKET_QUARANTINED
  - SCAN_DETECTED, SYBIL_DETECTED, SLOWLORIS_DETECTED, AMPLIFICATION_DETECTED
  - REPUTATION_CHANGED, IDENTITY_BLACKHOLED, IDENTITY_UNBLACKHOLED
  - FILTER_TRIGGERED, THRESHOLD_EXCEEDED, CONFIG_CHANGED
  - SYSTEM_START, SYSTEM_STOP, SYSTEM_ERROR
"""

import time
import logging
from enum import Enum, auto
from dataclasses import dataclass, field
from collections import deque
from threading import Lock

log = logging.getLogger("rathole.events")


class EventType(Enum):
    # ── Verdict events ──────────────────────────────────────────
    PACKET_DROPPED = auto()
    PACKET_THROTTLED = auto()
    PACKET_BLACKHOLED = auto()
    PACKET_QUARANTINED = auto()
    PACKET_ACCEPTED = auto()

    # ── Detection events ────────────────────────────────────────
    SCAN_DETECTED = auto()
    SYBIL_DETECTED = auto()
    SLOWLORIS_DETECTED = auto()
    AMPLIFICATION_DETECTED = auto()

    # ── Identity events ─────────────────────────────────────────
    REPUTATION_CHANGED = auto()
    IDENTITY_BLACKHOLED = auto()
    IDENTITY_UNBLACKHOLED = auto()

    # ── System events ───────────────────────────────────────────
    FILTER_TRIGGERED = auto()
    THRESHOLD_EXCEEDED = auto()
    CONFIG_CHANGED = auto()
    SYSTEM_START = auto()
    SYSTEM_STOP = auto()
    SYSTEM_ERROR = auto()


class EventSeverity(Enum):
    """Severity levels for display color-coding."""
    INFO = auto()       # Green
    NOTICE = auto()     # Blue
    WARNING = auto()    # Orange
    ALERT = auto()      # Red
    CRITICAL = auto()   # Purple


@dataclass
class SecurityEvent:
    """A single security event with full context."""
    event_type: EventType
    severity: EventSeverity
    timestamp: float = 0.0
    source: str = ""             # Filter or module name
    interface_name: str = ""
    identity_hash: str = ""
    destination_hash: str = ""
    description: str = ""
    details: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time.time()

    def to_dict(self) -> dict:
        """Serializable dictionary for JSON/Socket.IO."""
        return {
            "event_type": self.event_type.name,
            "severity": self.severity.name,
            "timestamp": self.timestamp,
            "source": self.source,
            "interface_name": self.interface_name,
            "identity_hash": self.identity_hash,
            "destination_hash": self.destination_hash,
            "description": self.description,
            "details": self.details,
        }


class EventBus:
    """
    Thread-safe event ring buffer with subscriber support.

    Events are stored in a bounded deque and can be consumed by
    multiple subscribers (TUI, dashboard, alerting, event store).

    Usage:
        bus = EventBus(max_events=10000)
        bus.emit(SecurityEvent(...))

        # Subscribe for real-time events
        unsub = bus.subscribe(lambda event: print(event))
        bus.emit(SecurityEvent(...))  # subscriber called
        unsub()  # stop listening
    """

    def __init__(self, max_events: int = 10000):
        self._lock = Lock()
        self._events: deque[SecurityEvent] = deque(maxlen=max_events)
        self._subscribers: list[callable] = []
        self._total_emitted: int = 0

    def emit(self, event: SecurityEvent):
        """Add an event and notify subscribers."""
        with self._lock:
            self._events.append(event)
            self._total_emitted += 1
            subs = list(self._subscribers)

        # Notify outside lock to prevent deadlocks
        for sub in subs:
            try:
                sub(event)
            except Exception as e:
                log.error("Event subscriber error: %s", e)

    def subscribe(self, callback: callable) -> callable:
        """
        Register a callback for new events. Returns an unsubscribe function.
        """
        with self._lock:
            self._subscribers.append(callback)

        def unsubscribe():
            with self._lock:
                try:
                    self._subscribers.remove(callback)
                except ValueError:
                    pass

        return unsubscribe

    @property
    def events(self) -> list[SecurityEvent]:
        with self._lock:
            return list(self._events)

    @property
    def total_emitted(self) -> int:
        with self._lock:
            return self._total_emitted

    def recent(self, count: int = 50) -> list[SecurityEvent]:
        """Get the most recent N events."""
        with self._lock:
            return list(self._events)[-count:]

    def query(
        self,
        event_type: EventType | None = None,
        severity: EventSeverity | None = None,
        interface_name: str = "",
        identity_hash: str = "",
        limit: int = 100,
    ) -> list[SecurityEvent]:
        """Query events with optional filters."""
        with self._lock:
            results = []
            for event in reversed(self._events):
                if event_type and event.event_type != event_type:
                    continue
                if severity and event.severity != severity:
                    continue
                if interface_name and event.interface_name != interface_name:
                    continue
                if identity_hash and event.identity_hash != identity_hash:
                    continue
                results.append(event)
                if len(results) >= limit:
                    break
            return results

    def stats(self) -> dict:
        """Event statistics for control interface."""
        with self._lock:
            by_type: dict[str, int] = {}
            by_severity: dict[str, int] = {}
            for event in self._events:
                by_type[event.event_type.name] = by_type.get(event.event_type.name, 0) + 1
                by_severity[event.severity.name] = by_severity.get(event.severity.name, 0) + 1
            return {
                "total_emitted": self._total_emitted,
                "buffered": len(self._events),
                "subscribers": len(self._subscribers),
                "by_type": by_type,
                "by_severity": by_severity,
            }
