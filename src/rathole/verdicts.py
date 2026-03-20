"""Filter verdict types and severity levels."""

from enum import Enum, auto
from dataclasses import dataclass, field


class Action(Enum):
    """Verdict returned by each filter in the pipeline."""
    ACCEPT = auto()
    DROP = auto()
    THROTTLE = auto()
    BLACKHOLE = auto()    # Drop AND add identity to RNS blackhole list
    QUARANTINE = auto()   # Hold for manual review (TUI/dashboard)


class Severity(Enum):
    """
    Severity level for verdicts and events.

    Used for alerting thresholds, log filtering, and dashboard
    color-coding (green/blue/orange/red/purple).
    """
    INFO = auto()       # Normal accept
    NOTICE = auto()     # Accepted but noteworthy
    WARNING = auto()    # Throttled or soft-blocked
    ALERT = auto()      # Dropped, possible attack
    CRITICAL = auto()   # Dropped, confirmed attack pattern


# Actions that block the packet from proceeding
BLOCKING_ACTIONS = frozenset({Action.DROP, Action.THROTTLE, Action.BLACKHOLE, Action.QUARANTINE})


@dataclass
class Verdict:
    """Full verdict with metadata for logging, metrics, and alerting."""
    action: Action
    filter_name: str = ""
    reason: str = ""
    severity: Severity = Severity.INFO
    peer_hash: str = ""
    destination_hash: str = ""
    hop_count: int = 0
    metadata: dict = field(default_factory=dict)

    @property
    def dropped(self) -> bool:
        """True if this verdict blocks the packet."""
        return self.action in BLOCKING_ACTIONS

    @property
    def accepted(self) -> bool:
        return self.action == Action.ACCEPT

    def __str__(self) -> str:
        tag = self.action.name
        sev = f"/{self.severity.name}" if self.severity != Severity.INFO else ""
        src = f" [{self.filter_name}]" if self.filter_name else ""
        why = f" — {self.reason}" if self.reason else ""
        dest = self.destination_hash[:16] if self.destination_hash else "?"
        return f"{tag}{sev}{src} dest={dest}.. hops={self.hop_count}{why}"
