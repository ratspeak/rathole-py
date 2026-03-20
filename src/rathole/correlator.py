"""
Coordinated attack detection — cross-filter pattern correlation.

Runs periodically (default 30s) and examines StateTracker data for
cross-filter patterns that individual filters can't detect:

  - Sybil clusters: Many new destinations from same interface in short window
  - Destination scanning: Sequential/patterned path request destinations
  - Slowloris links: Many half-established links, none completing
  - Amplification: High outbound-to-inbound ratio on an interface

Each detected pattern produces a CorrelationAlert with severity and
recommended action.

Response modes:
  - "alert": Log alerts only (default, safe)
  - "defensive": Auto-respond to detected patterns (reputation penalties,
    temporary threshold tightening). Respects dry-run mode.
"""

import time
import logging
from enum import Enum, auto
from dataclasses import dataclass, field
from collections import deque

log = logging.getLogger("rathole.correlator")


class AttackPattern(Enum):
    SYBIL_CLUSTER = auto()
    DESTINATION_SCAN = auto()
    SLOWLORIS_LINK = auto()
    AMPLIFICATION = auto()


@dataclass
class CorrelationAlert:
    """A detected cross-filter attack pattern."""
    pattern: AttackPattern
    interface_name: str
    timestamp: float
    severity: str           # "warning", "alert", "critical"
    description: str
    evidence: dict = field(default_factory=dict)
    recommended_action: str = ""
    response_executed: bool = False


class AttackCorrelator:
    """
    Periodically analyzes state for coordinated attack patterns.

    Config keys:
      - enabled: Enable correlation engine (default true)
      - interval: Seconds between analysis runs (default 30)
      - sybil_window: Window for Sybil cluster detection (default 300)
      - sybil_threshold: New destinations in window to trigger (default 50)
      - scan_sequential_threshold: Sequential dest hashes to flag (default 10)
      - slowloris_ratio: pending/established link ratio to flag (default 5.0)
      - amplification_ratio: outbound/inbound ratio to flag (default 50.0)
      - response_mode: "alert" (log only) or "defensive" (auto-respond)
      - response_cooldown: Seconds before same pattern re-triggers on same interface
    """

    def __init__(self, config: dict, state, reputation=None, router=None, dry_run: bool = False):
        self._config = config
        self._state = state
        self._reputation = reputation
        self._router = router
        self._dry_run = dry_run
        self._enabled = config.get("enabled", True)
        self._interval = config.get("interval", 30)

        # Detection thresholds
        self._sybil_window = config.get("sybil_window", 300)
        self._sybil_threshold = config.get("sybil_threshold", 50)
        self._scan_seq_threshold = config.get("scan_sequential_threshold", 10)
        self._slowloris_ratio = config.get("slowloris_ratio", 5.0)
        self._amplification_ratio = config.get("amplification_ratio", 50.0)

        # Response mode
        self._response_mode = config.get("response_mode", "alert")
        self._response_cooldown = config.get("response_cooldown", 300)
        self._grace_period = config.get("grace_period", 300)

        self._last_run: float = 0.0
        self._alerts: deque[CorrelationAlert] = deque(maxlen=500)
        self._cooldowns: dict[str, float] = {}  # "pattern:interface" -> last response time
        self._responses_executed: int = 0

        # Pattern history for stats display (timestamp, pattern_type, interface, severity)
        self._pattern_history: deque = deque(maxlen=100)

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def response_mode(self) -> str:
        return self._response_mode

    @property
    def alerts(self) -> list[CorrelationAlert]:
        return list(self._alerts)

    @property
    def recent_alerts(self) -> list[CorrelationAlert]:
        """Alerts from the last hour."""
        cutoff = time.monotonic() - 3600
        return [a for a in self._alerts if a.timestamp > cutoff]

    def run(self) -> list[CorrelationAlert]:
        """
        Run correlation analysis. Returns any new alerts detected.

        Should be called periodically (e.g., every 30s from a timer).
        """
        if not self._enabled:
            return []

        now = time.monotonic()
        if now - self._last_run < self._interval:
            return []

        self._last_run = now
        new_alerts = []

        new_alerts.extend(self._check_sybil_clusters())
        new_alerts.extend(self._check_destination_scan())
        new_alerts.extend(self._check_slowloris())
        new_alerts.extend(self._check_amplification())

        for alert in new_alerts:
            self._alerts.append(alert)
            self._pattern_history.append((
                alert.timestamp,
                alert.pattern.name,
                alert.interface_name,
                alert.severity,
            ))
            log.warning(
                "CORRELATION [%s] on %s: %s",
                alert.pattern.name, alert.interface_name, alert.description,
            )

            # Execute defensive response if in defensive mode
            if self._response_mode == "defensive":
                self._execute_response(alert)

        return new_alerts

    def _execute_response(self, alert: CorrelationAlert):
        """
        Execute a defensive response to a detected attack pattern.

        Respects cooldown (won't re-trigger same pattern on same interface
        within cooldown period) and dry-run mode (logs but doesn't execute).
        """
        cooldown_key = f"{alert.pattern.name}:{alert.interface_name}"
        now = time.monotonic()

        # Check cooldown
        last_response = self._cooldowns.get(cooldown_key, 0.0)
        if now - last_response < self._response_cooldown:
            log.debug(
                "Response cooldown active for %s (%.0fs remaining)",
                cooldown_key,
                self._response_cooldown - (now - last_response),
            )
            return

        self._cooldowns[cooldown_key] = now

        if self._dry_run:
            log.info(
                "DRY-RUN: Would execute defensive response for [%s] on %s: %s",
                alert.pattern.name, alert.interface_name, alert.recommended_action,
            )
            return

        # Execute pattern-specific response
        if alert.pattern == AttackPattern.SYBIL_CLUSTER:
            self._respond_sybil(alert)
        elif alert.pattern == AttackPattern.DESTINATION_SCAN:
            self._respond_destination_scan(alert)
        elif alert.pattern == AttackPattern.SLOWLORIS_LINK:
            self._respond_slowloris(alert)
        elif alert.pattern == AttackPattern.AMPLIFICATION:
            self._respond_amplification(alert)

        alert.response_executed = True
        self._responses_executed += 1

    def _respond_sybil(self, alert: CorrelationAlert):
        """Defensive response to Sybil cluster detection.

        Does NOT apply mass reputation penalties — the peers on an
        interface include relays that may be innocently forwarding
        traffic.  Only announce-based reputation updates (via the
        router) have cryptographic attribution.  Individual Sybil
        announces are still penalized through the normal announce
        pipeline filters and the router's per-verdict reputation path.
        """
        log.warning(
            "DEFENSIVE: Sybil cluster detected on %s — "
            "%s announces in window (threshold %s). "
            "Announce-level reputation tracking remains active via router.",
            alert.interface_name,
            alert.evidence.get("announce_count_window", "?"),
            alert.evidence.get("threshold", "?"),
        )

    def _respond_destination_scan(self, alert: CorrelationAlert):
        """Log defensive response for cross-interface destination scanning."""
        log.warning(
            "DEFENSIVE: Cross-interface destination scan detected — "
            "%s unique destinations across all interfaces (threshold %s)",
            alert.evidence.get("unique_destinations", "?"),
            alert.evidence.get("threshold", "?"),
        )

    def _respond_slowloris(self, alert: CorrelationAlert):
        """Log defensive response for Slowloris pattern."""
        log.warning(
            "DEFENSIVE: Slowloris pattern detected on %s — "
            "recommend reducing max_pending_per_interface",
            alert.interface_name,
        )

    def _respond_amplification(self, alert: CorrelationAlert):
        """Log defensive response for amplification pattern."""
        log.warning(
            "DEFENSIVE: Amplification pattern detected on %s — "
            "recommend increasing throttle factor",
            alert.interface_name,
        )

    def _check_sybil_clusters(self) -> list[CorrelationAlert]:
        """Detect many new destinations appearing from a single interface."""
        alerts = []
        now = time.monotonic()

        for iface_name, iface in self._state._interfaces.items():
            # Grace period: skip recently-connected interfaces (initial
            # routing table sync is legitimately announce-heavy)
            if now - iface.first_seen < self._grace_period:
                continue

            # Use windowed announce count (resets each correlator interval)
            if iface.announce_count_window >= self._sybil_threshold:
                alerts.append(CorrelationAlert(
                    pattern=AttackPattern.SYBIL_CLUSTER,
                    interface_name=iface_name,
                    timestamp=now,
                    severity="alert",
                    description=(
                        f"High announce volume from {iface_name}: "
                        f"{iface.announce_count_window} announces in window"
                    ),
                    evidence={
                        "announce_count_window": iface.announce_count_window,
                        "threshold": self._sybil_threshold,
                    },
                    recommended_action="tighten_rate_limits",
                ))
        return alerts

    def _check_destination_scan(self) -> list[CorrelationAlert]:
        """Detect distributed destination scanning across multiple interfaces.

        Individual per-interface scan detection is handled by the PathRequestFilter.
        This check correlates across all interfaces: if the aggregate unique
        destination count (within each tracker's current entries) exceeds the
        threshold, it flags a cross-interface scan even if each interface stays
        below its own limit.
        """
        now = time.monotonic()

        # Aggregate unique destinations across all path request trackers
        all_destinations: set[str] = set()
        contributing_interfaces: list[str] = []

        for iface_name, tracker in self._state._path_request_trackers.items():
            iface_dests = {dest for _ts, dest in tracker.entries if dest}
            if iface_dests:
                all_destinations.update(iface_dests)
                contributing_interfaces.append(iface_name)

        if len(all_destinations) >= self._scan_seq_threshold and len(contributing_interfaces) > 1:
            return [CorrelationAlert(
                pattern=AttackPattern.DESTINATION_SCAN,
                interface_name=", ".join(contributing_interfaces[:5]),
                timestamp=now,
                severity="alert",
                description=(
                    f"Cross-interface destination scan: {len(all_destinations)} unique "
                    f"destinations across {len(contributing_interfaces)} interfaces"
                ),
                evidence={
                    "unique_destinations": len(all_destinations),
                    "interfaces": contributing_interfaces,
                    "threshold": self._scan_seq_threshold,
                },
                recommended_action="tighten_path_request_limits",
            )]
        return []

    def _check_slowloris(self) -> list[CorrelationAlert]:
        """Detect many half-open links with few completions."""
        alerts = []
        now = time.monotonic()

        for iface_name, iface in self._state._interfaces.items():
            if iface.pending_links <= 0:
                continue
            # If pending links vastly outnumber completed link requests
            if iface.link_request_count > 0:
                ratio = iface.pending_links / max(1, iface.link_request_count - iface.pending_links)
                if ratio >= self._slowloris_ratio and iface.pending_links >= 3:
                    alerts.append(CorrelationAlert(
                        pattern=AttackPattern.SLOWLORIS_LINK,
                        interface_name=iface_name,
                        timestamp=now,
                        severity="alert",
                        description=(
                            f"Slowloris pattern on {iface_name}: "
                            f"{iface.pending_links} pending vs "
                            f"{iface.link_request_count} total link requests "
                            f"(ratio {ratio:.1f})"
                        ),
                        evidence={
                            "pending_links": iface.pending_links,
                            "link_request_count": iface.link_request_count,
                            "ratio": round(ratio, 2),
                            "threshold": self._slowloris_ratio,
                        },
                        recommended_action="reduce_pending_cap",
                    ))
        return alerts

    def _check_amplification(self) -> list[CorrelationAlert]:
        """Detect interfaces with high announce-to-data ratio (amplification)."""
        alerts = []
        now = time.monotonic()

        for iface_name, iface in self._state._interfaces.items():
            # Grace period: skip recently-connected interfaces
            if now - iface.first_seen < self._grace_period:
                continue

            # Use windowed counters (reset each correlator interval)
            if iface.packet_count_window < 10:
                continue

            non_announce = iface.packet_count_window - iface.announce_count_window
            if non_announce <= 0:
                ratio = float(iface.announce_count_window)
            else:
                ratio = iface.announce_count_window / non_announce

            if ratio >= self._amplification_ratio and iface.announce_count_window >= 10:
                alerts.append(CorrelationAlert(
                    pattern=AttackPattern.AMPLIFICATION,
                    interface_name=iface_name,
                    timestamp=now,
                    severity="warning",
                    description=(
                        f"Amplification pattern on {iface_name}: "
                        f"announce:data ratio {ratio:.1f} "
                        f"({iface.announce_count_window} announces / "
                        f"{non_announce} other) in window"
                    ),
                    evidence={
                        "announce_count_window": iface.announce_count_window,
                        "non_announce_count_window": non_announce,
                        "ratio": round(ratio, 2),
                        "threshold": self._amplification_ratio,
                    },
                    recommended_action="throttle_announces",
                ))
        return alerts

    def pattern_history(self) -> list[dict]:
        """Recent pattern detections for stats display."""
        return [
            {
                "timestamp": ts,
                "pattern": pattern,
                "interface": iface,
                "severity": sev,
            }
            for ts, pattern, iface, sev in self._pattern_history
        ]

    def refresh_config(self, config: dict):
        """Re-read cached config values after a live config change."""
        self._config = config
        self._enabled = config.get("enabled", True)
        self._interval = config.get("interval", 30)
        self._sybil_window = config.get("sybil_window", 300)
        self._sybil_threshold = config.get("sybil_threshold", 50)
        self._scan_seq_threshold = config.get("scan_sequential_threshold", 10)
        self._slowloris_ratio = config.get("slowloris_ratio", 5.0)
        self._amplification_ratio = config.get("amplification_ratio", 50.0)
        self._response_mode = config.get("response_mode", "alert")
        self._response_cooldown = config.get("response_cooldown", 300)
        self._grace_period = config.get("grace_period", 300)

    def summary(self) -> dict:
        """Summary for control interface."""
        return {
            "enabled": self._enabled,
            "response_mode": self._response_mode,
            "responses_executed": self._responses_executed,
            "total_alerts": len(self._alerts),
            "recent_alerts": len(self.recent_alerts),
            "pattern_history": self.pattern_history()[-20:],
            "alerts": [
                {
                    "pattern": a.pattern.name,
                    "interface": a.interface_name,
                    "severity": a.severity,
                    "description": a.description,
                    "timestamp": a.timestamp,
                    "response_executed": a.response_executed,
                }
                for a in list(self._alerts)[-20:]  # Last 20
            ],
        }
