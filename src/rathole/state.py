"""Per-peer, per-interface, and per-destination state tracking."""

import time
import json
import logging
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from typing import Optional

log = logging.getLogger("rathole.state")


# ── Data Structures ──────────────────────────────────────────────


@dataclass
class TokenBucket:
    """Token bucket for rate limiting."""
    capacity: float
    refill_rate: float  # tokens per second
    tokens: float = 0.0
    last_refill: float = 0.0

    def __post_init__(self):
        if self.last_refill == 0.0:
            self.last_refill = time.monotonic()
            self.tokens = self.capacity

    def consume(self, count: float = 1.0) -> bool:
        """Try to consume tokens. Returns True if successful."""
        self._refill()
        if self.tokens >= count:
            self.tokens -= count
            return True
        return False

    def _refill(self):
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now


@dataclass
class DestinationPenalty:
    """Churn dampening state for a single destination."""
    penalty: float = 0.0
    suppressed: bool = False
    last_announce: float = 0.0
    last_decay: float = 0.0

    def __post_init__(self):
        now = time.monotonic()
        if self.last_announce == 0.0:
            self.last_announce = now
        if self.last_decay == 0.0:
            self.last_decay = now


@dataclass
class PeerState:
    """Aggregate state for a single peer."""
    peer_hash: str
    first_seen: float = 0.0
    bucket: Optional[TokenBucket] = None

    # Lifetime counters (never reset — for stats/display)
    announce_count: int = 0
    real_traffic_count: int = 0

    # Windowed counters (reset each window — for anomaly ratio)
    announce_count_window: int = 0
    real_traffic_count_window: int = 0
    window_start: float = 0.0

    def __post_init__(self):
        now = time.monotonic()
        if self.first_seen == 0.0:
            self.first_seen = now
        if self.window_start == 0.0:
            self.window_start = now

    def announce_ratio(self, window: float) -> float:
        """Ratio of announces to real traffic in the current window."""
        now = time.monotonic()
        if now - self.window_start > window:
            # Reset windowed counters only
            self.announce_count_window = 0
            self.real_traffic_count_window = 0
            self.window_start = now
            return 0.0
        if self.real_traffic_count_window == 0:
            return float(self.announce_count_window) if self.announce_count_window > 0 else 0.0
        return self.announce_count_window / self.real_traffic_count_window


@dataclass
class InterfaceState:
    """Aggregate state for a single network interface."""
    interface_name: str
    first_seen: float = 0.0

    # Rate limiting buckets
    packet_bucket: Optional[TokenBucket] = None
    bandwidth_bucket: Optional[TokenBucket] = None
    link_request_bucket: Optional[TokenBucket] = None

    # Traffic counters (cumulative, never reset — for stats/display)
    packet_count: int = 0
    byte_count: int = 0
    announce_count: int = 0
    link_request_count: int = 0
    path_request_count: int = 0

    # Windowed counters (reset each correlator interval — for anomaly/correlator)
    packet_count_window: int = 0
    announce_count_window: int = 0
    window_start: float = 0.0

    # Resource tracking
    pending_links: int = 0
    active_resources: int = 0

    # Burst detection
    burst_detected: bool = False

    def __post_init__(self):
        now = time.monotonic()
        if self.first_seen == 0.0:
            self.first_seen = now
        if self.window_start == 0.0:
            self.window_start = now

    def reset_window(self):
        """Reset windowed counters for a new observation period."""
        self.announce_count_window = 0
        self.packet_count_window = 0
        self.window_start = time.monotonic()


@dataclass
class PathRequestTracker:
    """Tracks path request timestamps and destinations for scanning detection.

    Uses a single deque of (timestamp, destination_hash) tuples to keep
    the two fields synchronized during pruning.
    """
    entries: deque = field(default_factory=lambda: deque(maxlen=1000))


# ── State Tracker ────────────────────────────────────────────────


class StateTracker:
    """
    Thread-safe container for all per-peer, per-interface, and
    per-destination state.

    This is the central nervous system of Rathole. Filters read and
    write state through this object.
    """

    def __init__(self):
        self._lock = Lock()
        self._peers: dict[str, PeerState] = {}
        self._interfaces: dict[str, InterfaceState] = {}
        self._destinations: dict[str, DestinationPenalty] = {}
        self._path_request_trackers: dict[str, PathRequestTracker] = {}
        self._global_stats = {
            "total_announces": 0,
            "total_accepted": 0,
            "total_dropped": 0,
            "total_throttled": 0,
            "total_blackholed": 0,
            "total_quarantined": 0,
            "total_packets": 0,
            "total_bytes_in": 0,
            "unique_peers_seen": 0,
            "peak_packet_rate": 0.0,
            "peak_packet_rate_at": 0.0,
            "peak_announce_rate": 0.0,
            "peak_announce_rate_at": 0.0,
            "start_time": time.monotonic(),
        }

        # Unique peer tracking (set of hashes, never shrinks)
        self._seen_peers: set[str] = set()

        # Per-filter drop counters
        self._filter_drops: dict[str, int] = {}

        # Rate computation (windowed, reset each update_rates() call)
        self._rate_window_start: float = time.monotonic()
        self._rate_window_packets: int = 0
        self._rate_window_announces: int = 0

        # Peers-per-hour timeline (last 24h buckets, one per minute)
        self._peers_timeline: deque = deque(maxlen=1440)
        self._peers_timeline_window_start: float = time.monotonic()
        self._peers_timeline_new_count: int = 0

    # ── Peer State ───────────────────────────────────────────────

    def get_peer(self, peer_hash: str) -> PeerState:
        with self._lock:
            if peer_hash not in self._peers:
                self._peers[peer_hash] = PeerState(peer_hash=peer_hash)
            return self._peers[peer_hash]

    def init_peer_bucket(self, peer_hash: str, capacity: float, refill_rate: float):
        """Initialize or reset a peer's token bucket."""
        peer = self.get_peer(peer_hash)
        with self._lock:
            if peer.bucket is None:
                peer.bucket = TokenBucket(capacity=capacity, refill_rate=refill_rate)

    def record_announce(self, peer_hash: str):
        """Increment announce counter for a peer."""
        peer = self.get_peer(peer_hash)
        with self._lock:
            peer.announce_count += 1
            peer.announce_count_window += 1
            self._global_stats["total_announces"] += 1
            self._rate_window_announces += 1

    def record_real_traffic(self, peer_hash: str):
        """Increment real traffic counter for a peer."""
        peer = self.get_peer(peer_hash)
        with self._lock:
            peer.real_traffic_count += 1
            peer.real_traffic_count_window += 1

    # Action.name → stat key mapping (e.g. "DROP" → "total_dropped")
    _VERDICT_KEY_MAP = {
        "drop": "total_dropped",
        "throttle": "total_throttled",
        "blackhole": "total_blackholed",
        "quarantine": "total_quarantined",
        "accepted": "total_accepted",
        "accept": "total_accepted",
    }

    def record_verdict(self, action_name: str):
        """Update global verdict counters."""
        key = self._VERDICT_KEY_MAP.get(
            action_name.lower(), f"total_{action_name.lower()}"
        )
        with self._lock:
            if key in self._global_stats:
                self._global_stats[key] += 1

    def record_packet(self):
        """Increment total packet counter."""
        with self._lock:
            self._global_stats["total_packets"] += 1
            self._rate_window_packets += 1

    def record_peer_seen(self, peer_hash: str):
        """Track unique peers. Increments unique_peers_seen on first sighting."""
        with self._lock:
            if peer_hash not in self._seen_peers:
                self._seen_peers.add(peer_hash)
                self._global_stats["unique_peers_seen"] = len(self._seen_peers)
                self._peers_timeline_new_count += 1

    def record_bytes(self, nbytes: int):
        """Add to cumulative bytes-in counter."""
        if nbytes > 0:
            with self._lock:
                self._global_stats["total_bytes_in"] += nbytes

    def record_filter_drop(self, filter_name: str):
        """Increment per-filter drop counter."""
        with self._lock:
            self._filter_drops[filter_name] = self._filter_drops.get(filter_name, 0) + 1

    def update_rates(self):
        """Compute current packet/announce rates and update peaks.

        Called each maintenance cycle (every 5s from daemon).
        """
        now = time.monotonic()
        with self._lock:
            elapsed = now - self._rate_window_start
            if elapsed < 1.0:
                return  # Too soon to compute meaningful rate

            packet_rate = self._rate_window_packets / elapsed
            announce_rate = self._rate_window_announces / elapsed

            if packet_rate > self._global_stats["peak_packet_rate"]:
                self._global_stats["peak_packet_rate"] = round(packet_rate, 2)
                self._global_stats["peak_packet_rate_at"] = now

            if announce_rate > self._global_stats["peak_announce_rate"]:
                self._global_stats["peak_announce_rate"] = round(announce_rate, 2)
                self._global_stats["peak_announce_rate_at"] = now

            # Reset window
            self._rate_window_start = now
            self._rate_window_packets = 0
            self._rate_window_announces = 0

    def filter_effectiveness(self) -> dict[str, int]:
        """Return per-filter drop counts, sorted by drops descending."""
        with self._lock:
            return dict(
                sorted(self._filter_drops.items(), key=lambda x: x[1], reverse=True)
            )

    def flush_peers_timeline(self):
        """Push current window's new-peer count to timeline deque and reset.

        Called once per minute from daemon. Used for connection-rate display.
        """
        now = time.monotonic()
        with self._lock:
            self._peers_timeline.append((now, self._peers_timeline_new_count))
            self._peers_timeline_new_count = 0
            self._peers_timeline_window_start = now

    def peers_per_hour(self) -> float:
        """Compute new-peers-per-hour from the timeline (last 60 minutes)."""
        now = time.monotonic()
        cutoff = now - 3600
        with self._lock:
            total = sum(count for ts, count in self._peers_timeline if ts > cutoff)
        return float(total)

    # ── Interface State ──────────────────────────────────────────

    def get_interface(self, interface_name: str) -> InterfaceState:
        with self._lock:
            if interface_name not in self._interfaces:
                self._interfaces[interface_name] = InterfaceState(
                    interface_name=interface_name,
                )
            return self._interfaces[interface_name]

    def init_interface_bucket(
        self, interface_name: str, capacity: float, refill_rate: float,
    ):
        """Initialize a per-interface packet rate bucket."""
        iface = self.get_interface(interface_name)
        with self._lock:
            if iface.packet_bucket is None:
                iface.packet_bucket = TokenBucket(
                    capacity=capacity, refill_rate=refill_rate,
                )

    def init_interface_bandwidth_bucket(
        self, interface_name: str, capacity: float, refill_rate: float,
    ):
        """Initialize a per-interface bandwidth (bytes/sec) bucket."""
        iface = self.get_interface(interface_name)
        with self._lock:
            if iface.bandwidth_bucket is None:
                iface.bandwidth_bucket = TokenBucket(
                    capacity=capacity, refill_rate=refill_rate,
                )

    def init_link_request_bucket(
        self, interface_name: str, capacity: float, refill_rate: float,
    ):
        """Initialize a per-interface link request rate bucket."""
        iface = self.get_interface(interface_name)
        with self._lock:
            if iface.link_request_bucket is None:
                iface.link_request_bucket = TokenBucket(
                    capacity=capacity, refill_rate=refill_rate,
                )

    def reset_interface_windows(self):
        """Reset all interface windowed counters. Called after correlator runs."""
        with self._lock:
            for iface in self._interfaces.values():
                iface.reset_window()

    # ── Path Request Tracking ────────────────────────────────────

    def get_path_request_tracker(self, interface_name: str) -> PathRequestTracker:
        with self._lock:
            if interface_name not in self._path_request_trackers:
                self._path_request_trackers[interface_name] = PathRequestTracker()
            return self._path_request_trackers[interface_name]

    # ── Destination Penalty State ────────────────────────────────

    def get_destination(self, dest_hash: str) -> DestinationPenalty:
        with self._lock:
            if dest_hash not in self._destinations:
                self._destinations[dest_hash] = DestinationPenalty()
            return self._destinations[dest_hash]

    def apply_decay(self, decay_factor: float, decay_interval: float):
        """Apply time-based decay to all destination penalties."""
        now = time.monotonic()
        with self._lock:
            for dest in self._destinations.values():
                elapsed = now - dest.last_decay
                if elapsed >= decay_interval:
                    intervals = elapsed / decay_interval
                    dest.penalty *= decay_factor ** intervals
                    dest.last_decay = now

    def prune_stale(self, max_age: float = 3600.0):
        """Remove destination entries with near-zero penalties."""
        now = time.monotonic()
        with self._lock:
            stale = [
                h for h, d in self._destinations.items()
                if d.penalty < 0.01 and (now - d.last_announce) > max_age
            ]
            for h in stale:
                del self._destinations[h]
            if stale:
                log.debug("Pruned %d stale destination entries", len(stale))

    def decay_link_resources(self, factor: float = 0.5):
        """Decay pending_links and active_resources toward zero.

        Called periodically from the daemon to prevent counters from
        growing forever (since RNS doesn't signal link/resource completion
        back to Rathole). A factor of 0.5 halves counters each cycle,
        converging to actual values over a few iterations.
        """
        with self._lock:
            for iface in self._interfaces.values():
                iface.pending_links = int(iface.pending_links * factor)
                iface.active_resources = int(iface.active_resources * factor)

    # ── Snapshots ────────────────────────────────────────────────

    @property
    def stats(self) -> dict:
        with self._lock:
            uptime = time.monotonic() - self._global_stats["start_time"]
            now = time.monotonic()
            cutoff = now - 3600
            pph = sum(count for ts, count in self._peers_timeline if ts > cutoff)
            return {
                **self._global_stats,
                "uptime": uptime,
                "tracked_peers": len(self._peers),
                "tracked_interfaces": len(self._interfaces),
                "tracked_destinations": len(self._destinations),
                "filter_drops": dict(self._filter_drops),
                "peers_per_hour": float(pph),
            }

    def peer_summary(self) -> list[dict]:
        """Summary of all tracked peers for the control interface."""
        with self._lock:
            return [
                {
                    "peer": p.peer_hash,
                    "announces": p.announce_count,
                    "real_traffic": p.real_traffic_count,
                    "ratio": round(p.announce_ratio(600), 2),
                    "bucket_tokens": round(p.bucket.tokens, 1) if p.bucket else None,
                }
                for p in self._peers.values()
            ]

    def interface_summary(self) -> list[dict]:
        """Summary of all tracked interfaces."""
        with self._lock:
            return [
                {
                    "interface": i.interface_name,
                    "packets": i.packet_count,
                    "bytes": i.byte_count,
                    "announces": i.announce_count,
                    "link_requests": i.link_request_count,
                    "path_requests": i.path_request_count,
                    "pending_links": i.pending_links,
                    "active_resources": i.active_resources,
                    "burst": i.burst_detected,
                }
                for i in self._interfaces.values()
            ]

    def load(self, path: str | Path, reputation=None, blackhole=None) -> bool:
        """Load state from a saved snapshot file.

        Restores reputation scores and blackhole entries so they survive
        daemon restarts.  Returns True if loaded successfully.
        """
        path = Path(path).expanduser()
        if not path.exists():
            return False
        try:
            with open(path, "r") as f:
                snapshot = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            log.warning("Failed to load state from %s: %s", path, e)
            return False

        if reputation is not None and "reputation" in snapshot:
            reputation.load_snapshot(snapshot["reputation"])
        if blackhole is not None and "blackhole" in snapshot:
            blackhole.load_snapshot(snapshot["blackhole"])

        log.info("State restored from %s", path)
        return True

    def save(self, path: str | Path, reputation=None, blackhole=None):
        """Persist state snapshot to disk.

        Optionally includes reputation and blackhole snapshots.
        """
        path = Path(path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        snapshot = {
            "saved_at": time.time(),
            "stats": self.stats,
            "peers": {
                h: {
                    "announce_count": p.announce_count,
                    "real_traffic_count": p.real_traffic_count,
                }
                for h, p in self._peers.items()
            },
            "destinations": {
                h: {
                    "penalty": d.penalty,
                    "suppressed": d.suppressed,
                }
                for h, d in self._destinations.items()
            },
            "interfaces": {
                name: {
                    "packet_count": i.packet_count,
                    "byte_count": i.byte_count,
                    "announce_count": i.announce_count,
                    "pending_links": i.pending_links,
                    "active_resources": i.active_resources,
                }
                for name, i in self._interfaces.items()
            },
            "filter_drops": dict(self._filter_drops),
            "unique_peers": list(self._seen_peers),
        }
        if reputation is not None:
            snapshot["reputation"] = reputation.snapshot()
        if blackhole is not None:
            snapshot["blackhole"] = blackhole.snapshot()
        try:
            with open(path, "w") as f:
                json.dump(snapshot, f, indent=2)
            log.debug("State saved to %s", path)
        except OSError as e:
            log.error("Failed to save state: %s", e)
