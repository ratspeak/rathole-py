"""Path request rate limiter and scanning detector.

Path requests are cheap to generate but can force expensive announce
retransmissions (amplification). This filter limits path request rate
per interface and detects destination scanning patterns.
"""

import time
from .base import BaseFilter, PacketContext
from ..verdicts import Verdict, Severity
from ..context import PACKET_DATA


class PathRequestFilter(BaseFilter):
    name = "path_request"

    def __init__(self, config: dict, state):
        super().__init__(config, state)
        self._rate = config.get("max_per_minute", 30)
        self._scan_threshold = config.get("scan_threshold", 20)
        self._scan_window = config.get("scan_window", 60)

    def evaluate(self, ctx: PacketContext) -> Verdict:
        if not ctx.is_path_request:
            return self.accept(ctx)

        iface = ctx.interface_name or "unknown"
        tracker = self.state.get_path_request_tracker(iface)

        now = time.monotonic()

        # Prune old entries (single deque of (timestamp, dest) tuples)
        # Use max of rate window (60s) and scan_window so entries aren't
        # pruned before scan detection can analyze them.
        cutoff = now - max(60.0, self._scan_window)
        while tracker.entries and tracker.entries[0][0] < cutoff:
            tracker.entries.popleft()

        # Rate check
        if len(tracker.entries) >= self._rate:
            v = self.drop(
                ctx,
                reason=f"path request rate exceeded ({len(tracker.entries)}/{self._rate} per min) "
                       f"from interface {iface}",
            )
            v.severity = Severity.ALERT
            return v

        # Record this request
        tracker.entries.append((now, ctx.destination_hash))

        # Scanning detection: many unique destinations in short window
        scan_cutoff = now - self._scan_window
        recent_dests = {dest for ts, dest in tracker.entries if ts >= scan_cutoff}

        if len(recent_dests) >= self._scan_threshold:
            v = self.drop(
                ctx,
                reason=f"destination scanning detected: {len(recent_dests)} unique destinations "
                       f"in {self._scan_window}s from interface {iface}",
            )
            v.severity = Severity.CRITICAL
            return v

        return self.accept(ctx)
