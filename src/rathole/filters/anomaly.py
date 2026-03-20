"""Anomaly detector — interface-level windowed traffic pattern analysis.

Uses windowed counters (reset each correlator interval) on the receiving
interface rather than per-peer tracking. This prevents false positives
on hub connections where all announces from hundreds of peers arrive
through a single interface identity.

Requires a minimum sample size (min_packets) before evaluating the
ratio, so the initial routing table sync doesn't trigger alerts.
A grace period (default 300s) skips evaluation for newly-connected
interfaces, since initial routing table sync is legitimately
announce-heavy.
"""

import time

from .base import BaseFilter, AnnounceContext
from ..verdicts import Verdict


class AnomalyFilter(BaseFilter):
    name = "anomaly"

    def __init__(self, config: dict, state):
        super().__init__(config, state)
        self._max_ratio = config.get("max_announce_ratio", 50.0)
        self._action = config.get("anomaly_action", "throttle")
        self._min_packets = config.get("min_packets", 50)
        self._grace_period = config.get("grace_period", 300)

    def evaluate(self, ctx: AnnounceContext) -> Verdict:
        # Use interface-level windowed counters instead of per-peer
        if not ctx.interface_name:
            return self.accept(ctx)

        iface = self.state.get_interface(ctx.interface_name)

        # Grace period: skip recently-connected interfaces (initial
        # routing table sync is legitimately announce-heavy)
        if time.monotonic() - iface.first_seen < self._grace_period:
            return self.accept(ctx)

        # Don't evaluate until we have enough samples in this window
        if iface.packet_count_window < self._min_packets:
            return self.accept(ctx)

        # Calculate announce:non-announce ratio from windowed counters
        non_announce = iface.packet_count_window - iface.announce_count_window
        if non_announce <= 0:
            ratio = float(iface.announce_count_window)
        else:
            ratio = iface.announce_count_window / non_announce

        if ratio <= self._max_ratio:
            return self.accept(ctx)

        # Anomaly detected
        reason = (
            f"interface announce:traffic ratio {ratio:.1f} exceeds "
            f"threshold {self._max_ratio:.1f} "
            f"({iface.announce_count_window} announces / "
            f"{non_announce} other in window)"
        )

        if self._action == "flag":
            # Log-only: accept but mark metadata
            v = self.accept(ctx)
            v.metadata["anomaly_flagged"] = True
            v.metadata["announce_ratio"] = ratio
            return v

        elif self._action == "throttle":
            return self.throttle(ctx, reason=reason)

        else:  # "drop"
            return self.drop(ctx, reason=reason)
