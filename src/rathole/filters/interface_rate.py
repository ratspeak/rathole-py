"""Per-interface global packet rate limiter.

Limits the total number of packets (all types) accepted from a single
interface per second. This is the first line of defense — it runs in
the global pipeline before type-specific filters and catches raw
volume attacks regardless of packet type.

Protects against packet-count floods (many small packets). Complements
the bandwidth filter which counts bytes. RNS has no native per-interface
packet rate limiting.
"""

from .base import BaseFilter, PacketContext
from ..verdicts import Verdict, Severity


class InterfaceRateLimitFilter(BaseFilter):
    name = "interface_rate"

    def __init__(self, config: dict, state):
        super().__init__(config, state)
        self._refill_rate = config.get("refill_rate", 10.0)
        self._burst = config.get("burst", 50)
        self._overflow = config.get("overflow_action", "drop")

    def evaluate(self, ctx: PacketContext) -> Verdict:
        if not ctx.interface_name:
            return self.accept(ctx)

        self.state.init_interface_bucket(
            ctx.interface_name,
            capacity=self._burst,
            refill_rate=self._refill_rate,
        )

        iface = self.state.get_interface(ctx.interface_name)
        if iface.packet_bucket and iface.packet_bucket.consume(1.0):
            return self.accept(ctx)

        reason = f"interface {ctx.interface_name} packet rate exceeded"
        if self._overflow == "throttle":
            return self.throttle(ctx, reason=reason)
        v = self.drop(ctx, reason=reason)
        v.severity = Severity.WARNING
        return v
