"""Per-interface bandwidth limiter.

Token-bucket rate limiting on bytes per second per interface. Prevents
bandwidth exhaustion from any single interface regardless of packet
type or count.

Protects against byte-rate exhaustion (fewer large packets or sustained
streams). Complements the interface_rate filter which counts packets.
RNS has no native bandwidth rate limiting.
"""

from .base import BaseFilter, PacketContext
from ..verdicts import Verdict, Severity


class BandwidthFilter(BaseFilter):
    name = "bandwidth"

    def __init__(self, config: dict, state):
        super().__init__(config, state)
        # Default: 1 MB/s burst, 500 KB/s sustained
        self._refill_rate = config.get("bytes_per_second", 500_000)
        self._burst = config.get("burst_bytes", 1_000_000)

    def evaluate(self, ctx: PacketContext) -> Verdict:
        if not ctx.interface_name or ctx.raw_size == 0:
            return self.accept(ctx)

        self.state.init_interface_bandwidth_bucket(
            ctx.interface_name,
            capacity=self._burst,
            refill_rate=self._refill_rate,
        )

        iface = self.state.get_interface(ctx.interface_name)
        if iface.bandwidth_bucket and iface.bandwidth_bucket.consume(ctx.raw_size):
            return self.accept(ctx)

        v = self.drop(
            ctx,
            reason=f"interface {ctx.interface_name} bandwidth limit exceeded "
                   f"({ctx.raw_size} bytes)",
        )
        v.severity = Severity.WARNING
        return v
