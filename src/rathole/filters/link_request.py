"""Link request rate limiter.

Link establishment involves X25519 ECDH key exchange (~1-2ms per
handshake) and memory allocation for pending links. This filter
limits link request rate per interface and caps the number of
concurrent pending links to prevent resource exhaustion.
"""

from .base import BaseFilter, PacketContext
from ..verdicts import Verdict, Severity


class LinkRequestFilter(BaseFilter):
    name = "link_request"

    def __init__(self, config: dict, state):
        super().__init__(config, state)
        self._refill_rate = config.get("refill_rate", 1.0)
        self._burst = config.get("burst", 10)
        self._max_pending = config.get("max_pending_per_interface", 50)

    def evaluate(self, ctx: PacketContext) -> Verdict:
        if not ctx.is_link_request:
            return self.accept(ctx)

        iface = ctx.interface_name or "unknown"

        # Rate limit via token bucket
        self.state.init_link_request_bucket(
            iface,
            capacity=self._burst,
            refill_rate=self._refill_rate,
        )

        iface_state = self.state.get_interface(iface)

        # Check pending link count
        if iface_state.pending_links >= self._max_pending:
            v = self.drop(
                ctx,
                reason=f"too many pending links from interface {iface} "
                       f"({iface_state.pending_links}/{self._max_pending})",
            )
            v.severity = Severity.ALERT
            return v

        # Rate limit check
        if iface_state.link_request_bucket and iface_state.link_request_bucket.consume(1.0):
            iface_state.pending_links += 1
            return self.accept(ctx)

        v = self.drop(
            ctx,
            reason=f"link request rate exceeded from interface {iface}",
        )
        v.severity = Severity.WARNING
        return v
