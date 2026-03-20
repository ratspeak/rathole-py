"""Per-destination token bucket rate limiter.

Keys on destination_hash (not peer_hash) so that hub connections —
where hundreds of unique destinations arrive through one interface
identity — get independent rate limit buckets per destination.
"""

from .base import BaseFilter, AnnounceContext
from ..verdicts import Verdict


class RateLimitFilter(BaseFilter):
    name = "rate_limit"

    def __init__(self, config: dict, state):
        super().__init__(config, state)
        self._refill_rate = config.get("refill_rate", 0.5)
        self._burst = config.get("burst", 15)
        self._overflow = config.get("overflow_action", "drop")

    def evaluate(self, ctx: AnnounceContext) -> Verdict:
        # Key on destination, not peer — each destination gets its own bucket
        tracking_key = ctx.destination_hash or ctx.peer_hash

        # Ensure destination has an initialized bucket
        self.state.init_peer_bucket(
            tracking_key,
            capacity=self._burst,
            refill_rate=self._effective_refill(tracking_key),
        )

        peer = self.state.get_peer(tracking_key)
        if peer.bucket and peer.bucket.consume(1.0):
            return self.accept(ctx)

        # Budget exhausted
        if self._overflow == "throttle":
            return self.throttle(
                ctx, reason="destination announce budget exhausted (throttled)"
            )
        return self.drop(ctx, reason="destination announce budget exhausted")

    def _effective_refill(self, tracking_key: str) -> float:
        return self._refill_rate
