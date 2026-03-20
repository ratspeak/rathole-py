"""Announce churn dampening — BGP-style flap suppression for destinations.

RNS does per-destination rate limiting (one announce per destination per
period). This adds BGP RFC 2439-style dampening for identity CHURN
patterns — rapidly rotating identities that bypass per-destination limits.
"""

import time
from .base import BaseFilter, AnnounceContext
from ..verdicts import Verdict


class ChurnDampeningFilter(BaseFilter):
    name = "churn"

    def __init__(self, config: dict, state):
        super().__init__(config, state)
        self._penalty_inc = config.get("penalty_per_announce", 1.0)
        self._suppress_at = config.get("suppress_threshold", 5.0)
        self._reuse_at = config.get("reuse_threshold", 2.0)
        self._max_penalty = config.get("max_penalty", 20.0)
        self._decay_factor = config.get("decay_factor", 0.5)
        self._decay_interval = config.get("decay_interval", 300)

    def evaluate(self, ctx: AnnounceContext) -> Verdict:
        dest = self.state.get_destination(ctx.destination_hash)
        now = time.monotonic()

        # Apply time-based decay to this destination's penalty
        elapsed = now - dest.last_decay
        if elapsed >= self._decay_interval:
            intervals = elapsed / self._decay_interval
            dest.penalty *= self._decay_factor ** intervals
            dest.last_decay = now

        # Check suppression state transitions
        if dest.suppressed:
            if dest.penalty <= self._reuse_at:
                dest.suppressed = False
                # Falls through to normal processing
            else:
                return self.drop(
                    ctx,
                    reason=f"destination suppressed (penalty={dest.penalty:.1f})",
                )

        # Increment penalty for this re-announce
        dest.penalty = min(dest.penalty + self._penalty_inc, self._max_penalty)
        dest.last_announce = now

        # Check if we just crossed the suppress threshold
        if dest.penalty >= self._suppress_at:
            dest.suppressed = True
            return self.drop(
                ctx,
                reason=f"destination newly suppressed (penalty={dest.penalty:.1f})",
            )

        return self.accept(ctx)
