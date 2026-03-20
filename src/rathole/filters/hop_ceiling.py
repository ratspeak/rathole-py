"""Hop ceiling filter — drops announces exceeding max hops.

RNS has a hard max of PATHFINDER_M = 128 hops. This filter provides a
configurable lower ceiling with soft mode and logging. Presets use
tighter ceilings (16-32) while the default matches the protocol max.
"""

from .base import BaseFilter, AnnounceContext
from ..verdicts import Verdict


class HopCeilingFilter(BaseFilter):
    name = "hop_ceiling"

    def __init__(self, config: dict, state):
        super().__init__(config, state)
        self._max_hops = config.get("max_hops", 32)

    def evaluate(self, ctx: AnnounceContext) -> Verdict:
        if ctx.hop_count > self._max_hops:
            return self.drop(
                ctx,
                reason=f"hop count {ctx.hop_count} exceeds ceiling {self._max_hops}",
            )
        return self.accept(ctx)
