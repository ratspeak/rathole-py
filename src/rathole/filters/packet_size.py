"""Generic packet size filter.

Drops any packet exceeding a configurable maximum raw size. Applies
to all packet types. The Reticulum MTU is 500 bytes, so legitimate
packets should never be larger — but malformed or crafted packets
might be.

Why not redundant with RNS: Reticulum enforces MTU at pack() on
OUTBOUND packets only. Inbound packets are NOT size-checked before
parsing. This filter catches oversized inbound packets before RNS
spends CPU parsing them.
"""

from .base import BaseFilter, PacketContext
from ..verdicts import Verdict, Severity


class PacketSizeFilter(BaseFilter):
    name = "packet_size"

    def __init__(self, config: dict, state):
        super().__init__(config, state)
        # Default: 600 bytes (MTU 500 + generous header margin)
        self._max_size = config.get("max_bytes", 600)

    def evaluate(self, ctx: PacketContext) -> Verdict:
        if ctx.raw_size > self._max_size:
            v = self.drop(
                ctx,
                reason=f"packet too large ({ctx.raw_size} > {self._max_size} bytes)",
            )
            v.severity = Severity.WARNING
            return v

        return self.accept(ctx)
