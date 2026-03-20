"""Announce payload size filter.

Announces carry optional app_data. Unusually large app_data payloads
can be used for bandwidth amplification since announces are
re-propagated to all peers. This filter caps the maximum announce
payload size.

RNS has no app_data size limit. Oversized app_data amplifies across
ALL transport nodes since announces are re-propagated network-wide.
"""

from .base import BaseFilter, PacketContext
from ..verdicts import Verdict, Severity


class AnnounceSizeFilter(BaseFilter):
    name = "announce_size"

    def __init__(self, config: dict, state):
        super().__init__(config, state)
        # Default: 500 bytes. Reticulum's MDU (maximum data unit) is ~500 bytes,
        # so app_data is always smaller, but we allow configuration.
        self._max_app_data = config.get("max_app_data_bytes", 500)

    def evaluate(self, ctx: PacketContext) -> Verdict:
        if not ctx.is_announce:
            return self.accept(ctx)

        if ctx.announce_app_data_size > self._max_app_data:
            v = self.drop(
                ctx,
                reason=f"announce app_data too large ({ctx.announce_app_data_size} > "
                       f"{self._max_app_data} bytes)",
            )
            v.severity = Severity.WARNING
            return v

        return self.accept(ctx)
