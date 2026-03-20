"""Base filter interface."""

from abc import ABC, abstractmethod
from ..context import PacketContext, AnnounceContext  # noqa: F401 — re-export for backward compat
from ..verdicts import Verdict, Action
from ..state import StateTracker


class BaseFilter(ABC):
    """
    Abstract base for all Rathole filters.

    Subclasses implement `evaluate()` which returns a Verdict.
    Returning Action.ACCEPT means "I have no objection, pass to next filter."
    Returning Action.DROP or Action.THROTTLE is a terminal verdict.

    The `ctx` argument is a PacketContext. For announce-specific filters,
    ctx.is_announce will be True and announce-specific fields (peer_hash,
    announce_app_data_size) will be populated. Filters that only apply to
    specific packet types should check ctx.packet_type or the convenience
    properties (ctx.is_announce, ctx.is_link_request, etc.) and return
    ACCEPT for packet types they don't handle.
    """

    name: str = "base"

    def __init__(self, config: dict, state: StateTracker):
        self.config = config
        self.state = state

    @abstractmethod
    def evaluate(self, ctx: PacketContext) -> Verdict:
        """Evaluate a packet and return a verdict."""
        ...

    def accept(self, ctx: PacketContext, **metadata) -> Verdict:
        """Convenience: return ACCEPT verdict."""
        v = Verdict(
            action=Action.ACCEPT,
            filter_name=self.name,
            peer_hash=ctx.peer_hash,
            destination_hash=ctx.destination_hash,
            hop_count=ctx.hop_count,
        )
        if metadata:
            v.metadata.update(metadata)
        return v

    def drop(self, ctx: PacketContext, reason: str = "", **metadata) -> Verdict:
        """Convenience: return DROP verdict."""
        v = Verdict(
            action=Action.DROP,
            filter_name=self.name,
            reason=reason,
            peer_hash=ctx.peer_hash,
            destination_hash=ctx.destination_hash,
            hop_count=ctx.hop_count,
        )
        if metadata:
            v.metadata.update(metadata)
        return v

    def throttle(self, ctx: PacketContext, reason: str = "", **metadata) -> Verdict:
        """Convenience: return THROTTLE verdict."""
        v = Verdict(
            action=Action.THROTTLE,
            filter_name=self.name,
            reason=reason,
            peer_hash=ctx.peer_hash,
            destination_hash=ctx.destination_hash,
            hop_count=ctx.hop_count,
        )
        if metadata:
            v.metadata.update(metadata)
        return v
