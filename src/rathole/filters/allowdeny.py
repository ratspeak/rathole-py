"""Allow/Deny list filter — hard overrides checked first."""

from .base import BaseFilter, AnnounceContext
from ..verdicts import Verdict


class AllowDenyFilter(BaseFilter):
    name = "allowdeny"

    def __init__(self, config: dict, state):
        super().__init__(config, state)
        self._allow_dests = set(config.get("allow_destinations", []))
        self._allow_peers = set(config.get("allow_peers", []))
        self._deny_dests = set(config.get("deny_destinations", []))
        self._deny_peers = set(config.get("deny_peers", []))

    def evaluate(self, ctx: AnnounceContext) -> Verdict:
        # Allow takes priority — trusted peers/destinations bypass everything
        if ctx.destination_hash in self._allow_dests:
            return self.accept(ctx)
        if ctx.peer_hash in self._allow_peers:
            return self.accept(ctx)

        # Deny
        if ctx.destination_hash in self._deny_dests:
            return self.drop(ctx, reason="destination on deny list")
        if ctx.peer_hash in self._deny_peers:
            return self.drop(ctx, reason="peer on deny list")

        # No opinion — pass to next filter
        return self.accept(ctx)
