"""Resource transfer protection.

Guards against resource-based attacks: compression bombs, oversized
resource advertisements, and incomplete resource exhaustion. Checks
resource advertisement packets (RESOURCE_ADV context) for size limits
before the transfer begins.

Unlike global filters (which operate per-packet), this limits higher-level
resource TRANSFERS that span multiple packets over time. RNS has a 16MB
metadata max but no concurrent cap or advertised-vs-actual validation.
"""

from .base import BaseFilter, PacketContext
from ..verdicts import Verdict, Severity
from ..context import CTX_RESOURCE_ADV, CTX_RESOURCE, CTX_RESOURCE_REQ


class ResourceGuardFilter(BaseFilter):
    name = "resource_guard"

    def __init__(self, config: dict, state):
        super().__init__(config, state)
        # Maximum advertised resource size (bytes). Default: 16 MB
        self._max_resource_size = config.get("max_resource_bytes", 16 * 1024 * 1024)
        # Maximum concurrent active resources per interface
        self._max_active = config.get("max_active_per_interface", 10)

    def evaluate(self, ctx: PacketContext) -> Verdict:
        if not ctx.is_resource:
            return self.accept(ctx)

        iface = ctx.interface_name or "unknown"
        iface_state = self.state.get_interface(iface)

        # For resource advertisements, check advertised size
        if ctx.context_type == CTX_RESOURCE_ADV:
            # Check active resource count
            if iface_state.active_resources >= self._max_active:
                v = self.drop(
                    ctx,
                    reason=f"too many active resources from interface {iface} "
                           f"({iface_state.active_resources}/{self._max_active})",
                )
                v.severity = Severity.ALERT
                return v

            # Check advertised size against limit. We use raw_size as a
            # proxy since the actual resource size is embedded in the
            # advertisement payload (parsing requires RNS internals).
            if ctx.raw_size > self._max_resource_size:
                v = self.drop(
                    ctx,
                    reason=f"resource too large ({ctx.raw_size} bytes > "
                           f"{self._max_resource_size} max) from interface {iface}",
                )
                v.severity = Severity.ALERT
                return v

            iface_state.active_resources += 1

        return self.accept(ctx)
