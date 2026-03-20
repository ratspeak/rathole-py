"""Filter pipeline — runs packets through ordered filter chains."""

import logging
from .verdicts import Verdict, Action, Severity, BLOCKING_ACTIONS
from .state import StateTracker
from .config import RatholeConfig
from .filters import BaseFilter
from .context import PacketContext

log = logging.getLogger("rathole.pipeline")


class FilterPipeline:
    """
    Ordered chain of filters. A packet is evaluated by each filter
    in sequence. The first non-ACCEPT verdict is final.

    Used by PipelineRouter for type-specific chains, and can also
    be used standalone (backward-compatible with v0.1 usage).
    """

    def __init__(
        self,
        config: RatholeConfig,
        state: StateTracker,
        registry: list[tuple[str, type[BaseFilter]]] | None = None,
    ):
        self.config = config
        self.state = state
        self.dry_run = config.dry_run
        self._filters: list[BaseFilter] = []

        # If no explicit registry given, use the default announce registry
        if registry is None:
            from .filters import FILTER_REGISTRY
            registry = FILTER_REGISTRY
        self._registry = registry
        self._build_chain()

    def _build_chain(self):
        """Instantiate enabled filters in registry order."""
        self._filters = []
        for name, cls in self._registry:
            if self.config.filter_enabled(name):
                cfg = self.config.filter_cfg(name)
                f = cls(config=cfg, state=self.state)
                self._filters.append(f)
                log.info("Filter enabled: %s", name)
            else:
                log.info("Filter disabled: %s", name)

    def rebuild(self, config: RatholeConfig):
        """Rebuild the filter chain after config hot-reload."""
        self.config = config
        self.dry_run = config.dry_run
        self._build_chain()
        log.info("Filter pipeline rebuilt (%d active filters)", len(self._filters))

    def evaluate(self, ctx: PacketContext) -> Verdict:
        """
        Run a packet through the filter chain.

        Returns the final verdict. In dry-run mode, blocking verdicts
        are logged but downgraded to ACCEPT.

        Note: Traffic recording (record_announce, record_real_traffic)
        and verdict counting (record_verdict) are handled by
        PipelineRouter.evaluate() to avoid double-counting — this
        method is called once per pipeline (global + type-specific).
        """
        for f in self._filters:
            verdict = f.evaluate(ctx)
            if verdict.action != Action.ACCEPT:
                if self.dry_run:
                    # Log at INFO only — packet is NOT actually blocked
                    log.info("DRY-RUN would %s: %s", verdict.action.name, verdict)
                    return Verdict(
                        action=Action.ACCEPT,
                        filter_name="dry_run",
                        reason=f"dry-run override of {verdict}",
                        peer_hash=ctx.peer_hash,
                        destination_hash=ctx.destination_hash,
                        hop_count=ctx.hop_count,
                        metadata={"original_action": verdict.action},
                    )
                # Real blocking verdict — log at WARNING
                self._log_verdict(verdict)
                return verdict

        # All filters accepted
        return Verdict(
            action=Action.ACCEPT,
            filter_name="pipeline",
            peer_hash=ctx.peer_hash,
            destination_hash=ctx.destination_hash,
            hop_count=ctx.hop_count,
        )

    def _log_verdict(self, v: Verdict):
        if v.action in (Action.BLACKHOLE, Action.DROP):
            log.warning("%s: %s", v.action.name, v)
        elif v.action in (Action.THROTTLE, Action.QUARANTINE):
            log.warning("%s: %s", v.action.name, v)
        else:
            log.debug("ACCEPT: %s", v)
