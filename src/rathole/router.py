"""
Multi-pipeline router — dispatches packets to type-specific filter chains.

The router runs a global pipeline first (interface rate limiting,
bandwidth caps, packet size checks), then dispatches to a type-specific
pipeline based on the packet type. Each pipeline is independently
configurable.

Flow:
    Inbound packet
      → Global pipeline (all packet types)
      → Type dispatch:
          ANNOUNCE    → Announce pipeline
          LINKREQUEST → Link request pipeline
          DATA/PROOF  → Data pipeline
          Path request → Path request pipeline
      → Final verdict
"""

import time
import logging
from .context import PacketContext, PACKET_ANNOUNCE, PACKET_LINKREQUEST, PACKET_DATA, PACKET_PROOF
from .verdicts import Verdict, Action
from .state import StateTracker
from .config import RatholeConfig
from .pipeline import FilterPipeline
from .events import EventBus, SecurityEvent, EventType, EventSeverity
from .filters import (
    GLOBAL_FILTER_REGISTRY,
    ANNOUNCE_FILTER_REGISTRY,
    PATH_REQUEST_FILTER_REGISTRY,
    LINK_REQUEST_FILTER_REGISTRY,
    DATA_FILTER_REGISTRY,
)

log = logging.getLogger("rathole.router")

# Map blocking verdicts to SecurityEvent types and severities.
_ACTION_EVENT_MAP = {
    Action.DROP:       (EventType.PACKET_DROPPED,      EventSeverity.WARNING),
    Action.THROTTLE:   (EventType.PACKET_THROTTLED,     EventSeverity.NOTICE),
    Action.BLACKHOLE:  (EventType.PACKET_BLACKHOLED,    EventSeverity.ALERT),
    Action.QUARANTINE: (EventType.PACKET_QUARANTINED,   EventSeverity.WARNING),
}


class PipelineRouter:
    """
    Routes packets through the global pipeline, then dispatches to
    a type-specific pipeline. First non-ACCEPT verdict from either
    the global or type-specific pipeline is final.

    All traffic recording (record_announce, record_real_traffic) and
    verdict counting (record_verdict) are centralized here — NOT in
    FilterPipeline — to avoid double-counting across global + type
    pipelines.
    """

    EVENT_THROTTLE_SECONDS = 5.0

    def __init__(self, config: RatholeConfig, state: StateTracker, reputation=None, event_bus=None, blackhole=None):
        self.config = config
        self.state = state
        self._reputation = reputation
        self._event_bus = event_bus
        self._blackhole = blackhole
        self._event_throttle: dict[str, float] = {}

        self._global = FilterPipeline(config, state, registry=GLOBAL_FILTER_REGISTRY)
        self._announce = FilterPipeline(config, state, registry=ANNOUNCE_FILTER_REGISTRY)
        self._path_request = FilterPipeline(config, state, registry=PATH_REQUEST_FILTER_REGISTRY)
        self._link_request = FilterPipeline(config, state, registry=LINK_REQUEST_FILTER_REGISTRY)
        self._data = FilterPipeline(config, state, registry=DATA_FILTER_REGISTRY)

        log.info("PipelineRouter initialized with 5 pipelines")

    def rebuild(self, config: RatholeConfig):
        """Rebuild all pipelines after config hot-reload."""
        self.config = config
        self._global.rebuild(config)
        self._announce.rebuild(config)
        self._path_request.rebuild(config)
        self._link_request.rebuild(config)
        self._data.rebuild(config)
        log.info("PipelineRouter rebuilt")

    def evaluate(self, ctx: PacketContext) -> Verdict:
        """
        Run a packet through the global pipeline, then the
        type-specific pipeline. Returns the final verdict.

        Traffic recording and verdict counting happen ONCE here,
        not inside each FilterPipeline.evaluate() call.
        """
        self.state.record_packet()

        # ── Track unique peers + bytes ────────────────────────
        if ctx.peer_hash and ctx.peer_hash != "unknown":
            self.state.record_peer_seen(ctx.peer_hash)
        if ctx.raw_size > 0:
            self.state.record_bytes(ctx.raw_size)

        # ── Update interface counters ─────────────────────────
        if ctx.interface_name:
            iface = self.state.get_interface(ctx.interface_name)
            iface.packet_count += 1
            iface.packet_count_window += 1
            iface.byte_count += ctx.raw_size
            if ctx.is_announce:
                iface.announce_count += 1
                iface.announce_count_window += 1
            elif ctx.is_link_request:
                iface.link_request_count += 1
            elif ctx.is_path_request:
                iface.path_request_count += 1

        # ── Record traffic type ONCE (moved from FilterPipeline) ──
        if ctx.peer_hash and ctx.peer_hash != "unknown":
            if ctx.is_announce:
                self.state.record_announce(ctx.peer_hash)
            else:
                self.state.record_real_traffic(ctx.peer_hash)

        # ── Blackhole check (hard override, before any pipeline) ──
        if self._blackhole is not None and ctx.peer_hash and ctx.peer_hash != "unknown":
            if self._blackhole.is_blackholed(ctx.peer_hash):
                verdict = Verdict(
                    action=Action.BLACKHOLE,
                    filter_name="blackhole",
                    reason=f"identity {ctx.peer_hash[:16]} is blackholed",
                    peer_hash=ctx.peer_hash,
                    destination_hash=ctx.destination_hash,
                    hop_count=ctx.hop_count,
                )
                self._record_final_verdict(ctx, verdict)
                return verdict

        # ── Global pipeline (all packet types) ───────────────
        verdict = self._global.evaluate(ctx)
        if verdict.action != Action.ACCEPT:
            self._record_final_verdict(ctx, verdict)
            return verdict

        # ── Type-specific dispatch ───────────────────────────
        pipeline = self._select_pipeline(ctx)
        if pipeline is not None:
            verdict = pipeline.evaluate(ctx)
            self._record_final_verdict(ctx, verdict)
            return verdict

        # No type-specific pipeline — accept by default
        verdict = Verdict(
            action=Action.ACCEPT,
            filter_name="router",
            peer_hash=ctx.peer_hash,
            destination_hash=ctx.destination_hash,
            hop_count=ctx.hop_count,
        )
        self._record_final_verdict(ctx, verdict)
        return verdict

    def _record_final_verdict(self, ctx: PacketContext, verdict: Verdict):
        """Record verdict stats, update reputation, and emit events — called exactly once per packet."""
        if verdict.action == Action.ACCEPT:
            self.state.record_verdict("accepted")
        else:
            self.state.record_verdict(verdict.action.name)
            # Track which filter caused the drop
            self.state.record_filter_drop(verdict.filter_name)

        # ── Update reputation if wired ─────────────────────
        # In dry-run mode, pipeline overrides blocking verdicts to ACCEPT
        # but stores the original action in metadata. Use that for reputation
        # so dry-run drops still penalize instead of reward.
        rep_action = verdict.metadata.get("original_action", verdict.action)
        if self._reputation and ctx.peer_hash and ctx.peer_hash != "unknown":
            identity = ctx.peer_hash
            if rep_action == Action.ACCEPT:
                # Accept rewards apply to all packet types — forwarding
                # accepted traffic is a positive signal about the peer/relay.
                self._reputation.record_accept(identity)
            elif ctx.is_announce:
                # Penalties ONLY for announces.  Announces carry a
                # cryptographic signature proving the destination_hash
                # authored the packet — attribution is reliable.
                #
                # For all other packet types (path, link, data, proof),
                # peer_hash is the receiving interface identity, which
                # may be a relay serving many anonymous clients.
                # Penalizing that relay would be false accusation.
                if rep_action == Action.DROP:
                    self._reputation.record_drop(identity, verdict.reason or "")
                elif rep_action == Action.THROTTLE:
                    self._reputation.record_throttle(identity, verdict.reason or "")
                elif rep_action == Action.BLACKHOLE:
                    self._reputation.record_blackhole(identity, verdict.reason or "")

        # ── Emit security event for non-ACCEPT verdicts ────
        # Use original_action so dry-run drops still appear as events.
        if self._event_bus is not None and rep_action != Action.ACCEPT:
            self._emit_verdict_event(ctx, verdict, rep_action)

    def _emit_verdict_event(self, ctx: PacketContext, verdict: Verdict, action: Action):
        """Emit a SecurityEvent for a blocking verdict, with per-filter+peer throttling."""
        event_info = _ACTION_EVENT_MAP.get(action)
        if event_info is None:
            return

        event_type, severity = event_info

        # Throttle: max 1 event per (filter_name, peer_hash) per N seconds
        throttle_key = f"{verdict.filter_name}:{ctx.peer_hash or 'unknown'}"
        now = time.monotonic()
        last = self._event_throttle.get(throttle_key, 0.0)
        if now - last < self.EVENT_THROTTLE_SECONDS:
            return
        self._event_throttle[throttle_key] = now

        # Prune stale throttle entries if dict grows too large
        if len(self._event_throttle) > 10000:
            cutoff = now - self.EVENT_THROTTLE_SECONDS * 2
            self._event_throttle = {
                k: v for k, v in self._event_throttle.items() if v > cutoff
            }

        self._event_bus.emit(SecurityEvent(
            event_type=event_type,
            severity=severity,
            source=verdict.filter_name,
            interface_name=ctx.interface_name,
            identity_hash=ctx.peer_hash or "",
            destination_hash=ctx.destination_hash or "",
            description=verdict.reason or str(verdict),
            details={
                "action": action.name,
                "hop_count": ctx.hop_count,
                "dry_run": "original_action" in verdict.metadata,
            },
        ))

    def _select_pipeline(self, ctx: PacketContext) -> FilterPipeline | None:
        """Select the type-specific pipeline for a packet."""
        if ctx.is_announce:
            return self._announce
        if ctx.is_path_request:
            return self._path_request
        if ctx.is_link_request:
            return self._link_request
        if ctx.is_data or ctx.is_proof or ctx.is_resource:
            return self._data
        return None
