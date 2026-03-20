"""
RNS Transport hook.

This module patches Reticulum's Transport class to intercept inbound
packets before they are processed and re-propagated. It's the bridge
between Rathole's filter pipelines and the live RNS stack.

The hook wraps Transport.inbound() — the single entry point for ALL
inbound packets in RNS (Transport.py line ~1241). This is the only
reliable interception point; announce-specific methods don't exist
as standalone functions in RNS.

Additionally hooks Transport.path_request_handler() for path request
filtering, since path requests are dispatched through a separate code
path in RNS.

Design principles:
- Minimally invasive: wraps two methods at most
- Fail-open: if Rathole crashes, the original methods are called
- Pre-filter on raw packet header to avoid unnecessary parsing cost

IMPORTANT: This hooks into RNS internals. If Reticulum's Transport
API changes, this module may need updating. Pin your RNS version.
"""

import time
import logging
import traceback
from typing import Callable, Optional

from .context import (
    PacketContext,
    PACKET_DATA, PACKET_ANNOUNCE, PACKET_LINKREQUEST, PACKET_PROOF,
    CTX_PATH_RESPONSE,
)
from .router import PipelineRouter

log = logging.getLogger("rathole.hook")

# Module-level references
_original_inbound: Optional[Callable] = None
_original_path_request_handler: Optional[Callable] = None
_router: Optional[PipelineRouter] = None


def _extract_context_from_raw(raw: bytes, receiving_interface) -> PacketContext:
    """
    Extract a PacketContext from raw packet bytes BEFORE RNS unpacks.

    This is a lightweight extraction that reads the packet header to
    get packet_type, hops, and destination_hash. No signature
    verification, no decryption — just header parsing.

    RNS Header format (HEADER_1):
        byte 0: [ifac:1][header_type:1][context_flag:1][prop:1][dest_type:2][packet_type:2]
        byte 1: hops
        bytes 2-17: destination_hash (16 bytes)

    RNS Header format (HEADER_2, transport):
        byte 0: same flags
        byte 1: hops
        bytes 2-17: transport_id (16 bytes)
        bytes 18-33: destination_hash (16 bytes)

    IFAC handling:
        When bit 7 (IFAC flag) is set, a variable-length authentication
        hash is inserted after the 2-byte header, shifting all subsequent
        field offsets. The IFAC size is interface-specific and not encoded
        in the packet, so we cannot reliably extract destination_hash or
        transport_id. In this case we skip hash extraction and let the
        packet pass through with empty hashes. RNS validates and strips
        the IFAC internally before processing.
    """
    kwargs: dict = {
        "timestamp": time.monotonic(),
        "raw_packet": raw,
        "raw_size": len(raw),
    }

    try:
        if len(raw) >= 2:
            flags = raw[0]
            kwargs["hop_count"] = raw[1]

            # Parse flags byte
            ifac_flag = (flags & 0x80) >> 7
            header_type = (flags & 0b01000000) >> 6
            kwargs["packet_type"] = flags & 0b00000011
            kwargs["destination_type"] = (flags >> 2) & 0b00000011

            if ifac_flag:
                # IFAC signature present — field offsets are shifted by a
                # variable-length authentication hash. We cannot reliably
                # extract destination_hash without knowing the IFAC size
                # (which is interface-specific). Skip hash extraction and
                # let the packet pass through with empty hashes.
                # RNS will validate and strip IFAC before processing.
                log.debug("IFAC flag set — skipping hash extraction")
            else:
                # Extract destination hash (non-IFAC packets only)
                if header_type == 0x00 and len(raw) >= 18:
                    # HEADER_1: dest_hash at offset 2
                    kwargs["destination_hash"] = raw[2:18].hex()
                elif header_type == 0x01 and len(raw) >= 34:
                    # HEADER_2: transport_id at 2, dest_hash at 18
                    kwargs["transport_id"] = raw[2:18].hex()
                    kwargs["destination_hash"] = raw[18:34].hex()

            # For ANNOUNCE packets, estimate app_data size from total
            # packet size minus known announce overhead.
            # Announce structure: header + addresses + identity_data + signature + app_data
            # HEADER_1: 2 + 16 + 1 + 32 + 10 + 10 + 64 = 135 bytes overhead
            # HEADER_2: 2 + 32 + 1 + 32 + 10 + 10 + 64 = 151 bytes overhead
            if kwargs.get("packet_type") == PACKET_ANNOUNCE and not ifac_flag:
                if header_type == 0x00:
                    overhead = 135
                else:
                    overhead = 151
                kwargs["announce_app_data_size"] = max(0, len(raw) - overhead)

        # Interface metadata
        if receiving_interface is not None:
            if hasattr(receiving_interface, "name"):
                kwargs["interface_name"] = str(receiving_interface.name)
            if hasattr(receiving_interface, "mode"):
                kwargs["interface_mode"] = receiving_interface.mode
            if hasattr(receiving_interface, "bitrate"):
                kwargs["interface_bitrate"] = receiving_interface.bitrate or 0
            if hasattr(receiving_interface, "ic_burst_active"):
                kwargs["interface_burst_active"] = bool(receiving_interface.ic_burst_active)

            # Peer identity
            peer_hash = ""
            if hasattr(receiving_interface, "remote_identity"):
                ri = receiving_interface.remote_identity
                if ri is not None and hasattr(ri, "hash") and ri.hash:
                    peer_hash = ri.hash.hex() if isinstance(ri.hash, bytes) else str(ri.hash)
            if not peer_hash and hasattr(receiving_interface, "hash") and receiving_interface.hash:
                peer_hash = receiving_interface.hash.hex() if isinstance(receiving_interface.hash, bytes) else str(receiving_interface.hash)
            kwargs["peer_hash"] = peer_hash or "unknown"

        # For ANNOUNCE packets, the destination_hash IS the announcing
        # identity — use it as peer_hash so per-peer tracking is correct
        # in hub topologies where all packets share one interface identity.
        if kwargs.get("packet_type") == PACKET_ANNOUNCE and kwargs.get("destination_hash"):
            kwargs["peer_hash"] = kwargs["destination_hash"]

    except Exception as e:
        log.error("Failed to parse raw packet header: %s", e)

    return PacketContext(**kwargs)


def _hooked_inbound(raw, receiving_interface):
    """
    Replacement for Transport.inbound() that runs Rathole filtering
    on the raw packet before handing off to the original method.
    """
    global _original_inbound, _router

    if _router is None or _original_inbound is None:
        log.error("Rathole hook called but router not initialized — passing through")
        if _original_inbound:
            return _original_inbound(raw, receiving_interface)
        return

    try:
        ctx = _extract_context_from_raw(raw, receiving_interface)
        verdict = _router.evaluate(ctx)

        if verdict.dropped:
            log.debug("Blocked %s from %s: %s", ctx.type_name, ctx.interface_name, verdict)
            return

        # Ensure interface has announce_rate_target before RNS accesses it.
        # Dynamically-added interfaces (e.g. TCPClientInterface via RPC) may
        # lack this attribute, causing Transport.inbound() to crash.
        if receiving_interface is not None and not hasattr(receiving_interface, 'announce_rate_target'):
            receiving_interface.announce_rate_target = None

        return _original_inbound(raw, receiving_interface)

    except Exception as e:
        # FAIL OPEN — never break the network
        log.error(
            "Rathole filter error (failing open): %s\n%s",
            e, traceback.format_exc(),
        )
        try:
            return _original_inbound(raw, receiving_interface)
        except Exception:
            # Original handler also failed — packet is lost but network stays up
            log.debug("Original inbound handler also failed — packet dropped")
            return


def _hooked_path_request_handler(data, packet, *args, **kwargs):
    """
    Replacement for Transport.path_request_handler() that applies
    path request filtering before the original handler.
    """
    global _original_path_request_handler, _router

    if _router is None or _original_path_request_handler is None:
        if _original_path_request_handler:
            return _original_path_request_handler(data, packet, *args, **kwargs)
        return

    try:
        ctx = PacketContext(
            packet_type=PACKET_DATA,
            context_type=CTX_PATH_RESPONSE,
            destination_hash=data.hex() if isinstance(data, bytes) and len(data) >= 16 else "",
            timestamp=time.monotonic(),
        )

        # Add interface info from packet if available
        if packet and hasattr(packet, "receiving_interface") and packet.receiving_interface:
            iface = packet.receiving_interface
            if hasattr(iface, "name"):
                ctx.interface_name = str(iface.name)

        verdict = _router.evaluate(ctx)

        if verdict.dropped:
            log.debug("Blocked path request: %s", verdict)
            return

        return _original_path_request_handler(data, packet, *args, **kwargs)

    except Exception as e:
        log.error("Rathole path request filter error (failing open): %s", e)
        return _original_path_request_handler(data, packet, *args, **kwargs)


def install_hook(router: PipelineRouter):
    """
    Install the Rathole hook into the running RNS Transport.

    Call this AFTER Reticulum has been initialized.
    """
    global _original_inbound, _original_path_request_handler, _router

    try:
        import RNS
        from RNS import Transport as RNSTransport
    except ImportError:
        log.error("RNS not available — cannot install hook")
        raise RuntimeError("Reticulum (rns) package is required")

    _router = router

    # Hook Transport.inbound()
    if hasattr(RNSTransport, "inbound"):
        _original_inbound = RNSTransport.inbound
        RNSTransport.inbound = staticmethod(_hooked_inbound)
        log.info(
            "Rathole hook installed on Transport.inbound() "
            "(dry_run=%s)",
            router.config.dry_run,
        )
    else:
        log.error("Cannot find Transport.inbound — main hook not installed")
        raise RuntimeError("RNS Transport has no 'inbound' method")

    # Hook Transport.path_request_handler() (optional)
    if hasattr(RNSTransport, "path_request_handler"):
        _original_path_request_handler = RNSTransport.path_request_handler
        RNSTransport.path_request_handler = staticmethod(_hooked_path_request_handler)
        log.info("Rathole path request hook installed")
    else:
        log.info("Transport.path_request_handler not found — path request filtering unavailable")


def uninstall_hook():
    """Restore the original RNS Transport methods."""
    global _original_inbound, _original_path_request_handler, _router

    try:
        from RNS import Transport as RNSTransport

        if _original_inbound is not None:
            RNSTransport.inbound = _original_inbound
            log.info("Rathole hook removed from Transport.inbound()")

        if _original_path_request_handler is not None:
            RNSTransport.path_request_handler = _original_path_request_handler
            log.info("Rathole path request hook removed")

    except Exception as e:
        log.error("Failed to uninstall hooks: %s", e)
    finally:
        _original_inbound = None
        _original_path_request_handler = None
        _router = None
