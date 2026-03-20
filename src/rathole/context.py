"""
Generalized packet context for all Reticulum packet types.

Every inbound packet is wrapped in a PacketContext before entering the
filter pipeline. Fields not applicable to a given packet type are set
to their zero values (0, "", None, b"").

This module also provides the backward-compatible AnnounceContext alias
so existing filters continue to work unchanged.

RNS Packet type constants (from RNS.Packet):
    DATA         = 0x00
    ANNOUNCE     = 0x01
    LINKREQUEST  = 0x02
    PROOF        = 0x03

RNS Transport type constants (from RNS.Transport):
    BROADCAST    = 0x00
    TRANSPORT    = 0x01
    RELAY        = 0x02
    TUNNEL       = 0x03

RNS Destination type constants (from RNS.Destination):
    SINGLE       = 0x00
    GROUP        = 0x01
    PLAIN        = 0x02
    LINK         = 0x03

RNS Packet context constants (from RNS.Packet):
    NONE         = 0x00
    RESOURCE     = 0x01
    RESOURCE_ADV = 0x02
    ...
    CACHE_REQUEST = 0x08
    REQUEST      = 0x09
    RESPONSE     = 0x0A
    PATH_RESPONSE = 0x0B
    CHANNEL      = 0x0E
    KEEPALIVE    = 0xFA
    LINKIDENTIFY = 0xFB
    LINKCLOSE    = 0xFC
    LINKPROOF    = 0xFD
    LRPROOF      = 0xFF
"""

import time


# ── Packet type constants (mirror RNS values) ───────────────────

PACKET_DATA        = 0x00
PACKET_ANNOUNCE    = 0x01
PACKET_LINKREQUEST = 0x02
PACKET_PROOF       = 0x03

TRANSPORT_BROADCAST = 0x00
TRANSPORT_TRANSPORT = 0x01
TRANSPORT_RELAY     = 0x02
TRANSPORT_TUNNEL    = 0x03

DEST_SINGLE = 0x00
DEST_GROUP  = 0x01
DEST_PLAIN  = 0x02
DEST_LINK   = 0x03

# Context subtypes (subset — the ones relevant for filtering)
CTX_NONE          = 0x00
CTX_RESOURCE      = 0x01
CTX_RESOURCE_ADV  = 0x02
CTX_RESOURCE_REQ  = 0x03
CTX_CACHE_REQUEST = 0x08
CTX_REQUEST       = 0x09
CTX_RESPONSE      = 0x0A
CTX_PATH_RESPONSE = 0x0B
CTX_CHANNEL       = 0x0E
CTX_KEEPALIVE     = 0xFA
CTX_LINKIDENTIFY  = 0xFB
CTX_LINKCLOSE     = 0xFC
CTX_LINKPROOF     = 0xFD
CTX_LRPROOF       = 0xFF


class PacketContext:
    """
    All the information a filter needs about an inbound packet.

    Populated by the RNS hook before the pipeline runs. Uses __slots__
    for memory efficiency since one is created per inbound packet.

    Fields not applicable to a given packet type default to their zero
    values. For example, announce_app_data_size is only meaningful for
    ANNOUNCE packets and will be 0 for all others.
    """

    __slots__ = (
        # ── Packet identity ──────────────────────────────────────
        "packet_hash",          # SHA-256 hash of the packet (hex str)
        "destination_hash",     # 16-byte destination address (hex str)
        "destination_type",     # SINGLE/GROUP/PLAIN/LINK (int)
        "packet_type",          # DATA/ANNOUNCE/LINKREQUEST/PROOF (int)
        "context_type",         # Packet context subtype (int)
        "transport_type",       # BROADCAST/TRANSPORT/RELAY/TUNNEL (int)

        # ── Routing ──────────────────────────────────────────────
        "hop_count",            # Current hop count (int)
        "transport_id",         # Transport ID if routed (hex str or "")

        # ── Radio metadata ───────────────────────────────────────
        "rssi",                 # Received signal strength (float or None)
        "snr",                  # Signal-to-noise ratio (float or None)
        "quality",              # Quality metric (float or None)

        # ── Interface ────────────────────────────────────────────
        "interface_name",       # Name of receiving interface (str)
        "interface_mode",       # Interface mode constant (int)
        "interface_bitrate",    # Interface bitrate in bps (int)
        "interface_burst_active",  # True if ingress control burst active

        # ── Timing ───────────────────────────────────────────────
        "timestamp",            # time.monotonic() at receipt

        # ── Size ─────────────────────────────────────────────────
        "raw_packet",           # Raw packet bytes
        "raw_size",             # len(raw_packet)

        # ── Announce-specific ────────────────────────────────────
        "peer_hash",            # Originating peer identity hash (hex str)
        "announce_app_data_size",  # Size of announce app_data payload

        # ── Link-specific ────────────────────────────────────────
        "link_id",              # Link ID for link packets (hex str or "")
    )

    def __init__(
        self,
        *,
        # Required for all packets
        destination_hash: str = "",
        packet_type: int = PACKET_DATA,
        hop_count: int = 0,
        timestamp: float = 0.0,
        # Common optional
        packet_hash: str = "",
        destination_type: int = DEST_SINGLE,
        context_type: int = CTX_NONE,
        transport_type: int = TRANSPORT_BROADCAST,
        transport_id: str = "",
        # Radio
        rssi: float | None = None,
        snr: float | None = None,
        quality: float | None = None,
        # Interface
        interface_name: str = "",
        interface_mode: int = 0,
        interface_bitrate: int = 0,
        interface_burst_active: bool = False,
        # Size
        raw_packet: bytes = b"",
        raw_size: int = 0,
        # Announce-specific
        peer_hash: str = "",
        announce_app_data_size: int = 0,
        # Link-specific
        link_id: str = "",
    ):
        self.packet_hash = packet_hash
        self.destination_hash = destination_hash
        self.destination_type = destination_type
        self.packet_type = packet_type
        self.context_type = context_type
        self.transport_type = transport_type

        self.hop_count = hop_count
        self.transport_id = transport_id

        self.rssi = rssi
        self.snr = snr
        self.quality = quality

        self.interface_name = interface_name
        self.interface_mode = interface_mode
        self.interface_bitrate = interface_bitrate
        self.interface_burst_active = interface_burst_active

        self.timestamp = timestamp or time.monotonic()

        self.raw_packet = raw_packet
        self.raw_size = raw_size or len(raw_packet)

        self.peer_hash = peer_hash
        self.announce_app_data_size = announce_app_data_size

        self.link_id = link_id

    @property
    def is_announce(self) -> bool:
        return self.packet_type == PACKET_ANNOUNCE

    @property
    def is_link_request(self) -> bool:
        return self.packet_type == PACKET_LINKREQUEST

    @property
    def is_data(self) -> bool:
        return self.packet_type == PACKET_DATA

    @property
    def is_proof(self) -> bool:
        return self.packet_type == PACKET_PROOF

    @property
    def is_path_request(self) -> bool:
        """Path requests are DATA packets with PATH_RESPONSE context."""
        # Note: actual path requests arrive via a separate handler in RNS,
        # but when synthesized as PacketContext they use this marker.
        return self.context_type == CTX_PATH_RESPONSE

    @property
    def is_resource(self) -> bool:
        return self.context_type in (
            CTX_RESOURCE, CTX_RESOURCE_ADV, CTX_RESOURCE_REQ,
        )

    @property
    def is_cache_request(self) -> bool:
        return self.context_type == CTX_CACHE_REQUEST

    @property
    def type_name(self) -> str:
        """Human-readable packet type name."""
        names = {
            PACKET_DATA: "DATA",
            PACKET_ANNOUNCE: "ANNOUNCE",
            PACKET_LINKREQUEST: "LINKREQUEST",
            PACKET_PROOF: "PROOF",
        }
        return names.get(self.packet_type, f"UNKNOWN(0x{self.packet_type:02x})")


# ── Backward compatibility ───────────────────────────────────────
#
# AnnounceContext was the original context type in v0.1. We keep it
# as a factory function that creates a PacketContext with packet_type
# set to ANNOUNCE. Existing filters that accept AnnounceContext will
# receive a PacketContext instead — the interface is a superset.

def AnnounceContext(
    destination_hash: str,
    peer_hash: str,
    hop_count: int,
    raw_announce: bytes = b"",
    interface_name: str = "",
    timestamp: float = 0.0,
) -> "PacketContext":
    """
    Backward-compatible factory for announce-type PacketContext.

    Existing filters and tests that construct AnnounceContext will
    continue to work unchanged. Returns a PacketContext with
    packet_type=PACKET_ANNOUNCE.
    """
    return PacketContext(
        destination_hash=destination_hash,
        peer_hash=peer_hash,
        hop_count=hop_count,
        packet_type=PACKET_ANNOUNCE,
        raw_packet=raw_announce,
        raw_size=len(raw_announce),
        interface_name=interface_name,
        timestamp=timestamp,
    )
