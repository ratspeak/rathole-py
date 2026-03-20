"""Gateway Registry — announce-based gateway discovery for Rathole nodes.

Gateways register by announcing a `rathole.gateway` destination on the
Reticulum network. The announce carries msgpack-encoded app_data with
the gateway's I2P B32 address, name, capabilities, and version.

Discovery still uses HTTP GET against the registry server.
All errors are non-fatal.
"""

import json
import logging
import random
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger("rathole.registry")


@dataclass
class GatewayEntry:
    """A single gateway record from the registry."""
    identity_hash: str
    destination_hash: str = ""
    node_name: str = ""
    b32: str = ""
    capabilities: list[str] = field(default_factory=list)
    rathole_version: str = ""
    node_mode: str = ""
    timestamp: float = 0
    first_seen: float = 0
    announce_count: int = 0
    hops: int = 0
    status: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "GatewayEntry":
        return cls(
            identity_hash=d.get("identity_hash", ""),
            destination_hash=d.get("destination_hash", ""),
            node_name=d.get("node_name", ""),
            b32=d.get("b32", ""),
            capabilities=d.get("capabilities", []),
            rathole_version=d.get("rathole_version", ""),
            node_mode=d.get("node_mode", ""),
            timestamp=d.get("timestamp", 0),
            first_seen=d.get("first_seen", 0),
            announce_count=d.get("announce_count", 0),
            hops=d.get("hops", 0),
            status=d.get("status", ""),
        )


class RegistryClient:
    """Client for the Rathole Gateway Registry.

    Registration: announces a `rathole.gateway` destination on the
    Reticulum network. The registry server catches the announce.

    Discovery: HTTP GET against the registry API.

    All errors are caught and logged — never fatal.
    """

    def __init__(self, config: dict, daemon=None):
        self._daemon = daemon
        self._discovered: list[GatewayEntry] = []
        self._connected_count = 0
        self._last_heartbeat: float = 0
        self._last_discover: float = 0
        self._published = False
        self._gw_destination = None
        self._discover_failures: int = 0
        self._discover_backoff_until: float = 0
        self.refresh_config(config)

    def refresh_config(self, cfg: dict):
        """Update config (called on init and SIGHUP hot-reload)."""
        self._cfg = cfg
        self.enabled = cfg.get("enabled", False)
        self._discover_url = cfg.get("discover_url",
                                     cfg.get("url", "https://registry.ratspeak.org/api/v1")).rstrip("/")
        self._publish = cfg.get("publish", False)
        self._discover = cfg.get("discover", True)
        self._auto_connect = cfg.get("auto_connect", False)
        self._max_auto_connect = cfg.get("max_auto_connect", 5)
        self._announce_interval = cfg.get("announce_interval",
                                          cfg.get("heartbeat_interval", 300))
        self._discover_interval = cfg.get("discover_interval", 600)
        self._node_name = cfg.get("node_name", "")
        self._capabilities = cfg.get("capabilities", [])
        self._exclude_identities = set(cfg.get("exclude_identities", []))
        self._request_timeout = cfg.get("request_timeout", 10)

    # ── Public API ────────────────────────────────────────────────

    def init_gateway_destination(self):
        """Create the rathole.gateway RNS destination for announcing.

        Must be called after Reticulum transport is initialized.
        """
        if not self.enabled or not self._publish:
            return

        identity = self._get_transport_identity()
        if not identity:
            log.warning("Registry: cannot init gateway destination — no transport identity")
            return

        # Always exclude our own identity from auto-connect candidates
        # so the node never tries to connect to itself.
        try:
            self._exclude_identities.add(identity.hexhash)
        except Exception:
            pass

        try:
            import RNS

            self._gw_destination = RNS.Destination(
                identity,
                RNS.Destination.IN,
                RNS.Destination.SINGLE,
                "rathole",
                "gateway",
            )

            # Set app_data callback — RNS calls this each time an announce is sent
            self._gw_destination.set_default_app_data(self._build_app_data)

            log.info("Registry: gateway destination created: %s",
                     RNS.prettyhexrep(self._gw_destination.hash))
        except Exception as e:
            log.error("Registry: failed to create gateway destination: %s", e)
            self._gw_destination = None

    def register(self) -> bool:
        """Announce this gateway on the Reticulum network. Returns True on success.

        Waits for a B32 address before announcing — the announce carries
        the B32 in app_data, so announcing without it is useless. The
        daemon heartbeat loop retries every 30s until B32 is available.
        """
        if not self.enabled or not self._publish:
            return False

        if self._gw_destination is None:
            self.init_gateway_destination()
            if self._gw_destination is None:
                return False

        # Don't announce until we have a B32 — the registry is I2P-only
        # and the app_data would be empty without it.
        from .i2p import get_i2p_b32_from_transport
        b32 = get_i2p_b32_from_transport()
        if not b32:
            log.debug("Registry: B32 not yet available — skipping announce (will retry)")
            return False

        try:
            self._gw_destination.announce()
            self._published = True
            self._last_heartbeat = time.monotonic()
            log.info("Registry: announced gateway (%s)", b32[:16])
            return True
        except Exception as e:
            log.warning("Registry: announce failed: %s", e)
            return False

    def heartbeat(self) -> bool:
        """Re-announce the gateway (same as register)."""
        return self.register()

    def deregister(self) -> bool:
        """Stop announcing. The registry entry will expire after TTL.

        There is no active deregistration — we simply stop announcing
        and the server-side entry expires naturally.
        """
        if self._gw_destination is not None:
            log.info("Registry: stopped announcing (entry will expire after TTL)")
        self._published = False
        self._gw_destination = None
        return True

    def cached_list(self) -> list[dict]:
        """Return the last-discovered gateway list without making an HTTP call."""
        return [e.__dict__ for e in self._discovered]

    def discover(self, exclude: set | None = None) -> list[GatewayEntry]:
        """Query the registry HTTP API for gateways. Returns list of entries."""
        if not self.enabled or not self._discover:
            return []

        # Backoff: skip discover calls during backoff period
        now = time.monotonic()
        if now < self._discover_backoff_until:
            return self._discovered

        exclude_all = set(self._exclude_identities)
        if exclude:
            exclude_all.update(exclude)

        params = "?limit=50"
        if exclude_all:
            params += f"&exclude={','.join(exclude_all)}"

        result = self._http_get(f"/gateways{params}")
        if result is None:
            self._discover_failures += 1
            backoff = min(30 * (2 ** (self._discover_failures - 1)), 600)
            self._discover_backoff_until = time.monotonic() + backoff
            if self._discover_failures == 1:
                log.warning("Registry: discover failed, backing off for %ds", backoff)
            else:
                log.debug("Registry: discover failed (%d consecutive), backing off for %ds",
                          self._discover_failures, backoff)
            return self._discovered

        self._discover_failures = 0
        self._discover_backoff_until = 0

        entries = []
        for gw in result.get("gateways", []):
            entry = GatewayEntry.from_dict(gw)
            entries.append(entry)

        self._discovered = entries
        self._last_discover = time.monotonic()
        log.info("Registry: discovered %d gateways", len(entries))
        return entries

    def auto_connect(self, entries: list[GatewayEntry]) -> int:
        """Connect to top-ranked candidates. Returns count of new connections."""
        if not self._daemon:
            return 0

        # Suppress in dry-run
        if hasattr(self._daemon, 'config') and self._daemon.config.dry_run:
            log.info("Registry: auto-connect suppressed (dry-run)")
            return 0

        # Ensure local identity is excluded even if init_gateway_destination
        # was never called (discover-only nodes that don't publish).
        local_id = self._get_transport_identity()
        if local_id:
            self._exclude_identities.add(local_id.hexhash)

        connected_b32s = self._get_connected_b32s()
        ranked = self._rank_candidates(entries, connected_b32s)

        connected = 0
        for entry in ranked[:self._max_auto_connect]:
            try:
                result = self._daemon._add_i2p_peer_interface(entry.b32)
                if result.get("ok"):
                    connected += 1
                    log.info("Registry: auto-connected to %s (%s)",
                             entry.node_name or entry.identity_hash[:16],
                             entry.b32[:16])
                else:
                    log.debug("Registry: skip %s: %s",
                              entry.b32[:16], result.get("error", ""))
            except Exception as e:
                log.warning("Registry: connect error for %s: %s",
                            entry.b32[:16], e)

        self._connected_count += connected
        return connected

    def status(self) -> dict:
        """Return registry status for RPC."""
        from .i2p import get_i2p_b32_from_transport

        age = 0.0
        if self._last_heartbeat > 0:
            age = time.monotonic() - self._last_heartbeat

        dest_hash = None
        if self._gw_destination:
            try:
                dest_hash = self._gw_destination.hexhash
            except Exception:
                pass

        return {
            "enabled": self.enabled,
            "publish": self._publish,
            "published": self._published,
            "discover": self._discover,
            "auto_connect": self._auto_connect,
            "discovered_count": len(self._discovered),
            "connected_count": self._connected_count,
            "last_heartbeat_age": round(age, 1) if self._last_heartbeat > 0 else None,
            "last_discover_age": round(time.monotonic() - self._last_discover, 1) if self._last_discover > 0 else None,
            "b32": get_i2p_b32_from_transport(),
            "discover_url": self._discover_url,
            "destination_hash": dest_hash,
        }

    # ── Internal ──────────────────────────────────────────────────

    @staticmethod
    def _get_transport_identity():
        """Get RNS.Transport.identity, or None."""
        try:
            import RNS
            if hasattr(RNS.Transport, "identity") and RNS.Transport.identity:
                return RNS.Transport.identity
        except ImportError:
            pass
        return None

    def _build_app_data(self):
        """Build msgpack-encoded app_data for the announce.

        Called by RNS each time an announce is sent. Returns bytes.
        """
        try:
            import msgpack
        except ImportError:
            log.error("Registry: msgpack not installed, cannot build app_data")
            return None

        from .i2p import get_i2p_b32_from_transport, validate_b32_address
        b32 = get_i2p_b32_from_transport()
        if not b32:
            return None

        if not validate_b32_address(b32):
            log.warning("Registry: B32 address %r doesn't match expected format", b32)
            return None

        data = {
            "b32": b32,
        }
        if self._node_name:
            data["name"] = self._node_name
        if self._capabilities:
            data["caps"] = list(self._capabilities)
        data["ver"] = "1.0.0"
        if self._daemon and hasattr(self._daemon, 'config'):
            data["mode"] = self._daemon.config.node_mode

        return msgpack.packb(data, use_bin_type=True)

    def _rank_candidates(self, entries: list[GatewayEntry],
                         connected_b32s: set[str]) -> list[GatewayEntry]:
        """Rank gateway candidates for auto-connect.

        1. Filter out already-connected + excluded identities
        2. Score: online status (+10), uptime bonus (+1 per 24h, cap +5),
           low hops (+3 if <=2), jitter (0-2)
        3. Sort descending, take top max_auto_connect
        """
        now = time.time()
        candidates = []
        for entry in entries:
            if entry.b32 in connected_b32s:
                continue
            if entry.identity_hash in self._exclude_identities:
                continue
            if not entry.b32:
                continue

            score = 0.0
            # Online gateways preferred
            if entry.status == "online":
                score += 10.0
            elif entry.status == "stale":
                score += 3.0
            # Uptime bonus: +1 per 24h since first_seen, capped at +5
            if entry.first_seen > 0:
                uptime_days = (now - entry.first_seen) / 86400
                score += min(uptime_days, 5.0)
            # Low hop count bonus
            if entry.hops <= 2:
                score += 3.0
            score += random.uniform(0, 2.0)
            candidates.append((score, entry))

        candidates.sort(key=lambda x: x[0], reverse=True)
        return [entry for _, entry in candidates[:self._max_auto_connect]]

    def _get_connected_b32s(self) -> set[str]:
        """Get B32 addresses of currently connected I2P interfaces."""
        connected = set()
        try:
            import RNS
            for iface in RNS.Transport.interfaces:
                if "I2P" in type(iface).__name__:
                    peers = getattr(iface, "peers", None)
                    if peers:
                        if isinstance(peers, str):
                            connected.add(peers)
                        elif isinstance(peers, (list, tuple)):
                            connected.update(peers)
                    b32 = getattr(iface, "b32", None)
                    if b32:
                        addr = str(b32)
                        if not addr.endswith(".b32.i2p"):
                            addr += ".b32.i2p"
                        connected.add(addr)
        except Exception:
            pass
        return connected

    def _http_get(self, path: str) -> dict | None:
        """Make an HTTP GET request to the registry. Returns parsed JSON or None."""
        url = self._discover_url + path

        for attempt in range(2):
            try:
                req = urllib.request.Request(url, method="GET")
                with urllib.request.urlopen(req, timeout=self._request_timeout) as resp:
                    resp_data = resp.read().decode()
                    return json.loads(resp_data) if resp_data else {}
            except urllib.error.HTTPError as e:
                if e.code >= 500 and attempt == 0:
                    log.debug("Registry: GET %s → %d, retrying", path, e.code)
                    continue
                log.warning("Registry: GET %s → HTTP %d", path, e.code)
                return None
            except (urllib.error.URLError, OSError, TimeoutError) as e:
                log.warning("Registry: GET %s failed: %s", path, e)
                return None
            except (json.JSONDecodeError, ValueError) as e:
                log.warning("Registry: malformed response from %s: %s", path, e)
                return None

        return None
