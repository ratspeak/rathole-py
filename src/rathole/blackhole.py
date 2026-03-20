"""
RNS Blackhole integration — bidirectional sync with Transport.blackholed_identities.

When enabled, Rathole can:
  1. Read the RNS blackhole list on startup
  2. Periodically sync (every 60s by default)
  3. Add identities to the RNS blackhole via Transport.blackhole_identity()
  4. Remove identities from the blackhole
  5. Auto-blackhole identities below a reputation threshold (OFF by default)

The RNS blackhole persists to disk and propagates across the network,
so auto-blackhole is a powerful action that requires explicit opt-in.
"""

import time
import logging
from threading import Lock

log = logging.getLogger("rathole.blackhole")


class BlackholeManager:
    """
    Manages the local blackhole list and syncs with RNS Transport.

    Config keys:
      - sync_interval: Seconds between RNS syncs (default 60)
      - auto_blackhole: Auto-blackhole from reputation (default false)
      - auto_blackhole_score: Score threshold (default 0.15)

    The manager maintains its own set so it works even without
    a live RNS Transport (for testing and dry-run).
    """

    def __init__(self, config: dict):
        self._config = config
        self._sync_interval = config.get("sync_interval", 60)
        self._auto_enabled = config.get("auto_blackhole", False)
        self._auto_score = config.get("auto_blackhole_score", 0.15)

        self._lock = Lock()
        self._blackholed: set[str] = set()  # identity hashes
        self._last_sync: float = 0.0
        self._rns_transport = None  # Set via attach_transport()

        # Track manual vs auto entries for auditability
        self._manual_entries: set[str] = set()
        self._auto_entries: set[str] = set()
        self._reasons: dict[str, str] = {}  # identity -> reason

    def attach_transport(self, transport):
        """Attach a live RNS Transport module for real blackhole operations."""
        self._rns_transport = transport
        self._sync_from_rns()
        log.info("Attached RNS Transport for blackhole sync")

    def is_blackholed(self, identity_hash: str) -> bool:
        """Check if an identity is blackholed."""
        with self._lock:
            return identity_hash in self._blackholed

    def add(self, identity_hash: str, reason: str = "", auto: bool = False) -> bool:
        """
        Add an identity to the blackhole.

        Returns True if newly added, False if already blackholed.
        """
        with self._lock:
            if identity_hash in self._blackholed:
                return False
            self._blackholed.add(identity_hash)
            if reason:
                self._reasons[identity_hash] = reason
            if auto:
                self._auto_entries.add(identity_hash)
            else:
                self._manual_entries.add(identity_hash)

        # Push to RNS if connected
        self._push_to_rns(identity_hash)

        source = "auto" if auto else "manual"
        log.warning(
            "BLACKHOLED %s (%s): %s",
            identity_hash[:16], source, reason or "no reason given",
        )
        return True

    def remove(self, identity_hash: str) -> bool:
        """
        Remove an identity from the blackhole.

        Returns True if removed, False if not blackholed.
        """
        with self._lock:
            if identity_hash not in self._blackholed:
                return False
            self._blackholed.discard(identity_hash)
            self._manual_entries.discard(identity_hash)
            self._auto_entries.discard(identity_hash)
            self._reasons.pop(identity_hash, None)

        # Remove from RNS if connected
        self._remove_from_rns(identity_hash)

        log.info("Removed %s from blackhole", identity_hash[:16])
        return True

    def list_all(self) -> list[dict]:
        """List all blackholed identities with source info and reason."""
        with self._lock:
            return [
                {
                    "identity": h,
                    "source": "auto" if h in self._auto_entries
                              else "manual" if h in self._manual_entries
                              else "rns",
                    "reason": self._reasons.get(h, ""),
                }
                for h in sorted(self._blackholed)
            ]

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._blackholed)

    @property
    def auto_enabled(self) -> bool:
        return self._auto_enabled

    def periodic_sync(self):
        """Call periodically to sync with RNS Transport."""
        now = time.monotonic()
        if now - self._last_sync < self._sync_interval:
            return
        self._sync_from_rns()
        self._last_sync = now

    def snapshot(self) -> dict:
        """Serializable snapshot for persistence."""
        with self._lock:
            return {
                "blackholed": sorted(self._blackholed),
                "manual": sorted(self._manual_entries),
                "auto": sorted(self._auto_entries),
            }

    def load_snapshot(self, data: dict):
        """Restore from a saved snapshot."""
        with self._lock:
            self._blackholed = set(data.get("blackholed", []))
            self._manual_entries = set(data.get("manual", []))
            self._auto_entries = set(data.get("auto", []))
        log.info("Loaded %d blackholed identities from snapshot", len(self._blackholed))

    def refresh_config(self, config: dict):
        """Re-read cached config values after a live config change."""
        self._config = config
        self._sync_interval = config.get("sync_interval", 60)
        self._auto_enabled = config.get("auto_blackhole", False)
        self._auto_score = config.get("auto_blackhole_score", 0.15)

    # ── RNS Transport operations ─────────────────────────────────

    def _sync_from_rns(self):
        """Pull blackhole list from RNS Transport."""
        if self._rns_transport is None:
            return
        try:
            rns_list = getattr(self._rns_transport, "blackholed_identities", None)
            if rns_list is None:
                return
            with self._lock:
                # Add any RNS entries we don't have
                for identity_hash in rns_list:
                    h = identity_hash.hex() if isinstance(identity_hash, bytes) else str(identity_hash)
                    if h not in self._blackholed:
                        self._blackholed.add(h)
                        log.debug("Synced blackhole entry from RNS: %s", h[:16])
        except Exception as e:
            log.error("Failed to sync from RNS blackhole: %s", e)

    def _push_to_rns(self, identity_hash: str):
        """Push a blackhole entry to RNS Transport."""
        if self._rns_transport is None:
            return
        try:
            blackhole_fn = getattr(self._rns_transport, "blackhole_identity", None)
            if blackhole_fn is not None:
                # RNS expects bytes for identity hash
                h_bytes = bytes.fromhex(identity_hash)
                blackhole_fn(h_bytes)
                log.debug("Pushed blackhole to RNS: %s", identity_hash[:16])
        except Exception as e:
            log.error("Failed to push blackhole to RNS: %s", e)

    def _remove_from_rns(self, identity_hash: str):
        """Remove a blackhole entry from RNS Transport."""
        if self._rns_transport is None:
            return
        try:
            unblackhole_fn = getattr(self._rns_transport, "unblackhole_identity", None)
            if unblackhole_fn is not None:
                h_bytes = bytes.fromhex(identity_hash)
                unblackhole_fn(h_bytes)
                log.debug("Removed blackhole from RNS: %s", identity_hash[:16])
        except Exception as e:
            log.error("Failed to remove blackhole from RNS: %s", e)
