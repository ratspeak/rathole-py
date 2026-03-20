"""
Identity reputation engine — per-identity scoring and behavior tracking.

Each identity (peer hash) has a reputation score from 0.0 (untrusted) to
1.0 (fully trusted). The score is updated based on observed behavior:

  - Good behavior (successful links, normal traffic) increases the score
  - Bad behavior (drops, rate limit hits, scan detection) decreases it
  - Score decays toward a neutral baseline without activity

Categories:
  UNKNOWN → Reserved (unused — new identities start as NEUTRAL at 0.5)
  TRUSTED → Consistently good behavior (score >= 0.6)
  NEUTRAL → Default range for new peers (score 0.3–0.6)
  SUSPECT → Confirmed bad behavior patterns (score < 0.3)

Scoring math (default config):
  accept_reward = 0.005, drop_penalty = 0.015 → 3:1 ratio
  1 drop = 3 accepts to recover
  A 95% clean node gains ~+0.40 per 100 packets → reaches TRUSTED quickly

Higher reputation → larger rate limit buckets, more lenient filtering.
Lower reputation  → stricter filtering, potential auto-blackhole.
"""

import time
import logging
from enum import Enum, auto
from dataclasses import dataclass, field
from collections import deque
from threading import RLock

log = logging.getLogger("rathole.reputation")


class ReputationCategory(Enum):
    UNKNOWN = auto()
    TRUSTED = auto()    # >= 0.6
    NEUTRAL = auto()    # 0.3–0.6
    SUSPECT = auto()    # < 0.3


@dataclass
class ReputationEvent:
    """A single reputation-affecting event."""
    timestamp: float
    delta: float        # Positive = good, negative = bad
    reason: str = ""


@dataclass
class IdentityReputation:
    """Reputation state for a single identity."""
    identity_hash: str
    score: float = 0.5           # Start neutral
    first_seen: float = 0.0
    last_seen: float = 0.0
    last_decay: float = 0.0

    # Counters
    total_accepts: int = 0
    total_drops: int = 0
    total_throttles: int = 0
    total_blackhole_events: int = 0

    # Recent history (bounded)
    history: deque = field(default_factory=lambda: deque(maxlen=100))

    # Manual overrides
    pinned: bool = False         # If True, score is locked by operator
    pinned_score: float = 0.0

    def __post_init__(self):
        now = time.monotonic()
        if self.first_seen == 0.0:
            self.first_seen = now
        if self.last_seen == 0.0:
            self.last_seen = now
        if self.last_decay == 0.0:
            self.last_decay = now

    @property
    def effective_score(self) -> float:
        """Score respecting manual pin."""
        if self.pinned:
            return self.pinned_score
        return self.score

    @property
    def category(self) -> ReputationCategory:
        s = self.effective_score
        if s >= 0.6:
            return ReputationCategory.TRUSTED
        if s >= 0.3:
            return ReputationCategory.NEUTRAL
        return ReputationCategory.SUSPECT


class ReputationEngine:
    """
    Manages reputation scores for all tracked identities.

    Config keys:
      - neutral_score: Starting score for new identities (default 0.5)
      - accept_reward: Score increase per accepted packet (default 0.005)
      - drop_penalty: Score decrease per dropped packet (default 0.015)
      - throttle_penalty: Score decrease per throttled packet (default 0.01)
      - blackhole_penalty: Score decrease per blackhole verdict (default 0.1)
      - scan_penalty: Score decrease per scan detection (default 0.15)
      - decay_rate: Rate of decay toward neutral per hour (default 0.02)
      - auto_blackhole: Whether to auto-blackhole malicious identities (default false)
      - auto_blackhole_score: Score below which to auto-blackhole (default 0.15)
    """

    def __init__(self, config: dict):
        self._config = config
        self._neutral = config.get("neutral_score", 0.5)
        self._accept_reward = config.get("accept_reward", 0.005)
        self._drop_penalty = config.get("drop_penalty", 0.015)
        self._throttle_penalty = config.get("throttle_penalty", 0.01)
        self._blackhole_penalty = config.get("blackhole_penalty", 0.1)
        self._scan_penalty = config.get("scan_penalty", 0.15)
        self._decay_rate = config.get("decay_rate", 0.02)
        self._auto_blackhole = config.get("auto_blackhole", False)
        self._auto_blackhole_score = config.get("auto_blackhole_score", 0.15)

        self._lock = RLock()
        self._identities: dict[str, IdentityReputation] = {}

        # Category transition tracking (e.g. "TRUSTED→NEUTRAL" → count)
        self._category_transitions: dict[str, int] = {}
        self._auto_blackhole_count: int = 0

    def get(self, identity_hash: str) -> IdentityReputation:
        """Get or create reputation for an identity."""
        with self._lock:
            if identity_hash not in self._identities:
                self._identities[identity_hash] = IdentityReputation(
                    identity_hash=identity_hash,
                    score=self._neutral,
                )
            rep = self._identities[identity_hash]
            rep.last_seen = time.monotonic()
            return rep

    def record_accept(self, identity_hash: str):
        """Record a packet acceptance for an identity."""
        with self._lock:
            rep = self.get(identity_hash)
            if rep.pinned:
                return
            rep.total_accepts += 1
            self._apply_delta(rep, self._accept_reward, "accepted")

    def record_drop(self, identity_hash: str, reason: str = ""):
        """Record a packet drop for an identity."""
        with self._lock:
            rep = self.get(identity_hash)
            if rep.pinned:
                return
            rep.total_drops += 1
            self._apply_delta(rep, -self._drop_penalty, f"dropped: {reason}")

    def record_throttle(self, identity_hash: str, reason: str = ""):
        """Record a throttle verdict for an identity."""
        with self._lock:
            rep = self.get(identity_hash)
            if rep.pinned:
                return
            rep.total_throttles += 1
            self._apply_delta(rep, -self._throttle_penalty, f"throttled: {reason}")

    def record_blackhole(self, identity_hash: str, reason: str = ""):
        """Record a blackhole verdict for an identity."""
        with self._lock:
            rep = self.get(identity_hash)
            if rep.pinned:
                return
            rep.total_blackhole_events += 1
            self._apply_delta(rep, -self._blackhole_penalty, f"blackholed: {reason}")

    def record_scan(self, identity_hash: str):
        """Record a scan detection (severe penalty)."""
        with self._lock:
            rep = self.get(identity_hash)
            if rep.pinned:
                return
            self._apply_delta(rep, -self._scan_penalty, "scan detected")

    def pin(self, identity_hash: str, score: float):
        """Pin an identity to a fixed score (operator override)."""
        with self._lock:
            rep = self.get(identity_hash)
            rep.pinned = True
            rep.pinned_score = max(0.0, min(1.0, score))
            log.info("Pinned %s to score %.2f", identity_hash[:16], rep.pinned_score)

    def unpin(self, identity_hash: str):
        """Remove operator pin from an identity."""
        with self._lock:
            rep = self.get(identity_hash)
            rep.pinned = False
            log.info("Unpinned %s (current score %.2f)", identity_hash[:16], rep.score)

    def decay_all(self):
        """Apply time-based decay toward neutral for all identities."""
        with self._lock:
            now = time.monotonic()
            for rep in self._identities.values():
                if rep.pinned:
                    continue
                elapsed_hours = (now - rep.last_decay) / 3600.0
                if elapsed_hours < 0.01:
                    continue
                # Move score toward neutral by decay_rate * elapsed_hours
                diff = self._neutral - rep.score
                adjustment = diff * min(1.0, self._decay_rate * elapsed_hours)
                rep.score = max(0.0, min(1.0, rep.score + adjustment))
                rep.last_decay = now

    def should_auto_blackhole(self, identity_hash: str) -> bool:
        """Check if an identity should be auto-blackholed."""
        with self._lock:
            if not self._auto_blackhole:
                return False
            rep = self.get(identity_hash)
            return rep.effective_score < self._auto_blackhole_score

    def rate_limit_multiplier(self, identity_hash: str) -> float:
        """
        Get rate limit multiplier based on reputation.

        TRUSTED peers get headroom (1.5x–3x).
        NEUTRAL peers get baseline (0.5x–1.5x).
        SUSPECT peers get minimum (0.25x–0.5x).
        """
        with self._lock:
            rep = self.get(identity_hash)
            s = rep.effective_score
            if s >= 0.6:
                return 1.5 + (s - 0.6) * (1.5 / 0.4)  # 1.5 to 3.0 (TRUSTED)
            if s >= 0.3:
                return 0.5 + (s - 0.3) * (1.0 / 0.3)   # 0.5 to 1.5 (NEUTRAL)
            return max(0.25, s / 0.3 * 0.5)              # 0.25 to 0.5 (SUSPECT)

    def category_transitions(self) -> dict[str, int]:
        """Return category transition counts (e.g. "TRUSTED→NEUTRAL": 3)."""
        with self._lock:
            return dict(self._category_transitions)

    def reputation_distribution(self) -> dict[str, int]:
        """Count identities per reputation category."""
        with self._lock:
            dist: dict[str, int] = {c.name: 0 for c in ReputationCategory}
            for rep in self._identities.values():
                dist[rep.category.name] += 1
            return dist

    def record_auto_blackhole(self):
        """Increment auto-blackhole counter (called from daemon)."""
        with self._lock:
            self._auto_blackhole_count += 1

    def refresh_config(self, config: dict):
        """Re-read cached config values after a live config change.

        Does NOT touch _identities or _category_transitions (runtime state).
        """
        with self._lock:
            self._config = config
            self._accept_reward = config.get("accept_reward", 0.005)
            self._drop_penalty = config.get("drop_penalty", 0.015)
            self._throttle_penalty = config.get("throttle_penalty", 0.01)
            self._blackhole_penalty = config.get("blackhole_penalty", 0.1)
            self._scan_penalty = config.get("scan_penalty", 0.15)
            self._decay_rate = config.get("decay_rate", 0.02)
            self._auto_blackhole = config.get("auto_blackhole", False)
            self._auto_blackhole_score = config.get("auto_blackhole_score", 0.15)

    def identities_snapshot(self) -> list[tuple[str, "IdentityReputation"]]:
        """Return a snapshot of all identities for safe iteration outside the lock."""
        with self._lock:
            return list(self._identities.items())

    def summary(self) -> list[dict]:
        """Summary of all tracked identities for control interface."""
        with self._lock:
            return [
                {
                    "identity": rep.identity_hash[:16],
                    "score": round(rep.effective_score, 3),
                    "category": rep.category.name,
                    "accepts": rep.total_accepts,
                    "drops": rep.total_drops,
                    "throttles": rep.total_throttles,
                    "pinned": rep.pinned,
                }
                for rep in self._identities.values()
            ]

    def prune_stale(self, max_age_hours: float = 24.0):
        """Remove identities not seen in max_age_hours with neutral-ish scores."""
        with self._lock:
            now = time.monotonic()
            cutoff = now - (max_age_hours * 3600)
            stale = [
                h for h, rep in self._identities.items()
                if rep.last_seen < cutoff
                and not rep.pinned
                and 0.4 <= rep.score <= 0.6
            ]
            for h in stale:
                del self._identities[h]
            if stale:
                log.debug("Pruned %d stale reputation entries", len(stale))

    def snapshot(self) -> dict:
        """Serializable snapshot for persistence."""
        with self._lock:
            return {
                "_meta": {
                    "category_transitions": dict(self._category_transitions),
                    "auto_blackhole_count": self._auto_blackhole_count,
                    "distribution": self.reputation_distribution(),
                },
                "identities": {
                    h: {
                        "score": rep.score,
                        "first_seen": rep.first_seen,
                        "total_accepts": rep.total_accepts,
                        "total_drops": rep.total_drops,
                        "total_throttles": rep.total_throttles,
                        "total_blackhole_events": rep.total_blackhole_events,
                        "pinned": rep.pinned,
                        "pinned_score": rep.pinned_score,
                    }
                    for h, rep in self._identities.items()
                },
            }

    def load_snapshot(self, data: dict):
        """Restore reputation state from a saved snapshot."""
        identities = data.get("identities", {})
        with self._lock:
            for h, info in identities.items():
                rep = IdentityReputation(
                    identity_hash=h,
                    score=info.get("score", self._neutral),
                    total_accepts=info.get("total_accepts", 0),
                    total_drops=info.get("total_drops", 0),
                    total_throttles=info.get("total_throttles", 0),
                    total_blackhole_events=info.get("total_blackhole_events", 0),
                    pinned=info.get("pinned", False),
                    pinned_score=info.get("pinned_score", 0.0),
                )
                self._identities[h] = rep
            meta = data.get("_meta", {})
            self._category_transitions = meta.get("category_transitions", {})
            self._auto_blackhole_count = meta.get("auto_blackhole_count", 0)
        log.info("Loaded %d identity reputations from snapshot", len(identities))

    def _apply_delta(self, rep: IdentityReputation, delta: float, reason: str):
        """Apply a score change, clamping to [0, 1]."""
        old = rep.score
        old_category = rep.category
        rep.score = max(0.0, min(1.0, rep.score + delta))
        rep.history.append(ReputationEvent(
            timestamp=time.monotonic(),
            delta=delta,
            reason=reason,
        ))

        # Track category transitions
        new_category = rep.category
        if old_category != new_category:
            key = f"{old_category.name}\u2192{new_category.name}"
            self._category_transitions[key] = self._category_transitions.get(key, 0) + 1

        if rep.category == ReputationCategory.SUSPECT and old >= 0.3:
            log.warning(
                "Identity %s became SUSPECT (score %.3f \u2192 %.3f): %s",
                rep.identity_hash[:16], old, rep.score, reason,
            )
