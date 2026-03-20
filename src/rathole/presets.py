"""
Config presets — mode-scoped configurations for gateway and client deployments.

Presets provide complete filter configurations tuned for different
deployment profiles. They can be applied via CLI, TUI, or setup wizard.

Gateway presets (public transport hub, hundreds of peers):
  - observe:    Learn traffic patterns before blocking anything
  - balanced:   Active defense with fair limits (recommended)
  - fortress:   Zero tolerance, maximum protection

Client presets (contributing transport node, local mesh):
  - relaxed:    Minimal interference, observe first
  - standard:   Good defaults for most users (recommended)
  - strict:     Tight security for cautious operators

Cross-mode:
  - lora:       Ultra-tight bandwidth caps for LoRa links
"""

import copy
import logging

from .config import DEFAULT_CONFIG, _deep_merge

log = logging.getLogger("rathole.presets")


# ── Gateway Presets ──────────────────────────────────────────────

_OBSERVE: dict = {
    "general": {
        "node_mode": "gateway",
        "dry_run": True,  # Observe for 48h before blocking
    },
    "filters": {
        "allowdeny": {"enabled": True},
        "hop_ceiling": {"enabled": True, "max_hops": 64},
        "rate_limit": {"enabled": True, "refill_rate": 1.0, "burst": 30, "overflow_action": "drop"},
        "churn": {"enabled": False, "suppress_threshold": 20.0, "reuse_threshold": 5.0, "decay_interval": 120},
        "anomaly": {"enabled": True, "anomaly_action": "flag", "max_announce_ratio": 100.0, "min_packets": 100},
        "interface_rate": {"enabled": True, "refill_rate": 50.0, "burst": 200},
        "bandwidth": {"enabled": True, "bytes_per_second": 2_000_000, "burst_bytes": 4_000_000},
        "packet_size": {"enabled": True, "max_bytes": 600},
        "announce_size": {"enabled": True, "max_app_data_bytes": 500},
        "path_request": {"enabled": True, "max_per_minute": 100, "scan_threshold": 50, "scan_window": 60},
        "link_request": {"enabled": True, "refill_rate": 2.0, "burst": 20, "max_pending_per_interface": 100},
        "resource_guard": {"enabled": True, "max_resource_bytes": 33_554_432, "max_active_per_interface": 20},
    },
    "reputation": {"enabled": True, "auto_blackhole": False},
    "adaptive": {"enabled": True, "learning_hours": 24},
    "correlator": {"enabled": True, "sybil_threshold": 100, "response_mode": "alert", "grace_period": 600},
    "metrics": {"enabled": True},
    "eventstore": {"enabled": True},
    "registry": {"enabled": True, "publish": True, "discover": True, "auto_connect": False},
}

_BALANCED: dict = {
    "general": {
        "node_mode": "gateway",
        "dry_run": False,
    },
    "filters": {
        "allowdeny": {"enabled": True},
        "hop_ceiling": {"enabled": True, "max_hops": 64},
        "rate_limit": {"enabled": True, "refill_rate": 1.0, "burst": 30},
        "churn": {"enabled": False, "suppress_threshold": 15.0, "reuse_threshold": 3.0, "decay_interval": 120},
        "anomaly": {"enabled": True, "anomaly_action": "throttle", "max_announce_ratio": 75.0, "min_packets": 50},
        "interface_rate": {"enabled": True, "refill_rate": 30.0, "burst": 100},
        "bandwidth": {"enabled": True, "bytes_per_second": 1_500_000, "burst_bytes": 3_000_000},
        "packet_size": {"enabled": True, "max_bytes": 600},
        "announce_size": {"enabled": True, "max_app_data_bytes": 500},
        "path_request": {"enabled": True, "max_per_minute": 60, "scan_threshold": 30, "scan_window": 60},
        "link_request": {"enabled": True, "refill_rate": 2.0, "burst": 20, "max_pending_per_interface": 100},
        "resource_guard": {"enabled": True, "max_resource_bytes": 33_554_432, "max_active_per_interface": 20},
    },
    "reputation": {"enabled": True, "auto_blackhole": False},
    "adaptive": {"enabled": True, "learning_hours": 12},
    "correlator": {"enabled": True, "sybil_threshold": 50, "response_mode": "alert", "grace_period": 300},
    "metrics": {"enabled": True},
    "eventstore": {"enabled": True},
    "registry": {"enabled": True, "publish": True, "discover": True, "auto_connect": False},
}

_FORTRESS: dict = {
    "general": {
        "node_mode": "gateway",
        "dry_run": False,
    },
    "filters": {
        "allowdeny": {"enabled": True},
        "hop_ceiling": {"enabled": True, "max_hops": 32},
        "rate_limit": {"enabled": True, "refill_rate": 0.3, "burst": 10, "overflow_action": "drop"},
        "churn": {"enabled": True, "suppress_threshold": 8.0, "reuse_threshold": 2.0, "penalty_per_announce": 2.0},
        "anomaly": {"enabled": True, "anomaly_action": "drop", "max_announce_ratio": 20.0, "min_packets": 25},
        "interface_rate": {"enabled": True, "refill_rate": 20.0, "burst": 50, "overflow_action": "drop"},
        "bandwidth": {"enabled": True, "bytes_per_second": 1_000_000, "burst_bytes": 2_000_000},
        "packet_size": {"enabled": True, "max_bytes": 500},
        "announce_size": {"enabled": True, "max_app_data_bytes": 300},
        "path_request": {"enabled": True, "max_per_minute": 30, "scan_threshold": 15, "scan_window": 30},
        "link_request": {"enabled": True, "refill_rate": 1.0, "burst": 10, "max_pending_per_interface": 50},
        "resource_guard": {"enabled": True, "max_resource_bytes": 16_777_216, "max_active_per_interface": 10},
    },
    "reputation": {"enabled": True, "auto_blackhole": True, "auto_blackhole_score": 0.2},
    "adaptive": {"enabled": True, "learning_hours": 6, "alert_sigma": 2.5, "block_sigma": 4.0},
    "correlator": {"enabled": True, "sybil_threshold": 20, "amplification_ratio": 5.0, "response_mode": "defensive", "grace_period": 120},
    "metrics": {"enabled": True},
    "eventstore": {"enabled": True},
    "registry": {"enabled": True, "publish": False, "discover": True, "auto_connect": False},
}


# ── Client Presets ───────────────────────────────────────────────

_RELAXED: dict = {
    "general": {
        "node_mode": "client",
        "dry_run": True,  # Observe first
    },
    "filters": {
        "allowdeny": {"enabled": True},
        "hop_ceiling": {"enabled": True, "max_hops": 64},
        "rate_limit": {"enabled": True, "refill_rate": 1.0, "burst": 30, "overflow_action": "drop"},
        "churn": {"enabled": False, "suppress_threshold": 20.0, "reuse_threshold": 5.0, "decay_interval": 120},
        "anomaly": {"enabled": True, "anomaly_action": "flag", "max_announce_ratio": 100.0, "min_packets": 100},
        "interface_rate": {"enabled": True, "refill_rate": 20.0, "burst": 100},
        "bandwidth": {"enabled": True, "bytes_per_second": 1_000_000, "burst_bytes": 2_000_000},
        "packet_size": {"enabled": True, "max_bytes": 600},
        "announce_size": {"enabled": True, "max_app_data_bytes": 500},
        "path_request": {"enabled": True, "max_per_minute": 60, "scan_threshold": 50, "scan_window": 60},
        "link_request": {"enabled": True, "refill_rate": 2.0, "burst": 20, "max_pending_per_interface": 100},
        "resource_guard": {"enabled": True, "max_resource_bytes": 33_554_432, "max_active_per_interface": 20},
    },
    "reputation": {"enabled": True, "auto_blackhole": False},
    "adaptive": {"enabled": False},
    "correlator": {"enabled": True, "sybil_threshold": 100, "response_mode": "alert", "grace_period": 600},
    "registry": {"enabled": True, "publish": False, "discover": True, "auto_connect": True, "max_auto_connect": 5},
}

_STANDARD: dict = {
    "general": {
        "node_mode": "client",
        "dry_run": False,
    },
    "filters": {
        "allowdeny": {"enabled": True},
        "hop_ceiling": {"enabled": True, "max_hops": 32},
        "rate_limit": {"enabled": True, "refill_rate": 0.5, "burst": 15},
        "churn": {"enabled": False, "suppress_threshold": 15.0, "reuse_threshold": 3.0, "decay_interval": 120},
        "anomaly": {"enabled": True, "anomaly_action": "flag", "max_announce_ratio": 75.0, "min_packets": 50},
        "interface_rate": {"enabled": True, "refill_rate": 10.0, "burst": 50},
        "bandwidth": {"enabled": True, "bytes_per_second": 500_000, "burst_bytes": 1_000_000},
        "packet_size": {"enabled": True, "max_bytes": 600},
        "announce_size": {"enabled": True, "max_app_data_bytes": 500},
        "path_request": {"enabled": True, "max_per_minute": 30, "scan_threshold": 20, "scan_window": 60},
        "link_request": {"enabled": True, "refill_rate": 1.0, "burst": 10, "max_pending_per_interface": 50},
        "resource_guard": {"enabled": True, "max_resource_bytes": 16_777_216, "max_active_per_interface": 10},
    },
    "reputation": {"enabled": True, "auto_blackhole": False},
    "adaptive": {"enabled": True, "learning_hours": 12},
    "correlator": {"enabled": True, "sybil_threshold": 50, "response_mode": "alert", "grace_period": 300},
    "registry": {"enabled": True, "publish": False, "discover": True, "auto_connect": True, "max_auto_connect": 5},
}

_STRICT: dict = {
    "general": {
        "node_mode": "client",
        "dry_run": False,
    },
    "filters": {
        "allowdeny": {"enabled": True},
        "hop_ceiling": {"enabled": True, "max_hops": 16},
        "rate_limit": {"enabled": True, "refill_rate": 0.2, "burst": 8, "overflow_action": "drop"},
        "churn": {"enabled": True, "suppress_threshold": 8.0, "reuse_threshold": 2.0, "penalty_per_announce": 2.0},
        "anomaly": {"enabled": True, "anomaly_action": "throttle", "max_announce_ratio": 30.0, "min_packets": 25},
        "interface_rate": {"enabled": True, "refill_rate": 5.0, "burst": 25, "overflow_action": "drop"},
        "bandwidth": {"enabled": True, "bytes_per_second": 250_000, "burst_bytes": 500_000},
        "packet_size": {"enabled": True, "max_bytes": 500},
        "announce_size": {"enabled": True, "max_app_data_bytes": 300},
        "path_request": {"enabled": True, "max_per_minute": 15, "scan_threshold": 10, "scan_window": 30},
        "link_request": {"enabled": True, "refill_rate": 0.5, "burst": 5, "max_pending_per_interface": 20},
        "resource_guard": {"enabled": True, "max_resource_bytes": 8_388_608, "max_active_per_interface": 5},
    },
    "reputation": {"enabled": True, "auto_blackhole": False},
    "adaptive": {"enabled": True, "learning_hours": 6, "alert_sigma": 2.5, "block_sigma": 4.0},
    "correlator": {"enabled": True, "sybil_threshold": 20, "response_mode": "alert", "grace_period": 120},
    "registry": {"enabled": True, "publish": False, "discover": True, "auto_connect": False},
}


# ── Cross-Mode: LoRa ────────────────────────────────────────────

_LORA: dict = {
    "general": {
        "dry_run": False,
        # Does NOT set node_mode — works with either
    },
    "filters": {
        "allowdeny": {"enabled": True},
        "hop_ceiling": {"enabled": True, "max_hops": 12},  # LoRa topologies are deeper
        "rate_limit": {"enabled": True, "refill_rate": 0.1, "burst": 5},  # Bandwidth is precious
        "churn": {"enabled": True, "suppress_threshold": 6.0, "reuse_threshold": 2.0},
        "anomaly": {"enabled": True, "anomaly_action": "drop", "max_announce_ratio": 10.0, "min_packets": 20},
        "interface_rate": {"enabled": True, "refill_rate": 2.0, "burst": 10},
        "bandwidth": {"enabled": True, "bytes_per_second": 10_000, "burst_bytes": 20_000},  # LoRa is slow
        "packet_size": {"enabled": True, "max_bytes": 500},
        "announce_size": {"enabled": True, "max_app_data_bytes": 200},
        "path_request": {"enabled": True, "max_per_minute": 10, "scan_threshold": 5, "scan_window": 120},
        "link_request": {"enabled": True, "refill_rate": 0.2, "burst": 3, "max_pending_per_interface": 10},
        "resource_guard": {"enabled": True, "max_resource_bytes": 1_048_576, "max_active_per_interface": 3},
    },
    "reputation": {"enabled": True, "auto_blackhole": False},
    "adaptive": {"enabled": True, "learning_hours": 24},  # Longer baseline for LoRa
    "correlator": {"enabled": True, "sybil_threshold": 10, "response_mode": "defensive", "grace_period": 600},
    "registry": {"enabled": False},
}


# ── Registry ─────────────────────────────────────────────────────

PRESETS: dict[str, dict] = {
    # Gateway
    "observe": _OBSERVE,
    "balanced": _BALANCED,
    "fortress": _FORTRESS,
    # Client
    "relaxed": _RELAXED,
    "standard": _STANDARD,
    "strict": _STRICT,
    # Cross-mode
    "lora": _LORA,
}

# Presets available per mode (for setup wizard / TUI)
MODE_PRESETS: dict[str, list[str]] = {
    "gateway": ["observe", "balanced", "fortress", "lora"],
    "client": ["relaxed", "standard", "strict", "lora"],
}

# Backward-compatible aliases for old preset names
PRESET_ALIASES: dict[str, str] = {
    # Legacy aliases (pre-v1.0)
    "conservative": "relaxed",
    "moderate": "standard",
    "aggressive": "fortress",
    # Old two-word aliases (v1.0)
    "gateway-observe": "observe",
    "gateway-balanced": "balanced",
    "gateway-fortress": "fortress",
    "client-relaxed": "relaxed",
    "client-balanced": "standard",
    "client-strict": "strict",
}

DESCRIPTIONS: dict[str, str] = {
    "observe": "Observe first — dry-run ON, generous limits, learn traffic for 24h, publishes to registry",
    "balanced": "Active defense — fair limits, adaptive learning, metrics enabled, publishes to registry",
    "fortress": "Zero tolerance — auto-blackhole, tight limits, defensive correlator, discovers but never publishes",
    "relaxed": "Minimal interference — dry-run ON, observe first, generous limits, auto-connects to gateways",
    "standard": "Good defaults — standard protection, adaptive learning enabled, auto-connects to gateways",
    "strict": "Tight security — strict rate limits, low hop ceiling, active monitoring, manual peering only",
    "lora": "LoRa optimized — ultra-tight bandwidth, deeper hop ceiling, slow rates, registry disabled",
}


def list_presets(mode: str | None = None) -> list[dict]:
    """List available presets, optionally filtered by mode.

    Args:
        mode: "gateway", "client", or None for all presets.
    """
    if mode and mode in MODE_PRESETS:
        names = MODE_PRESETS[mode]
    else:
        names = list(PRESETS.keys())

    return [
        {"name": name, "description": DESCRIPTIONS.get(name, "")}
        for name in names
    ]


def apply_preset(name: str) -> dict:
    """
    Generate a full config by merging a preset over the defaults.

    Supports both new names (e.g. "balanced") and legacy aliases
    (e.g. "moderate" → "standard", "gateway-balanced" → "balanced").

    Returns the merged config dict, ready to be used as RatholeConfig.raw.
    """
    # Resolve aliases
    resolved = PRESET_ALIASES.get(name, name)

    if resolved not in PRESETS:
        available = list(PRESETS.keys()) + list(PRESET_ALIASES.keys())
        raise ValueError(f"Unknown preset: {name}. Available: {available}")

    preset = PRESETS[resolved]
    merged = _deep_merge(copy.deepcopy(DEFAULT_CONFIG), preset)
    log.info("Applied preset: %s%s", resolved, f" (alias for {name})" if resolved != name else "")
    return merged


def preset_diff(name: str) -> dict:
    """
    Show what a preset changes from defaults.

    Returns a dict of only the values that differ from DEFAULT_CONFIG.
    """
    resolved = PRESET_ALIASES.get(name, name)
    if resolved not in PRESETS:
        raise ValueError(f"Unknown preset: {name}")
    return PRESETS[resolved]
