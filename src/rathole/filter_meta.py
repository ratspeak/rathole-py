"""
Filter metadata registry — labels, descriptions, and parameter definitions.

Provides structured metadata for all 12 Rathole filters, organized by
pipeline. Used by rat and rathole-tui to render filter cards
with human-readable labels, descriptions, and typed parameter inputs.

Ported from the web dashboard's FILTER_META (app.js) and PIPELINE_FILTERS
(server.py) to make CLI/TUI first-class citizens.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ParamInfo:
    """Definition of a single filter parameter."""
    label: str
    type: str = "number"        # "number", "select", "bool"
    step: float = 1.0
    options: tuple = ()         # For "select" type


@dataclass(frozen=True)
class FilterInfo:
    """Metadata for a single filter."""
    name: str                   # Config key (e.g. "rate_limit")
    label: str                  # Human-readable (e.g. "Rate Limiter")
    pipeline: str               # Pipeline name (e.g. "announce")
    description: str
    params: dict[str, ParamInfo] = field(default_factory=dict)


# ── Pipeline → filter ordering ──────────────────────────────────

PIPELINE_ORDER = ["global", "announce", "path", "link", "data"]

PIPELINE_FILTERS: dict[str, list[str]] = {
    "global":   ["interface_rate", "bandwidth", "packet_size"],
    "announce": ["allowdeny", "hop_ceiling", "announce_size", "rate_limit", "churn", "anomaly"],
    "path":     ["path_request"],
    "link":     ["link_request"],
    "data":     ["resource_guard"],
}

PIPELINE_LABELS: dict[str, str] = {
    "global":   "Global (all packets)",
    "announce": "Announce",
    "path":     "Path Request",
    "link":     "Link Request",
    "data":     "Data / Resource",
}


# ── Filter metadata ─────────────────────────────────────────────

FILTER_META: dict[str, FilterInfo] = {
    "interface_rate": FilterInfo(
        name="interface_rate",
        label="Interface Rate Limit",
        pipeline="global",
        description="Per-interface packet flood protection",
        params={
            "refill_rate": ParamInfo(label="Refill Rate (pkt/s)", step=0.1),
            "burst": ParamInfo(label="Burst Capacity", step=1),
        },
    ),
    "bandwidth": FilterInfo(
        name="bandwidth",
        label="Bandwidth Cap",
        pipeline="global",
        description="Per-interface byte-rate abuse prevention",
        params={
            "bytes_per_second": ParamInfo(label="Bytes/sec", step=1000),
            "burst_bytes": ParamInfo(label="Burst Bytes", step=1000),
        },
    ),
    "packet_size": FilterInfo(
        name="packet_size",
        label="Packet Size Limit",
        pipeline="global",
        description="Drop oversized packets",
        params={
            "max_bytes": ParamInfo(label="Max Bytes", step=10),
        },
    ),
    "allowdeny": FilterInfo(
        name="allowdeny",
        label="Allow / Deny Lists",
        pipeline="announce",
        description="Hard allow/deny by identity or destination hash",
        params={},
    ),
    "hop_ceiling": FilterInfo(
        name="hop_ceiling",
        label="Hop Ceiling",
        pipeline="announce",
        description="Block deep-topology amplification attacks",
        params={
            "max_hops": ParamInfo(label="Max Hops", step=1),
            "soft_mode": ParamInfo(label="Soft Mode", type="bool"),
        },
    ),
    "announce_size": FilterInfo(
        name="announce_size",
        label="Announce Size",
        pipeline="announce",
        description="Block oversized announce app_data",
        params={
            "max_app_data_bytes": ParamInfo(label="Max App Data (bytes)", step=10),
        },
    ),
    "rate_limit": FilterInfo(
        name="rate_limit",
        label="Rate Limiter",
        pipeline="announce",
        description="Per-peer announce flood protection",
        params={
            "refill_rate": ParamInfo(label="Refill Rate (tok/s)", step=0.1),
            "burst": ParamInfo(label="Burst", step=1),
            "overflow_action": ParamInfo(
                label="Overflow Action", type="select",
                options=("drop", "throttle"),
            ),
        },
    ),
    "churn": FilterInfo(
        name="churn",
        label="Churn Dampening",
        pipeline="announce",
        description="BGP-style re-announce suppression (RFC 2439)",
        params={
            "suppress_threshold": ParamInfo(label="Suppress At", step=0.5),
            "reuse_threshold": ParamInfo(label="Reuse At", step=0.5),
            "penalty_per_announce": ParamInfo(label="Penalty/Announce", step=0.1),
            "decay_factor": ParamInfo(label="Decay Factor", step=0.05),
        },
    ),
    "anomaly": FilterInfo(
        name="anomaly",
        label="Anomaly Detector",
        pipeline="announce",
        description="High announce:traffic ratio detection",
        params={
            "max_announce_ratio": ParamInfo(label="Max Ratio", step=1),
            "anomaly_action": ParamInfo(
                label="Action", type="select",
                options=("flag", "throttle", "drop"),
            ),
        },
    ),
    "path_request": FilterInfo(
        name="path_request",
        label="Path Request Filter",
        pipeline="path",
        description="Path request flood and destination scan detection",
        params={
            "max_per_minute": ParamInfo(label="Max/min", step=1),
            "scan_threshold": ParamInfo(label="Scan Threshold", step=1),
            "scan_window": ParamInfo(label="Scan Window (s)", step=10),
        },
    ),
    "link_request": FilterInfo(
        name="link_request",
        label="Link Request Filter",
        pipeline="link",
        description="Link establishment flood and pending connection cap",
        params={
            "refill_rate": ParamInfo(label="Refill Rate (req/s)", step=0.1),
            "burst": ParamInfo(label="Burst", step=1),
            "max_pending_per_interface": ParamInfo(label="Max Pending", step=1),
        },
    ),
    "resource_guard": FilterInfo(
        name="resource_guard",
        label="Resource Guard",
        pipeline="data",
        description="Resource/compression bomb protection",
        params={
            "max_resource_bytes": ParamInfo(label="Max Size (bytes)", step=1000),
            "max_active_per_interface": ParamInfo(label="Max Active", step=1),
        },
    ),
}


def get_filter_info(name: str) -> FilterInfo | None:
    """Get metadata for a filter by config key name."""
    return FILTER_META.get(name)


def get_pipeline_filters(pipeline: str) -> list[FilterInfo]:
    """Get ordered list of FilterInfo for a pipeline."""
    names = PIPELINE_FILTERS.get(pipeline, [])
    return [FILTER_META[n] for n in names if n in FILTER_META]


def all_filters_by_pipeline() -> list[tuple[str, str, list[FilterInfo]]]:
    """
    Get all filters organized by pipeline, in display order.

    Returns list of (pipeline_key, pipeline_label, filters).
    """
    result = []
    for key in PIPELINE_ORDER:
        label = PIPELINE_LABELS.get(key, key.title())
        filters = get_pipeline_filters(key)
        result.append((key, label, filters))
    return result
