"""
Prometheus-compatible metrics endpoint.

Exposes counters, gauges, and histograms for monitoring Rathole behavior.
Runs a lightweight HTTP server on a configurable bind address (default
127.0.0.1:9777).

This module provides a thin abstraction that works with or without the
prometheus_client library. When the library is not installed, metrics are
tracked internally and exposed as plain text in Prometheus exposition format.

Config keys (under [metrics]):
  - enabled: Enable metrics endpoint (default false)
  - bind: Address to bind HTTP server (default "127.0.0.1:9777")
  - per_peer_metrics: Expose per-peer breakdown (default true)
"""

import time
import logging
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

log = logging.getLogger("rathole.metrics")


class MetricStore:
    """
    Thread-safe metric storage. Provides counters and gauges without
    requiring prometheus_client as a dependency.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._counters: dict[str, float] = {}
        self._gauges: dict[str, float] = {}
        self._labels: dict[str, dict[str, str]] = {}  # metric -> labels

    def inc(self, name: str, value: float = 1.0, labels: dict[str, str] | None = None):
        """Increment a counter."""
        key = self._key(name, labels)
        with self._lock:
            self._counters[key] = self._counters.get(key, 0.0) + value
            if labels:
                self._labels[key] = labels

    def set_gauge(self, name: str, value: float, labels: dict[str, str] | None = None):
        """Set a gauge value."""
        key = self._key(name, labels)
        with self._lock:
            self._gauges[key] = value
            if labels:
                self._labels[key] = labels

    def get_counter(self, name: str, labels: dict[str, str] | None = None) -> float:
        key = self._key(name, labels)
        with self._lock:
            return self._counters.get(key, 0.0)

    def get_gauge(self, name: str, labels: dict[str, str] | None = None) -> float:
        key = self._key(name, labels)
        with self._lock:
            return self._gauges.get(key, 0.0)

    def exposition(self) -> str:
        """Generate Prometheus exposition format text."""
        lines = []
        with self._lock:
            # Counters
            emitted_help = set()
            for key, value in sorted(self._counters.items()):
                name = key.split("{")[0]
                if name not in emitted_help:
                    lines.append(f"# TYPE {name} counter")
                    emitted_help.add(name)
                lines.append(f"{key} {value}")

            # Gauges
            emitted_help = set()
            for key, value in sorted(self._gauges.items()):
                name = key.split("{")[0]
                if name not in emitted_help:
                    lines.append(f"# TYPE {name} gauge")
                    emitted_help.add(name)
                lines.append(f"{key} {value}")

        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _key(name: str, labels: dict[str, str] | None) -> str:
        if not labels:
            return name
        label_str = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"


class _ReusableHTTPServer(HTTPServer):
    """HTTPServer with SO_REUSEADDR to avoid 'address already in use'."""
    allow_reuse_address = True


class _MetricsHandler(BaseHTTPRequestHandler):
    """HTTP handler for /metrics endpoint."""
    store: MetricStore = None  # Set by MetricsServer

    def do_GET(self):
        if self.path == "/metrics":
            body = self.store.exposition().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Suppress default stderr logging
        pass


class MetricsServer:
    """
    Manages the metrics store and optional HTTP endpoint.

    Usage:
        server = MetricsServer(config)
        server.start()  # Non-blocking, runs in background thread
        server.store.inc("rathole_packets_total")
        server.stop()
    """

    def __init__(self, config: dict):
        self._enabled = config.get("enabled", False)
        self._bind = config.get("bind", "127.0.0.1:9777")
        self._per_peer = config.get("per_peer_metrics", True)

        self.store = MetricStore()
        self._httpd: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def enabled(self) -> bool:
        return self._enabled

    def start(self):
        """Start the metrics HTTP server in a background thread.

        Tries up to 10 consecutive ports starting from the configured port.
        """
        if not self._enabled:
            return

        host, port_str = self._bind.rsplit(":", 1)
        base_port = int(port_str)

        handler = type("Handler", (_MetricsHandler,), {"store": self.store})
        for offset in range(10):
            port = base_port + offset
            try:
                self._httpd = _ReusableHTTPServer((host, port), handler)
                self._thread = threading.Thread(
                    target=self._httpd.serve_forever,
                    daemon=True,
                    name="rathole-metrics",
                )
                self._thread.start()
                bound = f"{host}:{port}"
                if offset > 0:
                    log.info("Metrics server listening on %s (configured port %d was busy)",
                             bound, base_port)
                else:
                    log.info("Metrics server listening on %s", bound)
                return
            except OSError as e:
                if offset < 9:
                    log.debug("Metrics port %d busy: %s, trying %d", port, e, port + 1)
                else:
                    log.error("Failed to start metrics server on ports %d-%d: %s",
                              base_port, port, e)

    def stop(self):
        """Stop the metrics HTTP server and release resources."""
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        log.info("Metrics server stopped")

    def update_from_state(self, state, reputation=None, blackhole=None, config=None):
        """Bulk-update metrics from StateTracker and friends."""
        stats = state.stats
        self.store.set_gauge("rathole_uptime_seconds", stats.get("uptime", 0))
        self.store.set_gauge("rathole_peers_tracked", stats.get("tracked_peers", 0))
        self.store.set_gauge("rathole_interfaces_tracked", stats.get("tracked_interfaces", 0))
        self.store.set_gauge("rathole_destinations_tracked", stats.get("tracked_destinations", 0))

        for key in ("total_packets", "total_announces", "total_accepted",
                     "total_dropped", "total_throttled", "total_blackholed",
                     "total_quarantined"):
            # These are cumulative, so set as counter value
            self.store._counters[f"rathole_{key}"] = float(stats.get(key, 0))

        # ── Phase 6: New metrics ──────────────────────────────

        # Unique peers total (counter)
        self.store._counters["rathole_unique_peers_total"] = float(
            stats.get("unique_peers_seen", 0)
        )

        # Total bytes in (counter)
        self.store._counters["rathole_bytes_in_total"] = float(
            stats.get("total_bytes_in", 0)
        )

        # Peak rates (gauges)
        self.store.set_gauge(
            "rathole_peak_packet_rate",
            stats.get("peak_packet_rate", 0.0),
        )
        self.store.set_gauge(
            "rathole_peak_announce_rate",
            stats.get("peak_announce_rate", 0.0),
        )

        # Per-filter drop counters
        filter_drops = stats.get("filter_drops", {})
        for filter_name, count in filter_drops.items():
            self.store._counters[
                self.store._key("rathole_filter_drops_total", {"filter_name": filter_name})
            ] = float(count)

        # Node mode (info gauge)
        if config is not None:
            node_mode = config.node_mode if hasattr(config, "node_mode") else "client"
            self.store.set_gauge(
                "rathole_node_mode",
                1.0,
                {"mode": node_mode},
            )

        # ── Reputation metrics ────────────────────────────────

        if reputation is not None:
            # Per-identity scores (if per_peer enabled)
            if self._per_peer:
                for entry in reputation.summary():
                    labels = {"identity": entry["identity"]}
                    self.store.set_gauge("rathole_reputation_score", entry["score"], labels)

            # Reputation distribution (gauge per category)
            distribution = reputation.reputation_distribution()
            for category, count in distribution.items():
                self.store.set_gauge(
                    "rathole_reputation_distribution",
                    float(count),
                    {"category": category},
                )

            # Category transitions (counter)
            for transition, count in reputation.category_transitions().items():
                self.store._counters[
                    self.store._key("rathole_category_transitions_total", {"transition": transition})
                ] = float(count)

            # Auto-blackhole count (counter)
            self.store._counters["rathole_auto_blackholes_total"] = float(
                reputation._auto_blackhole_count
            )

        if blackhole is not None:
            self.store.set_gauge("rathole_blackholed_identities", blackhole.count)
