"""
Adaptive threshold engine — dynamic thresholds based on observed traffic.

After a learning period, baselines are computed per metric per interface.
Thresholds are then set dynamically as: mean + (N * stddev).

Manual config thresholds ALWAYS override adaptive thresholds.
Opt-in only — disabled by default.

Config keys:
  - enabled: Enable adaptive thresholds (default false)
  - learning_hours: Baseline learning period in hours (default 24)
  - alert_sigma: N for alert threshold (default 3.0)
  - block_sigma: N for block threshold (default 5.0)
  - sample_interval: Seconds between samples (default 60)
  - max_samples: Maximum samples to retain (default 1440 = 24h at 60s)
"""

import math
import time
import logging
from collections import deque
from dataclasses import dataclass, field

log = logging.getLogger("rathole.adaptive")


@dataclass
class MetricBaseline:
    """Rolling statistics for a single metric on a single interface."""
    name: str
    samples: deque = field(default_factory=lambda: deque(maxlen=1440))
    last_sample: float = 0.0

    @property
    def count(self) -> int:
        return len(self.samples)

    @property
    def mean(self) -> float:
        if not self.samples:
            return 0.0
        return sum(self.samples) / len(self.samples)

    @property
    def stddev(self) -> float:
        if len(self.samples) < 2:
            return 0.0
        m = self.mean
        variance = sum((x - m) ** 2 for x in self.samples) / (len(self.samples) - 1)
        return math.sqrt(variance)

    def add_sample(self, value: float):
        self.samples.append(value)
        self.last_sample = time.monotonic()

    def threshold(self, sigma: float) -> float:
        """Compute threshold = mean + sigma * stddev."""
        return self.mean + sigma * self.stddev


class AdaptiveEngine:
    """
    Manages adaptive baselines for per-interface metrics.

    Tracks configurable metrics (packet rate, announce rate, link request
    rate, etc.) per interface. After the learning period, provides dynamic
    thresholds.

    Usage:
      engine = AdaptiveEngine(config)
      engine.record("iface1", "packet_rate", 42.5)
      alert_threshold = engine.get_alert_threshold("iface1", "packet_rate")
      block_threshold = engine.get_block_threshold("iface1", "packet_rate")
    """

    def __init__(self, config: dict):
        self._enabled = config.get("enabled", False)
        self._learning_hours = config.get("learning_hours", 24)
        self._alert_sigma = config.get("alert_sigma", 3.0)
        self._block_sigma = config.get("block_sigma", 5.0)
        self._sample_interval = config.get("sample_interval", 60)
        self._max_samples = config.get("max_samples", 1440)

        self._start_time = time.monotonic()
        # {interface_name: {metric_name: MetricBaseline}}
        self._baselines: dict[str, dict[str, MetricBaseline]] = {}

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def is_learning(self) -> bool:
        """True if still in the initial learning period."""
        elapsed_hours = (time.monotonic() - self._start_time) / 3600.0
        return elapsed_hours < self._learning_hours

    @property
    def learning_progress(self) -> float:
        """Learning progress as a fraction (0.0 to 1.0)."""
        if self._learning_hours <= 0:
            return 1.0
        elapsed_hours = (time.monotonic() - self._start_time) / 3600.0
        return min(1.0, elapsed_hours / self._learning_hours)

    def record(self, interface_name: str, metric_name: str, value: float):
        """Record a metric sample for an interface."""
        if not self._enabled:
            return

        if interface_name not in self._baselines:
            self._baselines[interface_name] = {}
        metrics = self._baselines[interface_name]

        if metric_name not in metrics:
            metrics[metric_name] = MetricBaseline(
                name=metric_name,
                samples=deque(maxlen=self._max_samples),
            )

        baseline = metrics[metric_name]

        # Only sample at configured interval
        now = time.monotonic()
        if baseline.last_sample > 0 and (now - baseline.last_sample) < self._sample_interval:
            return

        baseline.add_sample(value)

    def get_alert_threshold(self, interface_name: str, metric_name: str) -> float | None:
        """Get the alert threshold for a metric. Returns None if not enough data."""
        return self._get_threshold(interface_name, metric_name, self._alert_sigma)

    def get_block_threshold(self, interface_name: str, metric_name: str) -> float | None:
        """Get the block threshold for a metric. Returns None if not enough data."""
        return self._get_threshold(interface_name, metric_name, self._block_sigma)

    def get_baseline(self, interface_name: str, metric_name: str) -> MetricBaseline | None:
        """Get the raw baseline for inspection."""
        metrics = self._baselines.get(interface_name)
        if metrics is None:
            return None
        return metrics.get(metric_name)

    def summary(self) -> dict:
        """Summary of all baselines for control interface."""
        result = {
            "enabled": self._enabled,
            "learning": self.is_learning,
            "learning_progress": round(self.learning_progress, 2),
            "interfaces": {},
        }
        for iface, metrics in self._baselines.items():
            result["interfaces"][iface] = {
                name: {
                    "mean": round(bl.mean, 2),
                    "stddev": round(bl.stddev, 2),
                    "samples": bl.count,
                    "alert_at": round(bl.threshold(self._alert_sigma), 2),
                    "block_at": round(bl.threshold(self._block_sigma), 2),
                }
                for name, bl in metrics.items()
            }
        return result

    def refresh_config(self, config: dict):
        """Re-read cached config values after a live config change."""
        self._enabled = config.get("enabled", False)
        self._learning_hours = config.get("learning_hours", 24)
        self._alert_sigma = config.get("alert_sigma", 3.0)
        self._block_sigma = config.get("block_sigma", 5.0)
        self._sample_interval = config.get("sample_interval", 60)
        self._max_samples = config.get("max_samples", 1440)

    def _get_threshold(self, interface_name: str, metric_name: str, sigma: float) -> float | None:
        """Internal threshold computation."""
        if not self._enabled:
            return None

        # Don't enforce adaptive thresholds during learning
        if self.is_learning:
            return None

        metrics = self._baselines.get(interface_name)
        if metrics is None:
            return None

        baseline = metrics.get(metric_name)
        if baseline is None or baseline.count < 10:
            return None

        return baseline.threshold(sigma)
