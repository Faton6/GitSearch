# -*- coding: utf-8 -*-
"""
Performance Metrics Module for GitSearch

Collects and exports performance metrics for monitoring:
- Scanning times (clone, scan, AI analysis)
- Rate limit usage
- Cache hit/miss rates
- Queue sizes and throughput
- Error rates

Supports export to:
- Prometheus format
- JSON
- Console logging
"""

import time
import threading
from typing import Dict, Optional, Any
from dataclasses import dataclass, field
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timezone
import json

from src.logger import logger


@dataclass
class TimingMetric:
    """Single timing measurement."""

    name: str
    duration_seconds: float
    timestamp: float
    labels: Dict[str, str] = field(default_factory=dict)


@dataclass
class CounterMetric:
    """Counter metric (monotonically increasing)."""

    name: str
    value: int = 0
    labels: Dict[str, str] = field(default_factory=dict)


@dataclass
class GaugeMetric:
    """Gauge metric (can go up and down)."""

    name: str
    value: float = 0.0
    labels: Dict[str, str] = field(default_factory=dict)


class MetricsCollector:
    """
    Centralized metrics collection for GitSearch.

    Thread-safe singleton that collects:
    - Timing histograms (clone, scan, AI analysis)
    - Counters (requests, errors, leaks found)
    - Gauges (queue sizes, rate limits)

    Usage:
        metrics = get_metrics_collector()

        # Timing
        with metrics.timer('clone_duration', repo='user/repo'):
            clone_repo(url)

        # Counter
        metrics.increment('leaks_found', scanner='gitleaks')

        # Gauge
        metrics.set_gauge('ai_queue_size', 15)
    """

    _instance: Optional["MetricsCollector"] = None
    _lock = threading.Lock()

    # Histogram buckets for timing metrics (seconds)
    TIMING_BUCKETS = [0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, float("inf")]

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        # Проверяем наличие атрибута перед проверкой значения
        if hasattr(self, "_initialized") and self._initialized:
            return

        self._lock = threading.Lock()

        # Timing metrics (keep last N for percentile calculation)
        self._timings: Dict[str, deque] = {}
        self._timing_max_samples = 1000

        # Counters
        self._counters: Dict[str, int] = {}

        # Gauges
        self._gauges: Dict[str, float] = {}

        # Histogram buckets for timing metrics
        self._histograms: Dict[str, Dict[float, int]] = {}

        # Start time for uptime calculation
        self._start_time = time.time()

        # Initialize default metrics
        self._init_default_metrics()

        self._initialized = True
        logger.info("MetricsCollector initialized")

    def _init_default_metrics(self):
        """Initialize default metrics with zero values."""
        # Counters
        default_counters = [
            "repos_scanned_total",
            "repos_cloned_total",
            "leaks_found_total",
            "false_positives_total",
            "api_requests_total",
            "api_errors_total",
            "rate_limit_hits_total",
            "ai_analyses_total",
            "ai_analyses_failed_total",
            "db_queries_total",
            "db_errors_total",
        ]
        for name in default_counters:
            self._counters[name] = 0

        # Gauges
        default_gauges = [
            "ai_queue_size",
            "scan_queue_size",
            "active_workers",
            "rate_limit_remaining",
            "temp_folder_size_bytes",
            "temp_folder_repos_count",
            "cache_size",
        ]
        for name in default_gauges:
            self._gauges[name] = 0.0

    @contextmanager
    def timer(self, name: str, **labels):
        """
        Context manager for timing operations.

        Args:
            name: Metric name (e.g., 'clone_duration')
            **labels: Optional labels (e.g., scanner='gitleaks')

        Usage:
            with metrics.timer('scan_duration', scanner='gitleaks'):
                run_scan()
        """
        start = time.perf_counter()
        try:
            yield
        finally:
            duration = time.perf_counter() - start
            self.record_timing(name, duration, **labels)

    def record_timing(self, name: str, duration: float, **labels):
        """Record a timing measurement."""
        with self._lock:
            # Store in deque for percentile calculation
            if name not in self._timings:
                self._timings[name] = deque(maxlen=self._timing_max_samples)
            self._timings[name].append(
                TimingMetric(name=name, duration_seconds=duration, timestamp=time.time(), labels=labels)
            )

            # Update histogram
            self._update_histogram(name, duration)

    def _update_histogram(self, name: str, duration: float):
        """Update histogram bucket counts."""
        if name not in self._histograms:
            self._histograms[name] = {bucket: 0 for bucket in self.TIMING_BUCKETS}

        for bucket in self.TIMING_BUCKETS:
            if duration <= bucket:
                self._histograms[name][bucket] += 1
                break

    def increment(self, name: str, value: int = 1, **labels):
        """Increment a counter metric."""
        with self._lock:
            key = self._make_key(name, labels)
            if key not in self._counters:
                self._counters[key] = 0
            self._counters[key] += value

    def set_gauge(self, name: str, value: float, **labels):
        """Set a gauge metric value."""
        with self._lock:
            key = self._make_key(name, labels)
            self._gauges[key] = value

    def get_gauge(self, name: str, **labels) -> float:
        """Get current gauge value."""
        with self._lock:
            key = self._make_key(name, labels)
            return self._gauges.get(key, 0.0)

    def inc_gauge(self, name: str, value: float = 1.0, **labels):
        """Increment a gauge metric."""
        with self._lock:
            key = self._make_key(name, labels)
            if key not in self._gauges:
                self._gauges[key] = 0.0
            self._gauges[key] += value

    def dec_gauge(self, name: str, value: float = 1.0, **labels):
        """Decrement a gauge metric."""
        self.inc_gauge(name, -value, **labels)

    def _make_key(self, name: str, labels: Dict) -> str:
        """Create unique key from name and labels."""
        if not labels:
            return name
        label_str = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"

    def get_timing_stats(self, name: str) -> Dict[str, float]:
        """
        Get timing statistics for a metric.

        Returns:
            Dict with count, sum, avg, min, max, p50, p90, p99
        """
        with self._lock:
            if name not in self._timings or not self._timings[name]:
                return {"count": 0, "sum": 0, "avg": 0, "min": 0, "max": 0, "p50": 0, "p90": 0, "p99": 0}

            durations = sorted(m.duration_seconds for m in self._timings[name])
            count = len(durations)
            total = sum(durations)

            return {
                "count": count,
                "sum": round(total, 3),
                "avg": round(total / count, 3),
                "min": round(durations[0], 3),
                "max": round(durations[-1], 3),
                "p50": round(durations[int(count * 0.5)], 3),
                "p90": round(durations[int(count * 0.9)], 3),
                "p99": round(durations[min(int(count * 0.99), count - 1)], 3),
            }

    def get_all_metrics(self) -> Dict[str, Any]:
        """Get all metrics as a dictionary."""
        with self._lock:
            result = {
                "uptime_seconds": round(time.time() - self._start_time, 1),
                "collected_at": datetime.now(timezone.utc).isoformat(),
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
                "timings": {},
            }

            for name in self._timings:
                result["timings"][name] = self.get_timing_stats(name)

            return result

    def to_prometheus(self) -> str:
        """
        Export metrics in Prometheus format.

        Returns:
            String in Prometheus exposition format
        """
        lines = []

        # Uptime
        uptime = time.time() - self._start_time
        lines.append("# HELP gitsearch_uptime_seconds Time since service start")
        lines.append("# TYPE gitsearch_uptime_seconds gauge")
        lines.append(f"gitsearch_uptime_seconds {uptime:.1f}")
        lines.append("")

        # Counters
        with self._lock:
            for key, value in self._counters.items():
                name, labels = self._parse_key(key)
                metric_name = f"gitsearch_{name}"
                lines.append(f"# TYPE {metric_name} counter")
                if labels:
                    lines.append(f"{metric_name}{{{labels}}} {value}")
                else:
                    lines.append(f"{metric_name} {value}")

            lines.append("")

            # Gauges
            for key, value in self._gauges.items():
                name, labels = self._parse_key(key)
                metric_name = f"gitsearch_{name}"
                lines.append(f"# TYPE {metric_name} gauge")
                if labels:
                    lines.append(f"{metric_name}{{{labels}}} {value}")
                else:
                    lines.append(f"{metric_name} {value}")

            lines.append("")

            # Timing histograms
            for name, buckets in self._histograms.items():
                metric_name = f"gitsearch_{name}"
                lines.append(f"# HELP {metric_name} Duration histogram")
                lines.append(f"# TYPE {metric_name} histogram")

                cumulative = 0
                for bucket, count in sorted(buckets.items()):
                    cumulative += count
                    if bucket == float("inf"):
                        lines.append(f'{metric_name}_bucket{{le="+Inf"}} {cumulative}')
                    else:
                        lines.append(f'{metric_name}_bucket{{le="{bucket}"}} {cumulative}')

                stats = self.get_timing_stats(name)
                lines.append(f'{metric_name}_sum {stats["sum"]}')
                lines.append(f'{metric_name}_count {stats["count"]}')

        return "\n".join(lines)

    def _parse_key(self, key: str) -> tuple:
        """Parse key into name and labels string."""
        if "{" in key:
            name = key[: key.index("{")]
            labels = key[key.index("{") + 1 : -1]
            return name, labels
        return key, ""

    def to_json(self, pretty: bool = False) -> str:
        """Export metrics as JSON."""
        data = self.get_all_metrics()
        if pretty:
            return json.dumps(data, indent=2, default=str)
        return json.dumps(data, default=str)

    def reset(self):
        """Reset all metrics (for testing)."""
        with self._lock:
            self._timings.clear()
            self._counters.clear()
            self._gauges.clear()
            self._histograms.clear()
            self._init_default_metrics()
            self._start_time = time.time()


# Global instance getter
_metrics_collector: Optional[MetricsCollector] = None


def get_metrics_collector() -> MetricsCollector:
    """Get the global MetricsCollector instance."""
    global _metrics_collector
    if _metrics_collector is None:
        _metrics_collector = MetricsCollector()
    return _metrics_collector


# Convenience functions
def record_scan_time(scanner: str, duration: float, repo_url: str = ""):
    """Record scan duration for a scanner."""
    get_metrics_collector().record_timing("scan_duration_seconds", duration, scanner=scanner)


def record_clone_time(duration: float, method: str = "git"):
    """Record repository clone duration."""
    get_metrics_collector().record_timing("clone_duration_seconds", duration, method=method)


def record_ai_analysis_time(duration: float, provider: str = ""):
    """Record AI analysis duration."""
    get_metrics_collector().record_timing("ai_analysis_duration_seconds", duration, provider=provider)


def increment_leaks_found(scanner: str = "", severity: str = ""):
    """Increment leaks found counter."""
    labels = {}
    if scanner:
        labels["scanner"] = scanner
    if severity:
        labels["severity"] = severity
    get_metrics_collector().increment("leaks_found_total", **labels)


def increment_api_request(endpoint: str = "", status: str = "success"):
    """Increment API request counter."""
    get_metrics_collector().increment("api_requests_total", endpoint=endpoint, status=status)


def increment_error(error_type: str = "unknown"):
    """Increment error counter."""
    get_metrics_collector().increment("errors_total", type=error_type)


def set_queue_size(queue_name: str, size: int):
    """Set queue size gauge."""
    get_metrics_collector().set_gauge(f"{queue_name}_queue_size", size)


def set_rate_limit_remaining(token_hash: str, remaining: int):
    """Set rate limit remaining gauge."""
    get_metrics_collector().set_gauge("rate_limit_remaining", remaining, token=token_hash[:8])


__all__ = [
    "MetricsCollector",
    "get_metrics_collector",
    "record_scan_time",
    "record_clone_time",
    "record_ai_analysis_time",
    "increment_leaks_found",
    "increment_api_request",
    "increment_error",
    "set_queue_size",
    "set_rate_limit_remaining",
]
