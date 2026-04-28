"""
baseline.py — Maintains a rolling 30-minute baseline of per-second
request counts. Recalculates mean and stddev every 60 seconds.

How it works:
  - Every second, we record the global request count for that second
    into a deque capped at 30 * 60 = 1800 slots.
  - We also maintain per-hour slots so we can prefer the current
    hour's data when it has enough samples.
  - Every recalc_interval seconds, we compute mean and stddev over
    the rolling window (or the current hour's window if large enough).
  - A floor of 1.0 req/s is applied so stddev never collapses to zero
    on idle servers.
"""

import time
import math
import logging
import threading
from collections import deque, defaultdict

from audit import write_audit

logger = logging.getLogger("baseline")

FLOOR_MEAN = 1.0      # minimum effective mean (req/s)
FLOOR_STDDEV = 0.5    # minimum effective stddev
MIN_HOUR_SAMPLES = 60 # need at least 60 per-second samples to trust hourly slot


class BaselineTracker:
    def __init__(self, config):
        self.window_minutes = config["detection"]["baseline_window_minutes"]
        self.recalc_interval = config["detection"]["baseline_recalc_interval"]
        self.min_samples = config["detection"]["min_baseline_samples"]
        self.audit_path = config["audit_log"]["path"]

        self.max_slots = self.window_minutes * 60  # 1800 seconds

        # Rolling window of (timestamp, count) per second
        self._rolling: deque = deque(maxlen=self.max_slots)

        # Per-hour accumulator: hour_key -> list of per-second counts
        self._hourly: dict[int, list] = defaultdict(list)

        # Published stats (read by detector and dashboard)
        self.mean: float = FLOOR_MEAN
        self.stddev: float = FLOOR_STDDEV
        self.effective_hour: int = -1

        self._lock = threading.Lock()
        self._last_second_count = 0
        self._last_tick = time.time()

    # ------------------------------------------------------------------ #
    #  Called by monitor every time a request arrives                      #
    # ------------------------------------------------------------------ #
    def record_request(self):
        """Increment the in-progress per-second counter (thread-safe)."""
        with self._lock:
            self._last_second_count += 1

    # ------------------------------------------------------------------ #
    #  Background thread                                                   #
    # ------------------------------------------------------------------ #
    def run(self):
        """
        Two duties:
          1. Every second — snapshot the per-second count into the rolling deque.
          2. Every recalc_interval seconds — recompute mean/stddev.
        """
        last_recalc = time.time()

        while True:
            time.sleep(1)
            now = time.time()
            hour_key = int(now // 3600)

            with self._lock:
                count = self._last_second_count
                self._last_second_count = 0

            self._rolling.append((now, count))
            self._hourly[hour_key].append(count)

            # Trim hourly slots older than 2 hours to save memory
            cutoff_hour = hour_key - 2
            for k in list(self._hourly.keys()):
                if k < cutoff_hour:
                    del self._hourly[k]

            # Recalculate on schedule
            if now - last_recalc >= self.recalc_interval:
                self._recalculate(now, hour_key)
                last_recalc = now

    def _recalculate(self, now: float, hour_key: int):
        """Compute mean and stddev; prefer current hour if it has enough data."""
        hourly_samples = self._hourly.get(hour_key, [])

        if len(hourly_samples) >= MIN_HOUR_SAMPLES:
            samples = hourly_samples
            source = f"hour:{hour_key}"
        else:
            # Fall back to full rolling window
            samples = [c for _, c in self._rolling]
            source = "rolling"

        if len(samples) < self.min_samples:
            logger.debug("Not enough samples for baseline yet.")
            return

        mean = sum(samples) / len(samples)
        variance = sum((x - mean) ** 2 for x in samples) / len(samples)
        stddev = math.sqrt(variance)

        # Apply floors
        effective_mean = max(mean, FLOOR_MEAN)
        effective_stddev = max(stddev, FLOOR_STDDEV)

        with self._lock:
            self.mean = effective_mean
            self.stddev = effective_stddev
            self.effective_hour = hour_key

        write_audit(
            self.audit_path,
            action="BASELINE_RECALC",
            ip="-",
            condition=f"source={source} samples={len(samples)}",
            rate=effective_mean,
            baseline=effective_mean,
            duration="-",
        )

        logger.info(
            f"Baseline recalculated [{source}]: "
            f"mean={effective_mean:.3f} stddev={effective_stddev:.3f} "
            f"samples={len(samples)}"
        )

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "mean": self.mean,
                "stddev": self.stddev,
                "hour": self.effective_hour,
            }
