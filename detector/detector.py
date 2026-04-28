"""
detector.py — Anomaly detection logic.

Per-IP check (called on every request):
  - Compute z-score: (rate - mean) / stddev
  - Fire if z-score > 3.0 OR rate > 5x mean
  - If IP has an error surge (4xx/5xx rate > 3x baseline error rate),
    tighten thresholds: zscore_threshold *= 0.7, multiplier *= 0.7

Global check (runs every second in its own thread):
  - Same z-score / multiplier logic on global req/s
  - On anomaly: Slack alert only (no iptables block)
"""

import time
import logging
import threading

logger = logging.getLogger("detector")

# Cooldown: don't re-alert the same IP within this many seconds
ALERT_COOLDOWN = 30


class AnomalyDetector:
    def __init__(self, config, baseline, blocker, notifier, shared_state):
        self.cfg = config["detection"]
        self.baseline = baseline
        self.blocker = blocker
        self.notifier = notifier
        self.shared_state = shared_state

        self.zscore_threshold = self.cfg["zscore_threshold"]
        self.rate_multiplier = self.cfg["rate_multiplier"]
        self.error_multiplier = self.cfg["error_rate_multiplier"]

        # Track last alert time per IP to avoid spam
        self._last_alert: dict[str, float] = {}
        self._lock = threading.Lock()

        # Baseline error rate (approximated as mean * 0.05 initially)
        self._baseline_error_rate = 0.05

    # ------------------------------------------------------------------ #
    #  Per-IP check — called from monitor thread                           #
    # ------------------------------------------------------------------ #
    def check_ip(self, ip: str, rate: float, error_rate: float, entry: dict):
        stats = self.baseline.get_stats()
        mean = stats["mean"]
        stddev = stats["stddev"]

        # Tighten thresholds if error surge detected
        z_thresh = self.zscore_threshold
        mult_thresh = self.rate_multiplier
        error_surge = False

        baseline_err = max(self._baseline_error_rate, 0.01)
        if error_rate > self.error_multiplier * baseline_err:
            z_thresh *= 0.7
            mult_thresh *= 0.7
            error_surge = True

        # Compute z-score
        zscore = (rate - mean) / stddev if stddev > 0 else 0.0

        fired = False
        condition = None

        if zscore > z_thresh:
            condition = f"zscore={zscore:.2f} > threshold={z_thresh:.2f}"
            fired = True
        elif rate > mult_thresh * mean:
            condition = f"rate={rate:.2f} > {mult_thresh:.1f}x mean={mean:.2f}"
            fired = True

        if fired and not self._is_cooling_down(ip):
            suffix = " [error_surge]" if error_surge else ""
            full_condition = condition + suffix
            logger.warning(f"ANOMALY IP={ip} rate={rate:.2f} {full_condition}")
            self.blocker.ban(ip, full_condition, rate, mean)
            self._set_cooldown(ip)

    # ------------------------------------------------------------------ #
    #  Global check — runs in its own thread every second                  #
    # ------------------------------------------------------------------ #
    def run_global_check(self):
        while True:
            time.sleep(1)
            global_rate = self.shared_state.get("global_rps", 0.0)
            stats = self.baseline.get_stats()
            mean = stats["mean"]
            stddev = stats["stddev"]

            zscore = (global_rate - mean) / stddev if stddev > 0 else 0.0

            fired = False
            condition = None

            if zscore > self.zscore_threshold:
                condition = f"GLOBAL zscore={zscore:.2f} > {self.zscore_threshold}"
                fired = True
            elif global_rate > self.rate_multiplier * mean:
                condition = (
                    f"GLOBAL rate={global_rate:.2f} > "
                    f"{self.rate_multiplier}x mean={mean:.2f}"
                )
                fired = True

            if fired and not self._is_cooling_down("__global__"):
                logger.warning(f"GLOBAL ANOMALY: {condition}")
                self.notifier.send_global_alert(condition, global_rate, mean)
                self._set_cooldown("__global__")

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #
    def _is_cooling_down(self, key: str) -> bool:
        with self._lock:
            last = self._last_alert.get(key, 0)
            return (time.time() - last) < ALERT_COOLDOWN

    def _set_cooldown(self, key: str):
        with self._lock:
            self._last_alert[key] = time.time()
