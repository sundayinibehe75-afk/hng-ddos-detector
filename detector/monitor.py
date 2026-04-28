"""
monitor.py — Tails the Nginx JSON access log line by line and feeds
parsed entries into the detector. Uses a deque-based sliding window
per IP and globally to track request rates over the last 60 seconds.

Sliding window design:
  - Each IP has a deque of timestamps.
  - The global window is a deque of timestamps.
  - On every new request, we append the current time and evict entries
    older than window_seconds from the left (deque is time-ordered).
  - Rate = len(deque) / window_seconds  →  requests per second.
"""

import json
import time
import logging
import os
from collections import deque, defaultdict

logger = logging.getLogger("monitor")


class LogMonitor:
    def __init__(self, config, detector, baseline, shared_state):
        self.log_path = config["nginx"]["log_path"]
        self.window_seconds = config["detection"]["window_seconds"]
        self.detector = detector
        self.baseline = baseline
        self.shared_state = shared_state

        # Per-IP sliding window: ip -> deque of timestamps
        self.ip_windows: dict[str, deque] = defaultdict(deque)
        # Per-IP error tracking: ip -> deque of (timestamp, is_error)
        self.ip_error_windows: dict[str, deque] = defaultdict(deque)
        # Global sliding window
        self.global_window: deque = deque()

    def _evict_old(self, dq: deque, now: float):
        """Remove entries older than window_seconds from the left."""
        cutoff = now - self.window_seconds
        while dq and dq[0] < cutoff:
            dq.popleft()

    def _evict_old_errors(self, dq: deque, now: float):
        """Remove (timestamp, flag) tuples older than window_seconds."""
        cutoff = now - self.window_seconds
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def _parse_line(self, line: str) -> dict | None:
        line = line.strip()
        if not line:
            return None
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            return None

    def _wait_for_log(self):
        """Block until the log file exists."""
        while not os.path.exists(self.log_path):
            logger.info(f"Waiting for log file: {self.log_path}")
            time.sleep(2)

    def run(self):
        self._wait_for_log()
        logger.info(f"Tailing log: {self.log_path}")

        with open(self.log_path, "r") as f:
            # Seek to end so we only process new lines
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.05)
                    continue

                entry = self._parse_line(line)
                if not entry:
                    continue

                self.shared_state["log_lines_processed"] += 1
                self._process_entry(entry)

    def _process_entry(self, entry: dict):
        now = time.time()
        ip = entry.get("source_ip", "unknown")
        status = int(entry.get("status", 0))
        is_error = status >= 400

        # --- Update per-IP sliding window ---
        ip_dq = self.ip_windows[ip]
        ip_dq.append(now)
        self._evict_old(ip_dq, now)

        # --- Update per-IP error window ---
        err_dq = self.ip_error_windows[ip]
        err_dq.append((now, is_error))
        self._evict_old_errors(err_dq, now)

        # --- Update global sliding window ---
        self.global_window.append(now)
        self._evict_old(self.global_window, now)

        # --- Compute rates ---
        ip_rate = len(ip_dq) / self.window_seconds
        global_rate = len(self.global_window) / self.window_seconds

        # Error rate for this IP
        errors = sum(1 for _, e in err_dq if e)
        ip_error_rate = errors / self.window_seconds

        # --- Update shared state for dashboard ---
        self.shared_state["global_rps"] = global_rate
        top = self.shared_state["top_ips"]
        top[ip] = top.get(ip, 0) + 1

        # --- Record for baseline ---
        self.baseline.record_request()

        # --- Feed detector ---
        self.detector.check_ip(ip, ip_rate, ip_error_rate, entry)
