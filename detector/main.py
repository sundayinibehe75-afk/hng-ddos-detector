"""
main.py — Entry point. Wires all components together and starts threads.
"""

import threading
import logging
import time
import yaml
import os

from monitor import LogMonitor
from baseline import BaselineTracker
from detector import AnomalyDetector
from blocker import Blocker
from unbanner import Unbanner
from notifier import Notifier
from dashboard import start_dashboard

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("main")


def load_config(path="config.yaml"):
    with open(path, "r") as f:
        return yaml.safe_load(f)


def ensure_dirs(config):
    audit_dir = os.path.dirname(config["audit_log"]["path"])
    os.makedirs(audit_dir, exist_ok=True)


def main():
    config = load_config()
    ensure_dirs(config)

    logger.info("Starting HNG Anomaly Detection Engine")

    # Shared state
    shared_state = {
        "banned_ips": {},        # ip -> {ban_count, ban_until, reason}
        "global_rps": 0.0,
        "top_ips": {},           # ip -> request count in last window
        "baseline_stats": {},    # {"mean": x, "stddev": y, "hour": h}
        "uptime_start": time.time(),
        "log_lines_processed": 0,
    }

    notifier = Notifier(config)
    blocker = Blocker(config, notifier, shared_state)
    unbanner = Unbanner(config, notifier, shared_state)
    baseline = BaselineTracker(config)
    detector = AnomalyDetector(config, baseline, blocker, notifier, shared_state)
    monitor = LogMonitor(config, detector, baseline, shared_state)

    # Start threads
    threads = [
        threading.Thread(target=monitor.run, name="LogMonitor", daemon=True),
        threading.Thread(target=baseline.run, name="BaselineTracker", daemon=True),
        threading.Thread(target=unbanner.run, name="Unbanner", daemon=True),
        threading.Thread(target=detector.run_global_check, name="GlobalDetector", daemon=True),
    ]

    for t in threads:
        t.start()
        logger.info(f"Started thread: {t.name}")

    # Start dashboard (blocking — runs in main thread via Flask)
    start_dashboard(config, shared_state, baseline)


if __name__ == "__main__":
    main()
