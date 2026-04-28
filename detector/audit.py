"""
audit.py — Writes structured audit log entries.
Format: [timestamp] ACTION ip | condition | rate | baseline | duration
"""

import time
import os
import threading

_lock = threading.Lock()


def write_audit(path: str, action: str, ip: str, condition: str,
                rate: float, baseline: float, duration: str):
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    line = (
        f"[{ts}] {action} {ip} | {condition} | "
        f"rate={rate:.3f} | baseline={baseline:.3f} | duration={duration}\n"
    )
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with _lock:
            with open(path, "a") as f:
                f.write(line)
    except Exception as e:
        import logging
        logging.getLogger("audit").error(f"Failed to write audit log: {e}")
