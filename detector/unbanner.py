"""
unbanner.py — Periodically checks banned IPs and releases those whose
ban duration has expired. Follows the backoff schedule:
  ban 1 → 10 min, ban 2 → 30 min, ban 3 → 2 hours, ban 4+ → permanent.
Sends a Slack notification on every unban.
"""

import subprocess
import time
import logging
import threading

from audit import write_audit

logger = logging.getLogger("unbanner")

CHECK_INTERVAL = 10  # seconds between unban sweeps


class Unbanner:
    def __init__(self, config, notifier, shared_state):
        self.notifier = notifier
        self.shared_state = shared_state
        self.audit_path = config["audit_log"]["path"]
        self._lock = threading.Lock()

    def run(self):
        while True:
            time.sleep(CHECK_INTERVAL)
            self._sweep()

    def _sweep(self):
        now = time.time()
        banned = self.shared_state["banned_ips"]

        to_unban = []
        with self._lock:
            for ip, info in list(banned.items()):
                if info.get("permanent"):
                    continue
                ban_until = info.get("ban_until")
                if ban_until and now >= ban_until:
                    to_unban.append(ip)

        for ip in to_unban:
            self._unban(ip)

    def _unban(self, ip: str):
        with self._lock:
            info = self.shared_state["banned_ips"].pop(ip, None)

        if not info:
            return

        self._iptables_remove(ip)

        ban_count = info.get("ban_count", 1)
        condition = info.get("condition", "unknown")
        rate = info.get("rate", 0.0)
        baseline = info.get("baseline", 0.0)

        logger.info(f"UNBANNED {ip} after ban #{ban_count}")

        write_audit(
            self.audit_path,
            action="UNBAN",
            ip=ip,
            condition=condition,
            rate=rate,
            baseline=baseline,
            duration=f"ban_count={ban_count}",
        )

        threading.Thread(
            target=self.notifier.send_unban_alert,
            args=(ip, ban_count, condition),
            daemon=True,
        ).start()

    def _iptables_remove(self, ip: str):
        """Remove the DROP rule for this IP."""
        try:
            # Remove all matching rules (loop in case duplicates exist)
            while True:
                result = subprocess.run(
                    ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                    capture_output=True,
                )
                if result.returncode != 0:
                    break
            logger.info(f"iptables DROP rule removed for {ip}")
        except FileNotFoundError:
            logger.warning("iptables not found — skipping rule removal")
        except Exception as e:
            logger.error(f"Failed to remove iptables rule for {ip}: {e}")
