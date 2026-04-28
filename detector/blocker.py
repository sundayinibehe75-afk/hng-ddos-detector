"""
blocker.py — Adds iptables DROP rules for anomalous IPs and records
the ban in shared state. Sends a Slack alert within 10 seconds.
"""

import subprocess
import time
import logging
import threading

from audit import write_audit

logger = logging.getLogger("blocker")


class Blocker:
    def __init__(self, config, notifier, shared_state):
        self.notifier = notifier
        self.shared_state = shared_state
        self.audit_path = config["audit_log"]["path"]
        self.ban_schedule = config["ban"]["schedule_minutes"]
        self._lock = threading.Lock()

    def ban(self, ip: str, condition: str, rate: float, baseline: float):
        """
        Add iptables DROP rule for ip and record the ban.
        Ban duration follows the backoff schedule based on how many
        times this IP has been banned before.
        """
        with self._lock:
            banned = self.shared_state["banned_ips"]

            if ip in banned and banned[ip].get("permanent"):
                logger.info(f"IP {ip} already permanently banned.")
                return

            ban_count = banned.get(ip, {}).get("ban_count", 0)

            # Determine duration
            schedule = self.ban_schedule  # [10, 30, 120]
            if ban_count < len(schedule):
                duration_minutes = schedule[ban_count]
                permanent = False
            else:
                duration_minutes = None
                permanent = True

            ban_until = (
                time.time() + duration_minutes * 60
                if not permanent
                else None
            )

            banned[ip] = {
                "ban_count": ban_count + 1,
                "ban_until": ban_until,
                "permanent": permanent,
                "condition": condition,
                "rate": rate,
                "baseline": baseline,
                "banned_at": time.time(),
            }

        # Apply iptables rule
        self._iptables_drop(ip)

        duration_str = f"{duration_minutes}min" if not permanent else "permanent"
        logger.warning(
            f"BANNED {ip} | {condition} | rate={rate:.2f} | "
            f"baseline={baseline:.2f} | duration={duration_str}"
        )

        write_audit(
            self.audit_path,
            action="BAN",
            ip=ip,
            condition=condition,
            rate=rate,
            baseline=baseline,
            duration=duration_str,
        )

        # Slack alert (non-blocking)
        threading.Thread(
            target=self.notifier.send_ban_alert,
            args=(ip, condition, rate, baseline, duration_str),
            daemon=True,
        ).start()

    def _iptables_drop(self, ip: str):
        """Insert a DROP rule at the top of INPUT chain."""
        try:
            # Check if rule already exists
            check = subprocess.run(
                ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True,
            )
            if check.returncode == 0:
                logger.debug(f"iptables rule already exists for {ip}")
                return

            subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
                capture_output=True,
            )
            logger.info(f"iptables DROP rule added for {ip}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to add iptables rule for {ip}: {e}")
        except FileNotFoundError:
            logger.warning("iptables not found — running without blocking capability")
