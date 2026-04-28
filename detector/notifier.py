"""
notifier.py — Sends Slack webhook alerts for ban, unban, and global anomaly events.
Webhook URL is read from config.yaml.
"""

import requests
import logging
import time

logger = logging.getLogger("notifier")


class Notifier:
    def __init__(self, config):
        self.webhook_url = config["slack"]["webhook_url"]

    def _post(self, payload: dict):
        if not self.webhook_url or "YOUR/WEBHOOK" in self.webhook_url:
            logger.warning("Slack webhook not configured — skipping notification")
            return
        try:
            resp = requests.post(self.webhook_url, json=payload, timeout=8)
            if resp.status_code != 200:
                logger.error(f"Slack returned {resp.status_code}: {resp.text}")
        except Exception as e:
            logger.error(f"Slack notification failed: {e}")

    def send_ban_alert(self, ip: str, condition: str, rate: float, baseline: float, duration: str):
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        text = (
            f":rotating_light: *IP BANNED*\n"
            f"• IP: `{ip}`\n"
            f"• Condition: {condition}\n"
            f"• Current rate: `{rate:.2f} req/s`\n"
            f"• Baseline mean: `{baseline:.2f} req/s`\n"
            f"• Ban duration: `{duration}`\n"
            f"• Timestamp: `{ts}`"
        )
        self._post({"text": text})
        logger.info(f"Slack ban alert sent for {ip}")

    def send_unban_alert(self, ip: str, ban_count: int, condition: str):
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        text = (
            f":white_check_mark: *IP UNBANNED*\n"
            f"• IP: `{ip}`\n"
            f"• Ban count: `{ban_count}`\n"
            f"• Original condition: {condition}\n"
            f"• Timestamp: `{ts}`"
        )
        self._post({"text": text})
        logger.info(f"Slack unban alert sent for {ip}")

    def send_global_alert(self, condition: str, rate: float, baseline: float):
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        text = (
            f":warning: *GLOBAL TRAFFIC ANOMALY*\n"
            f"• Condition: {condition}\n"
            f"• Global rate: `{rate:.2f} req/s`\n"
            f"• Baseline mean: `{baseline:.2f} req/s`\n"
            f"• Timestamp: `{ts}`"
        )
        self._post({"text": text})
        logger.info("Slack global anomaly alert sent")
