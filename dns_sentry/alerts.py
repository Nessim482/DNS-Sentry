"""Minimal Discord alerting helpers for DNS-Sentry."""

from datetime import datetime, timezone
from time import monotonic
from urllib.parse import urlparse

import requests

from .config import load_discord_webhook_url

_HTTP_TIMEOUT_SECONDS = 3.0
_ALERT_WINDOW_SECONDS = 60.0
_RECENT_ALERTS: dict[tuple[str, str], float] = {}


def _is_valid_webhook_url(webhook_url: str) -> bool:
    parsed_url = urlparse(webhook_url.strip())

    return parsed_url.scheme in {"http", "https"} and bool(parsed_url.netloc)


def _build_discord_payload(result: dict, timestamp: str) -> dict[str, str]:
    domain = str(result["domain"])
    entropy = float(result["entropy"])
    threshold = float(result["threshold"])
    suspicious = bool(result["suspicious"])

    return {
        "content": (
            "DNS-Sentry alert\n"
            f"domain: {domain}\n"
            f"entropy: {entropy:.2f}\n"
            f"threshold: {threshold:.2f}\n"
            f"suspicious: {suspicious}\n"
            f"timestamp: {timestamp}"
        )
    }


def send_discord_alert(result: dict, webhook_url: str | None = None) -> bool:
    """Send a minimal Discord webhook alert for a suspicious DNS result."""
    effective_webhook_url = webhook_url or load_discord_webhook_url()

    if effective_webhook_url is None:
        return False

    if not _is_valid_webhook_url(effective_webhook_url):
        return False

    domain = str(result["domain"])
    alert_key = (effective_webhook_url, domain)
    current_time = monotonic()
    previous_alert_time = _RECENT_ALERTS.get(alert_key)

    if (
        previous_alert_time is not None
        and current_time - previous_alert_time < _ALERT_WINDOW_SECONDS
    ):
        return False

    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    payload = _build_discord_payload(result, timestamp)

    try:
        response = requests.post(
            effective_webhook_url,
            json=payload,
            timeout=_HTTP_TIMEOUT_SECONDS,
        )
    except requests.Timeout:
        return False
    except requests.RequestException:
        return False

    if 200 <= response.status_code < 300:
        _RECENT_ALERTS[alert_key] = current_time
        return True

    return False
