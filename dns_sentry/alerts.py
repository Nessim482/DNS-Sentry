"""Minimal Discord alerting helpers for DNS-Sentry."""

from datetime import datetime, timezone
import logging
from time import monotonic
from urllib.parse import urlparse

import requests

from .config import load_discord_webhook_url
from .logging_config import LOGGER_NAME, mask_sensitive_text

_HTTP_TIMEOUT_SECONDS = 3.0
_ALERT_WINDOW_SECONDS = 60.0
_RECENT_ALERTS: dict[tuple[str, str], float] = {}
_LOGGER = logging.getLogger(LOGGER_NAME)
ALERT_ACTIONS = {
    "alert",
    "strong_alert",
    "quarantine",
    "quarantine_and_containment",
}
_SEVERITY_COLORS = {
    "Safe": 0x2ECC71,
    "Low Suspicious": 0xF1C40F,
    "Suspicious": 0xE67E22,
    "Medium": 0xE67E22,
    "High Risk": 0xE74C3C,
    "High": 0xE74C3C,
    "Dangerous": 0xC0392B,
    "Critical": 0xC0392B,
}


def _is_valid_webhook_url(webhook_url: str) -> bool:
    parsed_url = urlparse(webhook_url.strip())

    return parsed_url.scheme in {"http", "https"} and bool(parsed_url.netloc)


def _severity_for_entropy(entropy: float, threshold: float) -> str:
    if entropy >= threshold + 1.2:
        return "Critical"

    if entropy >= threshold + 0.7:
        return "High"

    return "Medium"


def should_send_discord_alert(action: object | None) -> bool:
    """Return whether a scored action should trigger Discord alerting."""
    return str(action or "").strip().lower() in ALERT_ACTIONS


def _format_risk_score(value: object) -> str:
    if value is None:
        return "N/A"

    try:
        return str(int(value))
    except (TypeError, ValueError):
        return str(value)


def _format_top_reasons(reasons: object) -> str:
    if not isinstance(reasons, list) or not reasons:
        return "N/A"

    safe_reasons = [mask_sensitive_text(str(reason)) for reason in reasons[:3]]
    return "\n".join(f"- {reason}" for reason in safe_reasons)


def _format_bool(value: object) -> str:
    return "Yes" if bool(value) else "No"


def _build_discord_payload(result: dict, timestamp: str) -> dict[str, object]:
    domain = str(result["domain"])
    subdomain = str(result.get("subdomain") or "N/A")
    entropy = float(result["entropy"])
    threshold = float(result["threshold"])
    entropy_severity = _severity_for_entropy(entropy, threshold)
    severity = str(result.get("severity") or entropy_severity)
    action = str(result.get("action") or "alert")
    color = _SEVERITY_COLORS.get(severity, _SEVERITY_COLORS[entropy_severity])

    return {
        "embeds": [
            {
                "title": "DNS-Sentry Alert: Suspicious DNS Query",
                "description": (
                    "A DNS query with high-entropy characteristics was detected."
                ),
                "color": color,
                "fields": [
                    {"name": "Domain", "value": domain, "inline": False},
                    {"name": "Subdomain", "value": subdomain, "inline": False},
                    {"name": "Entropy", "value": f"{entropy:.2f}", "inline": True},
                    {"name": "Threshold", "value": f"{threshold:.2f}", "inline": True},
                    {"name": "Detection", "value": entropy_severity, "inline": True},
                    {
                        "name": "Risk Score",
                        "value": _format_risk_score(result.get("risk_score")),
                        "inline": True,
                    },
                    {"name": "Severity", "value": severity, "inline": True},
                    {"name": "Action", "value": action, "inline": True},
                    {
                        "name": "Quarantine",
                        "value": _format_bool(result.get("quarantined")),
                        "inline": True,
                    },
                    {
                        "name": "Containment Required",
                        "value": _format_bool(result.get("containment_required")),
                        "inline": True,
                    },
                    {
                        "name": "Top Reasons",
                        "value": _format_top_reasons(result.get("reasons")),
                        "inline": False,
                    },
                    {"name": "Timestamp UTC", "value": timestamp, "inline": False},
                ],
                "footer": {"text": "DNS-Sentry • Defensive DNS Monitoring"},
            }
        ]
    }


def send_discord_alert(result: dict, webhook_url: str | None = None) -> bool:
    """Send a minimal Discord webhook alert for a suspicious DNS result."""
    if "action" in result and not should_send_discord_alert(result.get("action")):
        _LOGGER.debug("Discord alert skipped: action=%s", result.get("action"))
        return False

    effective_webhook_url = webhook_url or load_discord_webhook_url()

    if effective_webhook_url is None:
        _LOGGER.debug("Discord alert skipped: webhook not configured")
        return False

    if not _is_valid_webhook_url(effective_webhook_url):
        _LOGGER.warning("Discord alert failed: invalid webhook URL")
        return False

    domain = str(result["domain"])
    alert_key = (effective_webhook_url, domain)
    current_time = monotonic()
    previous_alert_time = _RECENT_ALERTS.get(alert_key)

    if (
        previous_alert_time is not None
        and current_time - previous_alert_time < _ALERT_WINDOW_SECONDS
    ):
        _LOGGER.debug("Discord alert skipped: duplicate alert suppressed")
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
        _LOGGER.warning("Discord alert failed: request timed out")
        return False
    except requests.RequestException:
        _LOGGER.warning("Discord alert failed: network error")
        return False

    if 200 <= response.status_code < 300:
        _RECENT_ALERTS[alert_key] = current_time
        _LOGGER.info("Discord alert sent for domain=%s", domain)
        return True

    _LOGGER.warning(
        "Discord alert failed: webhook returned status=%s",
        response.status_code,
    )
    return False
