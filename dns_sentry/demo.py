"""Demo mode for DNS-Sentry without real network capture."""

import logging

from .alerts import send_discord_alert
from .analyzer import analyze_domain
from .logging_config import LOGGER_NAME

_LOGGER = logging.getLogger(LOGGER_NAME)

_DEMO_DOMAINS = (
    "google.com",
    "api.github.com",
    "dGhpcy1sb29rcy1saWtlLWJhc2U2NC1kYXRh.attacker.com",
    "x9kLmN2pQ7rT4vB8sH6zY3cA1.example.net",
)


def run_demo(threshold: float = 3.5, webhook_url: str | None = None) -> None:
    """Run DNS-Sentry against simulated DNS domains only."""
    _LOGGER.info("Starting DNS-Sentry demo mode")

    for domain in _DEMO_DOMAINS:
        result = analyze_domain(domain, threshold=threshold)

        if result["suspicious"]:
            _LOGGER.warning(
                "ALERT demo DNS query domain=%s entropy=%.1f suspicious=%s",
                result["domain"],
                result["entropy"],
                result["suspicious"],
            )

            if webhook_url is not None:
                send_discord_alert(result, webhook_url)
        else:
            _LOGGER.info(
                "INFO demo DNS query domain=%s entropy=%.1f suspicious=%s",
                result["domain"],
                result["entropy"],
                result["suspicious"],
            )

