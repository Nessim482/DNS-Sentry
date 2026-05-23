"""Demo mode for DNS-Sentry without real network capture."""

import logging
from pathlib import Path

from .alerts import send_discord_alert, should_send_discord_alert
from .analyzer import analyze_domain
from .logging_config import LOGGER_NAME
from .reputation import check_reputation, load_domain_list
from .scoring import score_domain

_LOGGER = logging.getLogger(LOGGER_NAME)
_CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"

_DEMO_DOMAINS = (
    "google.com",
    "api.github.com",
    "dGhpcy1sb29rcy1saWtlLWJhc2U2NC1kYXRh.attacker.com",
    "x9kLmN2pQ7rT4vB8sH6zY3cA1.example.net",
)


def _load_optional_domain_list(filename: str) -> set[str]:
    path = _CONFIG_DIR / filename

    if not path.is_file():
        return set()

    try:
        return load_domain_list(str(path))
    except OSError:
        _LOGGER.warning("Could not load DNS reputation list name=%s", filename)
        return set()


def _build_reputation_result(domain: str) -> dict:
    return check_reputation(
        domain,
        whitelist=_load_optional_domain_list("whitelist.txt"),
        blacklist=_load_optional_domain_list("blacklist.txt"),
        iocs=_load_optional_domain_list("iocs.txt"),
    )


def _enrich_demo_result(result: dict, threshold: float) -> dict:
    try:
        scoring_result = score_domain(
            str(result["domain"]),
            threshold=threshold,
            telemetry_result={},
            reputation_result=_build_reputation_result(str(result["domain"])),
        )
    except Exception:
        _LOGGER.warning("DNS scoring failed for demo domain=%s", result["domain"])
        fallback_action = "alert" if result.get("suspicious") else "log"
        enriched_result = dict(result)
        enriched_result.update(
            {
                "risk_score": None,
                "severity": "Unknown",
                "action": fallback_action,
                "reasons": [
                    "Scoring unavailable; entropy analysis used as fallback.",
                ],
            }
        )
        return enriched_result

    enriched_result = dict(result)
    enriched_result.update(
        {
            "risk_score": scoring_result["risk_score"],
            "severity": scoring_result["severity"],
            "action": scoring_result["action"],
            "reasons": scoring_result["reasons"],
        }
    )
    return enriched_result


def run_demo(threshold: float = 3.5, webhook_url: str | None = None) -> None:
    """Run DNS-Sentry against simulated DNS domains only."""
    _LOGGER.info("Starting DNS-Sentry demo mode")

    for domain in _DEMO_DOMAINS:
        result = analyze_domain(domain, threshold=threshold)
        result = _enrich_demo_result(result, threshold)

        if result["suspicious"] or should_send_discord_alert(result.get("action")):
            _LOGGER.warning(
                "ALERT demo DNS query domain=%s entropy=%.1f suspicious=%s "
                "risk_score=%s severity=%s action=%s",
                result["domain"],
                result["entropy"],
                result["suspicious"],
                result.get("risk_score", "N/A"),
                result.get("severity", "N/A"),
                result.get("action", "N/A"),
            )

            if webhook_url is not None and should_send_discord_alert(
                result.get("action")
            ):
                send_discord_alert(result, webhook_url)
        else:
            _LOGGER.info(
                "INFO demo DNS query domain=%s entropy=%.1f suspicious=%s "
                "risk_score=%s severity=%s action=%s",
                result["domain"],
                result["entropy"],
                result["suspicious"],
                result.get("risk_score", "N/A"),
                result.get("severity", "N/A"),
                result.get("action", "N/A"),
            )

