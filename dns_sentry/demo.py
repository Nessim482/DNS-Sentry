"""Demo mode for DNS-Sentry without real network capture."""

from collections.abc import Callable
import logging
from pathlib import Path

from .alerts import send_discord_alert, should_send_discord_alert
from .analyzer import analyze_domain
from .logging_config import LOGGER_NAME
from .quarantine import apply_action
from .reputation import check_reputation, load_domain_list
from .scoring import ThresholdConfig, score_domain

_LOGGER = logging.getLogger(LOGGER_NAME)
_CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"

_DEMO_DOMAINS = (
    "google.com",
    "api.github.com",
    "dGhpcy1sb29rcy1saWtlLWJhc2U2NC1kYXRh.attacker.com",
    "x9kLmN2pQ7rT4vB8sH6zY3cA1.example.net",
    "simulated-quarantine.malicious-example.test",
    "abcdefghijklmnopqrstuvwxyz1234.malicious-example.test",
)
_DEMO_BEHAVIOR_OVERRIDES = {
    "simulated-quarantine.malicious-example.test": {
        "repeated_queries": True,
        "many_unique_subdomains": True,
        "high_nxdomain_ratio": True,
        "possible_beaconing": True,
        "unusual_record_type": True,
    },
    "abcdefghijklmnopqrstuvwxyz1234.malicious-example.test": {
        "repeated_queries": True,
        "many_unique_subdomains": True,
        "high_nxdomain_ratio": True,
        "possible_beaconing": True,
        "unusual_record_type": True,
    },
}
_DEMO_CONTEXT_OVERRIDES = {
    "simulated-quarantine.malicious-example.test": {
        "sensitive_host": True,
        "unusual_activity_time": True,
    },
    "abcdefghijklmnopqrstuvwxyz1234.malicious-example.test": {
        "sensitive_host": True,
        "unusual_activity_time": True,
    },
}


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


def _enrich_with_action_decision(result: dict) -> dict:
    try:
        action_result = apply_action(result)
    except Exception:
        _LOGGER.warning("DNS action decision failed for demo domain=%s", result["domain"])
        enriched_result = dict(result)
        enriched_result.update(
            {
                "applied": False,
                "quarantined": False,
                "containment_required": False,
                "quarantine_message": "Logical quarantine decision unavailable.",
            }
        )
        return enriched_result

    enriched_result = dict(result)
    enriched_result.update(
        {
            "domain": action_result["domain"],
            "action": action_result["action"],
            "applied": action_result["applied"],
            "quarantined": action_result["quarantined"],
            "containment_required": action_result["containment_required"],
            "quarantine_message": action_result["message"],
        }
    )
    return enriched_result


def _enrich_demo_result(
    result: dict,
    threshold: float,
    threshold_config: ThresholdConfig | None = None,
) -> dict:
    domain = str(result["domain"])
    telemetry_result = _DEMO_BEHAVIOR_OVERRIDES.get(domain, {})
    context = _DEMO_CONTEXT_OVERRIDES.get(domain, {})

    try:
        scoring_kwargs = {
            "threshold": threshold,
            "telemetry_result": telemetry_result,
            "reputation_result": _build_reputation_result(domain),
            "context": context,
        }
        if threshold_config is not None:
            scoring_kwargs["threshold_config"] = threshold_config

        scoring_result = score_domain(domain, **scoring_kwargs)
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
        return _enrich_with_action_decision(enriched_result)

    enriched_result = dict(result)
    enriched_result.update(
        {
            "risk_score": scoring_result["risk_score"],
            "severity": scoring_result["severity"],
            "action": scoring_result["action"],
            "reasons": scoring_result["reasons"],
        }
    )
    return _enrich_with_action_decision(enriched_result)


def _notify_result_callback(
    result: dict,
    result_callback: Callable[[dict], None] | None,
) -> None:
    if result_callback is None:
        return

    try:
        result_callback(dict(result))
    except Exception:
        _LOGGER.warning("DNS demo result callback failed for domain=%s", result["domain"])


def run_demo(
    threshold: float = 3.5,
    webhook_url: str | None = None,
    result_callback: Callable[[dict], None] | None = None,
    threshold_config: ThresholdConfig | None = None,
) -> None:
    """Run DNS-Sentry against simulated DNS domains only."""
    _LOGGER.info("Starting DNS-Sentry demo mode")

    for domain in _DEMO_DOMAINS:
        result = analyze_domain(domain, threshold=threshold)
        result = _enrich_demo_result(result, threshold, threshold_config)

        if result["suspicious"] or should_send_discord_alert(result.get("action")):
            _LOGGER.warning(
                "ALERT demo DNS query domain=%s entropy=%.1f suspicious=%s "
                "risk_score=%s severity=%s action=%s applied=%s quarantined=%s "
                "containment_required=%s quarantine_message=%s",
                result["domain"],
                result["entropy"],
                result["suspicious"],
                result.get("risk_score", "N/A"),
                result.get("severity", "N/A"),
                result.get("action", "N/A"),
                result.get("applied", "N/A"),
                result.get("quarantined", "N/A"),
                result.get("containment_required", "N/A"),
                result.get("quarantine_message", "N/A"),
            )
            _notify_result_callback(result, result_callback)

            if webhook_url is not None and should_send_discord_alert(
                result.get("action")
            ):
                send_discord_alert(result, webhook_url)
        else:
            _LOGGER.info(
                "INFO demo DNS query domain=%s entropy=%.1f suspicious=%s "
                "risk_score=%s severity=%s action=%s applied=%s quarantined=%s "
                "containment_required=%s quarantine_message=%s",
                result["domain"],
                result["entropy"],
                result["suspicious"],
                result.get("risk_score", "N/A"),
                result.get("severity", "N/A"),
                result.get("action", "N/A"),
                result.get("applied", "N/A"),
                result.get("quarantined", "N/A"),
                result.get("containment_required", "N/A"),
                result.get("quarantine_message", "N/A"),
            )
            _notify_result_callback(result, result_callback)

