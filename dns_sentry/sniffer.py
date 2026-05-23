"""Minimal real-time DNS sniffer for DNS-Sentry."""

from collections.abc import Callable
import logging
from pathlib import Path
from typing import Any

from .alerts import send_discord_alert, should_send_discord_alert
from .analyzer import analyze_domain
from .config import (
    load_discord_webhook_url,
    load_dns_debug,
    load_dns_entropy_threshold,
    load_dns_interface,
)
from .logging_config import LOGGER_NAME, setup_logging
from .parser import parse_dns_query
from .quarantine import apply_action
from .reputation import check_reputation, load_domain_list
from .scoring import score_domain
from .telemetry import analyze_behavior, get_domain_stats, record_query

_DNS_CAPTURE_FILTER = "udp and dst port 53"
_LOGGER = logging.getLogger(LOGGER_NAME)
_SNIFFING_ERROR_MESSAGE = (
    "Live DNS sniffing requires Scapy and a packet capture driver. "
    "On Windows, install Npcap and run the terminal as Administrator."
)
_CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"
_QTYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    10: "NULL",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}


def _load_scapy() -> tuple[Any, Any, Any, Callable[..., Any]]:
    try:
        from scapy.all import DNS, DNSQR, UDP, sniff
    except ImportError as error:
        raise RuntimeError(_SNIFFING_ERROR_MESSAGE) from error

    return DNS, DNSQR, UDP, sniff


def _has_layer(packet: object, layer: object) -> bool:
    haslayer = getattr(packet, "haslayer", None)

    if haslayer is None:
        return False

    return bool(haslayer(layer))


def _extract_query_domain(
    packet: object,
    dns_layer: object,
    dns_query_layer: object,
    udp_layer: object,
) -> str | None:
    if not _has_layer(packet, dns_layer) or not _has_layer(packet, dns_query_layer):
        return None

    if not _has_layer(packet, udp_layer):
        return None

    dns = packet[dns_layer]  # type: ignore[index]
    udp = packet[udp_layer]  # type: ignore[index]

    if getattr(dns, "qr", None) != 0 or getattr(udp, "dport", None) != 53:
        return None

    query = packet[dns_query_layer]  # type: ignore[index]
    query_name = getattr(query, "qname", None)

    if query_name is None:
        return None

    if isinstance(query_name, bytes):
        return query_name.decode("utf-8", errors="ignore").rstrip(".").lower()

    return str(query_name).rstrip(".").lower()


def _extract_query_record_type(packet: object, dns_query_layer: object) -> str:
    if not _has_layer(packet, dns_query_layer):
        return "A"

    query = packet[dns_query_layer]  # type: ignore[index]
    qtype = getattr(query, "qtype", None)

    if qtype is None:
        return "A"

    if isinstance(qtype, int):
        return _QTYPE_NAMES.get(qtype, str(qtype))

    return str(qtype).strip().upper() or "UNKNOWN"


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


def _build_telemetry_result(domain: str, record_type: str) -> dict:
    record_query(domain, record_type=record_type)
    telemetry_result = analyze_behavior(domain)
    telemetry_result["record_types"] = get_domain_stats(domain)["record_types"]

    if record_type in {"TXT", "NULL"}:
        telemetry_result["unusual_record_type"] = True

    return telemetry_result


def _enrich_with_scoring(
    result: dict,
    telemetry_result: dict | None,
    reputation_result: dict | None,
    threshold: float,
) -> dict:
    try:
        scoring_result = score_domain(
            str(result["domain"]),
            threshold=threshold,
            telemetry_result=telemetry_result,
            reputation_result=reputation_result,
        )
    except Exception:
        _LOGGER.warning("DNS scoring failed for domain=%s", result["domain"])
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


def _enrich_with_action_decision(result: dict) -> dict:
    try:
        action_result = apply_action(result)
    except Exception:
        _LOGGER.warning("DNS action decision failed for domain=%s", result["domain"])
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


def _log_dns_result(result: dict) -> None:
    log_values = (
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

    if result["suspicious"] or should_send_discord_alert(result.get("action")):
        _LOGGER.warning(
            "Suspicious DNS query detected domain=%s entropy=%.1f "
            "suspicious=%s risk_score=%s severity=%s action=%s applied=%s "
            "quarantined=%s containment_required=%s quarantine_message=%s",
            *log_values,
        )
        return

    _LOGGER.info(
        "DNS query observed domain=%s entropy=%.1f suspicious=%s "
        "risk_score=%s severity=%s action=%s applied=%s quarantined=%s "
        "containment_required=%s quarantine_message=%s",
        *log_values,
    )


def _is_stop_requested(stop_event: object | None) -> bool:
    if stop_event is None:
        return False

    is_set = getattr(stop_event, "is_set", None)

    if is_set is None:
        return False

    return bool(is_set())


def _handle_dns_packet(
    packet: object,
    dns_layer: object,
    dns_query_layer: object,
    udp_layer: object,
    webhook_url: str | None = None,
    threshold: float = 3.5,
) -> dict | None:
    query_domain = _extract_query_domain(packet, dns_layer, dns_query_layer, udp_layer)

    if query_domain is None:
        return None

    domain = parse_dns_query(f"DNS_REQ {query_domain}")

    if domain is None:
        return None

    record_type = _extract_query_record_type(packet, dns_query_layer)
    result = analyze_domain(domain, threshold=threshold)
    telemetry_result = _build_telemetry_result(str(result["domain"]), record_type)
    reputation_result = _build_reputation_result(str(result["domain"]))
    result = _enrich_with_scoring(
        result,
        telemetry_result=telemetry_result,
        reputation_result=reputation_result,
        threshold=threshold,
    )
    result = _enrich_with_action_decision(result)

    _log_dns_result(result)

    if webhook_url is not None and should_send_discord_alert(result.get("action")):
        send_discord_alert(result, webhook_url)

    return result


def start_dns_sniffer(
    interface: str | None = None,
    webhook_url: str | None = None,
    threshold: float | None = None,
    debug: bool | None = None,
    stop_event: object | None = None,
) -> None:
    """Start a minimal DNS-only sniffer for outgoing DNS queries."""
    dns_layer, dns_query_layer, udp_layer, sniff = _load_scapy()
    effective_interface = interface if interface is not None else load_dns_interface()
    effective_webhook_url = (
        webhook_url if webhook_url is not None else load_discord_webhook_url()
    )
    effective_threshold = (
        threshold if threshold is not None else load_dns_entropy_threshold()
    )
    effective_debug = debug if debug is not None else load_dns_debug()
    logger = logging.getLogger(LOGGER_NAME)

    if logger.handlers:
        level = logging.DEBUG if effective_debug else logging.INFO
        logger.setLevel(level)

        for handler in logger.handlers:
            handler.setLevel(level)
    else:
        setup_logging(debug=bool(effective_debug))

    if effective_debug:
        _LOGGER.debug("DNS sniffer filter=%s", _DNS_CAPTURE_FILTER)

    sniff_kwargs: dict[str, Any] = {
        "filter": _DNS_CAPTURE_FILTER,
        "prn": lambda packet: _handle_dns_packet(
            packet,
            dns_layer,
            dns_query_layer,
            udp_layer,
            effective_webhook_url,
            effective_threshold,
        ),
        "store": False,
    }

    if effective_interface is not None:
        sniff_kwargs["iface"] = effective_interface

    try:
        if stop_event is None:
            sniff(**sniff_kwargs)
            return

        while not _is_stop_requested(stop_event):
            sniff(
                **sniff_kwargs,
                timeout=1,
                stop_filter=lambda _packet: _is_stop_requested(stop_event),
            )
    except Exception as error:
        raise RuntimeError(_SNIFFING_ERROR_MESSAGE) from error
