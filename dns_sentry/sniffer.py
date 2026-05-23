"""Minimal real-time DNS sniffer for DNS-Sentry."""

from collections.abc import Callable
import logging
from typing import Any

from .alerts import send_discord_alert
from .analyzer import analyze_domain
from .config import (
    load_discord_webhook_url,
    load_dns_debug,
    load_dns_entropy_threshold,
    load_dns_interface,
)
from .logging_config import LOGGER_NAME, setup_logging
from .parser import parse_dns_query

_DNS_CAPTURE_FILTER = "udp and dst port 53"
_LOGGER = logging.getLogger(LOGGER_NAME)
_SNIFFING_ERROR_MESSAGE = (
    "Live DNS sniffing requires Scapy and a packet capture driver. "
    "On Windows, install Npcap and run the terminal as Administrator."
)


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
) -> dict[str, str | float | bool] | None:
    query_domain = _extract_query_domain(packet, dns_layer, dns_query_layer, udp_layer)

    if query_domain is None:
        return None

    domain = parse_dns_query(f"DNS_REQ {query_domain}")

    if domain is None:
        return None

    result = analyze_domain(domain, threshold=threshold)

    if result["suspicious"]:
        _LOGGER.warning(
            "Suspicious DNS query detected domain=%s entropy=%.1f suspicious=%s",
            result["domain"],
            result["entropy"],
            result["suspicious"],
        )
    else:
        _LOGGER.info(
            "DNS query observed domain=%s entropy=%.1f suspicious=%s",
            result["domain"],
            result["entropy"],
            result["suspicious"],
        )

    if result["suspicious"] and webhook_url is not None:
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
