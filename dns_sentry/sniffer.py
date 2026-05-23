"""Minimal real-time DNS sniffer for DNS-Sentry."""

from collections.abc import Callable
from typing import Any

from .analyzer import analyze_domain
from .parser import parse_dns_query

_DNS_CAPTURE_FILTER = "udp and dst port 53"


def _load_scapy() -> tuple[Any, Any, Any, Callable[..., Any]]:
    try:
        from scapy.all import DNS, DNSQR, UDP, sniff
    except ImportError as error:
        raise RuntimeError(
            "Scapy is required to start DNS sniffing. "
            "Install it with: python -m pip install scapy"
        ) from error

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


def _handle_dns_packet(
    packet: object,
    dns_layer: object,
    dns_query_layer: object,
    udp_layer: object,
) -> dict[str, str | float | bool] | None:
    query_domain = _extract_query_domain(packet, dns_layer, dns_query_layer, udp_layer)

    if query_domain is None:
        return None

    domain = parse_dns_query(f"DNS_REQ {query_domain}")

    if domain is None:
        return None

    result = analyze_domain(domain)
    level = "ALERT" if result["suspicious"] else "INFO"

    print(
        f"[{level}] {result['domain']} "
        f"entropy={result['entropy']:.1f} suspicious={result['suspicious']}"
    )

    return result


def start_dns_sniffer(interface: str | None = None) -> None:
    """Start a minimal DNS-only sniffer for outgoing DNS queries."""
    dns_layer, dns_query_layer, udp_layer, sniff = _load_scapy()

    sniff_kwargs: dict[str, Any] = {
        "filter": _DNS_CAPTURE_FILTER,
        "prn": lambda packet: _handle_dns_packet(
            packet, dns_layer, dns_query_layer, udp_layer
        ),
        "store": False,
    }

    if interface is not None:
        sniff_kwargs["iface"] = interface

    sniff(**sniff_kwargs)

