"""Local UDP DNS proxy enforcement mode for DNS-Sentry."""

from __future__ import annotations

from collections.abc import Callable
import logging
from pathlib import Path
import socket
import threading
from typing import Any

from .analyzer import analyze_domain
from .config import load_dns_risk_thresholds
from .logging_config import LOGGER_NAME, setup_logging
from .quarantine import apply_action
from .reputation import check_reputation, load_domain_list
from .scoring import ThresholdConfig, score_domain
from .telemetry import analyze_behavior, get_domain_stats, record_query

_LOGGER = logging.getLogger(LOGGER_NAME)
_CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"
_BLOCK_ACTIONS = {"quarantine", "quarantine_and_containment"}
_FORWARD_ACTIONS = {"allow", "log", "alert", "strong_alert"}
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

SocketFactory = Callable[..., socket.socket]


def _read_query_name(packet: bytes, offset: int = 12) -> tuple[str | None, int | None]:
    labels: list[str] = []
    cursor = offset

    while cursor < len(packet):
        label_length = packet[cursor]
        cursor += 1

        if label_length == 0:
            if not labels:
                return None, None

            return ".".join(labels).lower(), cursor

        if label_length & 0xC0:
            return None, None

        if label_length > 63 or cursor + label_length > len(packet):
            return None, None

        label_bytes = packet[cursor : cursor + label_length]
        cursor += label_length
        label = label_bytes.decode("ascii", errors="ignore")

        if not label:
            return None, None

        labels.append(label)

    return None, None


def _question_end_offset(packet: bytes) -> int | None:
    if len(packet) < 12:
        return None

    _, name_end_offset = _read_query_name(packet)

    if name_end_offset is None or name_end_offset + 4 > len(packet):
        return None

    return name_end_offset + 4


def extract_query_domain(packet: bytes) -> str | None:
    """Extract the first DNS query domain from a raw UDP DNS packet."""
    if len(packet) < 12:
        return None

    flags = int.from_bytes(packet[2:4], byteorder="big")
    question_count = int.from_bytes(packet[4:6], byteorder="big")

    if flags & 0x8000 or question_count < 1:
        return None

    domain, name_end_offset = _read_query_name(packet)

    if domain is None or name_end_offset is None:
        return None

    if name_end_offset + 4 > len(packet):
        return None

    return domain.rstrip(".").lower()


def _extract_query_record_type(packet: bytes) -> str:
    _, name_end_offset = _read_query_name(packet)

    if name_end_offset is None or name_end_offset + 2 > len(packet):
        return "A"

    qtype = int.from_bytes(packet[name_end_offset : name_end_offset + 2], byteorder="big")
    return _QTYPE_NAMES.get(qtype, str(qtype))


def _build_error_response(query_packet: bytes, rcode: int) -> bytes:
    transaction_id = query_packet[:2] if len(query_packet) >= 2 else b"\x00\x00"
    query_flags = (
        int.from_bytes(query_packet[2:4], byteorder="big") if len(query_packet) >= 4 else 0
    )
    question_end = _question_end_offset(query_packet)
    question = query_packet[12:question_end] if question_end is not None else b""
    question_count = 1 if question else 0
    response_flags = 0x8000 | (query_flags & 0x0100) | (rcode & 0x000F)

    return b"".join(
        [
            transaction_id,
            response_flags.to_bytes(2, byteorder="big"),
            question_count.to_bytes(2, byteorder="big"),
            b"\x00\x00",
            b"\x00\x00",
            b"\x00\x00",
            question,
        ]
    )


def build_block_response(query_packet: bytes) -> bytes:
    """Build an NXDOMAIN response while preserving the DNS transaction ID."""
    return _build_error_response(query_packet, rcode=3)


def _build_servfail_response(query_packet: bytes) -> bytes:
    return _build_error_response(query_packet, rcode=2)


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


def _score_proxy_domain(
    domain: str,
    threshold: float,
    threshold_config: ThresholdConfig | None,
    record_type: str,
) -> dict:
    result = analyze_domain(domain, threshold=threshold)
    telemetry_result = _build_telemetry_result(str(result["domain"]), record_type)
    reputation_result = _build_reputation_result(str(result["domain"]))

    try:
        scoring_kwargs: dict[str, Any] = {
            "threshold": threshold,
            "telemetry_result": telemetry_result,
            "reputation_result": reputation_result,
        }
        if threshold_config is not None:
            scoring_kwargs["threshold_config"] = threshold_config

        scoring_result = score_domain(str(result["domain"]), **scoring_kwargs)
    except Exception:
        _LOGGER.warning("DNS proxy scoring failed for domain=%s", result["domain"])
        scoring_result = {
            "risk_score": None,
            "severity": "Unknown",
            "action": "alert" if result.get("suspicious") else "log",
            "reasons": ["Scoring unavailable; entropy analysis used as fallback."],
        }

    enriched_result = dict(result)
    enriched_result.update(
        {
            "risk_score": scoring_result["risk_score"],
            "severity": scoring_result["severity"],
            "action": scoring_result["action"],
            "reasons": scoring_result["reasons"],
        }
    )

    action_result = apply_action(enriched_result)
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


def _forward_to_upstream(
    packet: bytes,
    upstream_dns: str,
    upstream_port: int,
    socket_factory: SocketFactory,
    timeout: float = 5.0,
) -> bytes:
    with socket_factory(socket.AF_INET, socket.SOCK_DGRAM) as upstream_socket:
        upstream_socket.settimeout(timeout)
        upstream_socket.sendto(packet, (upstream_dns, upstream_port))
        response, _ = upstream_socket.recvfrom(4096)
        return response


def _notify_result_callback(
    result: dict,
    result_callback: Callable[[dict], None] | None,
) -> None:
    if result_callback is None:
        return

    try:
        result_callback(dict(result))
    except Exception:
        _LOGGER.warning("DNS proxy result callback failed for domain=%s", result["domain"])


def _log_proxy_decision(result: dict, blocked: bool) -> None:
    log_values = (
        result["domain"],
        result.get("risk_score", "N/A"),
        result.get("severity", "N/A"),
        result.get("action", "N/A"),
        result.get("quarantined", "N/A"),
    )

    if blocked:
        _LOGGER.warning(
            "DNS proxy blocked query domain=%s risk_score=%s severity=%s "
            "action=%s quarantined=%s",
            *log_values,
        )
        return

    _LOGGER.info(
        "DNS proxy forwarded query domain=%s risk_score=%s severity=%s "
        "action=%s quarantined=%s",
        *log_values,
    )


def handle_dns_query(
    packet: bytes,
    client_addr: tuple,
    socket_obj,
    upstream_dns: str = "1.1.1.1",
    upstream_port: int = 53,
    threshold: float = 4.0,
    threshold_config: ThresholdConfig | None = None,
    upstream_socket_factory: SocketFactory = socket.socket,
    result_callback: Callable[[dict], None] | None = None,
) -> None:
    """Handle one UDP DNS query, forwarding or blocking according to policy."""
    domain = extract_query_domain(packet)

    if domain is None:
        _LOGGER.warning("DNS proxy ignored malformed or unsupported DNS query")
        return

    record_type = _extract_query_record_type(packet)
    result = _score_proxy_domain(domain, threshold, threshold_config, record_type)
    action = str(result.get("action", "")).strip().lower()
    blocked = action in _BLOCK_ACTIONS or bool(result.get("quarantined"))
    _notify_result_callback(result, result_callback)
    _log_proxy_decision(result, blocked=blocked)

    if blocked:
        socket_obj.sendto(build_block_response(packet), client_addr)
        return

    if action not in _FORWARD_ACTIONS:
        _LOGGER.warning(
            "DNS proxy received unknown action=%s for domain=%s; returning SERVFAIL",
            action,
            domain,
        )
        socket_obj.sendto(_build_servfail_response(packet), client_addr)
        return

    try:
        upstream_response = _forward_to_upstream(
            packet,
            upstream_dns,
            upstream_port,
            socket_factory=upstream_socket_factory,
        )
    except OSError as error:
        _LOGGER.warning("DNS proxy upstream failed for domain=%s error=%s", domain, error)
        socket_obj.sendto(_build_servfail_response(packet), client_addr)
        return

    socket_obj.sendto(upstream_response, client_addr)


def _stop_requested(stop_event: threading.Event | None) -> bool:
    return stop_event is not None and stop_event.is_set()


def start_dns_proxy(
    listen_host: str = "127.0.0.1",
    listen_port: int = 5353,
    upstream_dns: str = "1.1.1.1",
    upstream_port: int = 53,
    threshold: float = 4.0,
    stop_event: threading.Event | None = None,
) -> None:
    """Start a local UDP DNS proxy that enforces quarantine decisions."""
    logger = setup_logging()
    threshold_config = load_dns_risk_thresholds()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns_socket:
        dns_socket.bind((listen_host, listen_port))
        dns_socket.settimeout(1.0)

        logger.info(
            "DNS proxy enforcement mode started on %s:%s",
            listen_host,
            listen_port,
        )
        logger.info(
            "DNS proxy enforcement only protects clients configured to use "
            "DNS-Sentry as their DNS resolver."
        )
        logger.info("Configure your system DNS to use DNS-Sentry to enforce blocking.")
        logger.info(
            "Port %s is useful for test/dev; system DNS normally uses UDP port 53.",
            listen_port,
        )

        while not _stop_requested(stop_event):
            try:
                packet, client_addr = dns_socket.recvfrom(4096)
            except socket.timeout:
                continue

            handle_dns_query(
                packet,
                client_addr,
                dns_socket,
                upstream_dns=upstream_dns,
                upstream_port=upstream_port,
                threshold=threshold,
                threshold_config=threshold_config,
            )
