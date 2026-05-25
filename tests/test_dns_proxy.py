import socket
import threading

from dns_sentry import dns_proxy, telemetry
from dns_sentry.scoring import ThresholdConfig

CLIENT_ADDR = ("127.0.0.1", 53000)


class FakeClientSocket:
    def __init__(self) -> None:
        self.sent_packets = []

    def sendto(self, packet: bytes, address: tuple) -> None:
        self.sent_packets.append((packet, address))


class FakeUpstreamSocket:
    def __init__(self, response: bytes) -> None:
        self.response = response
        self.timeout = None
        self.sent_packets = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        return None

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def sendto(self, packet: bytes, address: tuple) -> None:
        self.sent_packets.append((packet, address))

    def recvfrom(self, size: int) -> tuple[bytes, tuple]:
        return self.response, ("1.1.1.1", 53)


class FakeUpstreamFactory:
    def __init__(self, response: bytes) -> None:
        self.response = response
        self.sockets = []

    def __call__(self, *args: object, **kwargs: object) -> FakeUpstreamSocket:
        upstream_socket = FakeUpstreamSocket(self.response)
        self.sockets.append(upstream_socket)
        return upstream_socket


class FakeListenSocket:
    def __init__(self, stop_event: threading.Event) -> None:
        self.stop_event = stop_event
        self.bound_address = None
        self.timeout = None
        self.recv_calls = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        return None

    def bind(self, address: tuple[str, int]) -> None:
        self.bound_address = address

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def recvfrom(self, size: int) -> tuple[bytes, tuple]:
        self.recv_calls += 1
        self.stop_event.set()
        raise socket.timeout


def make_dns_query(
    domain: str,
    transaction_id: bytes = b"\x12\x34",
    qtype: int = 1,
) -> bytes:
    labels = [
        bytes([len(label)]) + label.encode("ascii")
        for label in domain.rstrip(".").split(".")
    ]
    qname = b"".join(labels) + b"\x00"
    return b"".join(
        [
            transaction_id,
            b"\x01\x00",
            b"\x00\x01",
            b"\x00\x00",
            b"\x00\x00",
            b"\x00\x00",
            qname,
            qtype.to_bytes(2, byteorder="big"),
            b"\x00\x01",
        ]
    )


def fake_score(action: str):
    def _fake_score_domain(
        domain: str,
        threshold: float,
        telemetry_result: dict,
        reputation_result: dict,
    ) -> dict:
        return {
            "domain": domain,
            "risk_score": 75 if action.startswith("quarantine") else 0,
            "severity": "Dangerous" if action.startswith("quarantine") else "Safe",
            "action": action,
            "reasons": [f"forced {action} action for test"],
        }

    return _fake_score_domain


def response_rcode(response: bytes) -> int:
    return int.from_bytes(response[2:4], byteorder="big") & 0x000F


def test_extract_query_domain_from_dns_query_packet() -> None:
    packet = make_dns_query("example.com")

    assert dns_proxy.extract_query_domain(packet) == "example.com"


def test_safe_query_is_forwarded_to_upstream(monkeypatch) -> None:
    telemetry.reset_telemetry()
    query_packet = make_dns_query("example.com")
    upstream_response = b"\x12\x34upstream-response"
    client_socket = FakeClientSocket()
    upstream_factory = FakeUpstreamFactory(upstream_response)
    monkeypatch.setattr(dns_proxy, "score_domain", fake_score("allow"))

    dns_proxy.handle_dns_query(
        query_packet,
        CLIENT_ADDR,
        client_socket,
        upstream_dns="9.9.9.9",
        upstream_port=53,
        upstream_socket_factory=upstream_factory,
    )

    assert upstream_factory.sockets[0].sent_packets == [
        (query_packet, ("9.9.9.9", 53))
    ]
    assert client_socket.sent_packets == [(upstream_response, CLIENT_ADDR)]


def test_quarantine_query_is_not_forwarded(monkeypatch) -> None:
    telemetry.reset_telemetry()
    query_packet = make_dns_query("blocked.example.com")
    client_socket = FakeClientSocket()
    monkeypatch.setattr(dns_proxy, "score_domain", fake_score("quarantine"))

    def fail_upstream(*args: object, **kwargs: object) -> None:
        raise AssertionError("quarantine action must not reach upstream DNS")

    dns_proxy.handle_dns_query(
        query_packet,
        CLIENT_ADDR,
        client_socket,
        upstream_socket_factory=fail_upstream,
    )

    assert len(client_socket.sent_packets) == 1


def test_quarantine_query_returns_block_response(monkeypatch) -> None:
    telemetry.reset_telemetry()
    query_packet = make_dns_query("blocked.example.com", transaction_id=b"\xab\xcd")
    client_socket = FakeClientSocket()
    monkeypatch.setattr(
        dns_proxy,
        "score_domain",
        fake_score("quarantine_and_containment"),
    )

    dns_proxy.handle_dns_query(query_packet, CLIENT_ADDR, client_socket)

    response, address = client_socket.sent_packets[0]
    assert address == CLIENT_ADDR
    assert response[:2] == b"\xab\xcd"
    assert response_rcode(response) == 3
    assert int.from_bytes(response[2:4], byteorder="big") & 0x8000


def test_block_response_keeps_original_transaction_id() -> None:
    query_packet = make_dns_query("blocked.example.com", transaction_id=b"\xca\xfe")

    response = dns_proxy.build_block_response(query_packet)

    assert response[:2] == b"\xca\xfe"
    assert response_rcode(response) == 3


def test_start_dns_proxy_stops_cleanly_with_stop_event(monkeypatch) -> None:
    stop_event = threading.Event()
    fake_socket = FakeListenSocket(stop_event)

    monkeypatch.setattr(dns_proxy, "load_dns_risk_thresholds", lambda: ThresholdConfig())
    monkeypatch.setattr(dns_proxy.socket, "socket", lambda *args, **kwargs: fake_socket)

    dns_proxy.start_dns_proxy(
        listen_host="127.0.0.1",
        listen_port=5353,
        stop_event=stop_event,
    )

    assert fake_socket.bound_address == ("127.0.0.1", 5353)
    assert fake_socket.timeout == 1.0
    assert fake_socket.recv_calls == 1
