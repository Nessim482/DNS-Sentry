from dns_sentry import sniffer
from dns_sentry.logging_config import setup_logging

TEST_WEBHOOK_URL = "https://example.test/webhook"


class DNS:
    pass


class DNSQR:
    pass


class UDP:
    pass


class FakeLayer:
    def __init__(self, **values: object) -> None:
        self.__dict__.update(values)


class FakePacket:
    def __init__(self, layers: dict[object, object]) -> None:
        self.layers = layers

    def haslayer(self, layer: object) -> bool:
        return layer in self.layers

    def __getitem__(self, layer: object) -> object:
        return self.layers[layer]


def make_dns_query_packet(domain: bytes | str) -> FakePacket:
    return FakePacket(
        {
            DNS: FakeLayer(qr=0),
            DNSQR: FakeLayer(qname=domain),
            UDP: FakeLayer(dport=53),
        }
    )


def test_extract_query_domain_from_dns_packet() -> None:
    packet = make_dns_query_packet(b"google.com.")

    assert sniffer._extract_query_domain(packet, DNS, DNSQR, UDP) == "google.com"


def test_extract_query_domain_ignores_dns_response() -> None:
    packet = FakePacket(
        {
            DNS: FakeLayer(qr=1),
            DNSQR: FakeLayer(qname=b"google.com."),
            UDP: FakeLayer(dport=53),
        }
    )

    assert sniffer._extract_query_domain(packet, DNS, DNSQR, UDP) is None


def test_handle_dns_packet_prints_info_for_normal_domain(capsys) -> None:
    setup_logging()

    result = sniffer._handle_dns_packet(
        make_dns_query_packet(b"google.com."), DNS, DNSQR, UDP
    )

    output = capsys.readouterr().out

    assert result is not None
    assert result["domain"] == "google.com"
    assert result["suspicious"] is False
    assert (
        "[INFO] DNS query observed domain=google.com entropy=0.0 suspicious=False"
        in output
    )


def test_handle_dns_packet_prints_alert_for_suspicious_domain(capsys) -> None:
    setup_logging()

    result = sniffer._handle_dns_packet(
        make_dns_query_packet("dGhpcy1sb29rcy1saWtlLWJhc2U2NC1kYXRh.attacker.com."),
        DNS,
        DNSQR,
        UDP,
    )

    output = capsys.readouterr().out

    assert result is not None
    assert result["suspicious"] is True
    assert output.startswith(
        "[WARNING] Suspicious DNS query detected "
        "domain=dghpcy1sb29rcy1sawtllwjhc2u2nc1kyxrh.attacker.com"
    )


def test_handle_dns_packet_sends_alert_only_when_suspicious(monkeypatch) -> None:
    sent_alerts = []

    def fake_send_discord_alert(result: dict, webhook_url: str) -> bool:
        sent_alerts.append((result, webhook_url))
        return True

    monkeypatch.setattr(sniffer, "send_discord_alert", fake_send_discord_alert)

    sniffer._handle_dns_packet(
        make_dns_query_packet(b"google.com."),
        DNS,
        DNSQR,
        UDP,
        webhook_url=TEST_WEBHOOK_URL,
    )
    sniffer._handle_dns_packet(
        make_dns_query_packet("dGhpcy1sb29rcy1saWtlLWJhc2U2NC1kYXRh.attacker.com."),
        DNS,
        DNSQR,
        UDP,
        webhook_url=TEST_WEBHOOK_URL,
    )

    assert len(sent_alerts) == 1
    assert sent_alerts[0][0]["suspicious"] is True
    assert sent_alerts[0][1] == TEST_WEBHOOK_URL


def test_start_dns_sniffer_uses_config_defaults(monkeypatch) -> None:
    calls = {}
    sent_alerts = []

    def fake_sniff(**kwargs: object) -> None:
        calls.update(kwargs)

    def fake_send_discord_alert(result: dict, webhook_url: str) -> bool:
        sent_alerts.append((result, webhook_url))
        return True

    monkeypatch.setattr(sniffer, "_load_scapy", lambda: (DNS, DNSQR, UDP, fake_sniff))
    monkeypatch.setattr(sniffer, "load_dns_interface", lambda: "Ethernet")
    monkeypatch.setattr(sniffer, "load_discord_webhook_url", lambda: TEST_WEBHOOK_URL)
    monkeypatch.setattr(sniffer, "load_dns_entropy_threshold", lambda: 4.0)
    monkeypatch.setattr(sniffer, "load_dns_debug", lambda: False)
    monkeypatch.setattr(sniffer, "send_discord_alert", fake_send_discord_alert)

    sniffer.start_dns_sniffer()
    calls["prn"](
        make_dns_query_packet("dGhpcy1sb29rcy1saWtlLWJhc2U2NC1kYXRh.attacker.com.")
    )

    assert calls["iface"] == "Ethernet"
    assert sent_alerts[0][0]["threshold"] == 4.0
    assert sent_alerts[0][1] == TEST_WEBHOOK_URL


def test_start_dns_sniffer_uses_dns_only_filter(monkeypatch) -> None:
    calls = {}

    def fake_sniff(**kwargs: object) -> None:
        calls.update(kwargs)

    monkeypatch.setattr(sniffer, "_load_scapy", lambda: (DNS, DNSQR, UDP, fake_sniff))

    sniffer.start_dns_sniffer(interface="Ethernet")

    assert calls["filter"] == "udp and dst port 53"
    assert calls["iface"] == "Ethernet"
    assert calls["store"] is False
    assert callable(calls["prn"])


def test_start_dns_sniffer_wraps_capture_errors(monkeypatch) -> None:
    def fake_sniff(**kwargs: object) -> None:
        raise OSError("driver missing")

    monkeypatch.setattr(sniffer, "_load_scapy", lambda: (DNS, DNSQR, UDP, fake_sniff))

    try:
        sniffer.start_dns_sniffer(interface="invalid")
    except RuntimeError as error:
        assert "Live DNS sniffing requires Scapy and a packet capture driver" in str(error)
    else:
        raise AssertionError("capture errors should be wrapped")
