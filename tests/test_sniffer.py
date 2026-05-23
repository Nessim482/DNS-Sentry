import pytest

from dns_sentry import sniffer, telemetry
from dns_sentry.logging_config import setup_logging
from dns_sentry.scoring import ThresholdConfig

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


def make_dns_query_packet(domain: bytes | str, qtype: int | str | None = None) -> FakePacket:
    query_values: dict[str, object] = {"qname": domain}
    if qtype is not None:
        query_values["qtype"] = qtype

    return FakePacket(
        {
            DNS: FakeLayer(qr=0),
            DNSQR: FakeLayer(**query_values),
            UDP: FakeLayer(dport=53),
        }
    )


@pytest.fixture(autouse=True)
def reset_dns_telemetry() -> None:
    telemetry.reset_telemetry()


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
    assert result["risk_score"] == 0
    assert result["severity"] == "Safe"
    assert result["action"] == "allow"
    assert result["applied"] is True
    assert result["quarantined"] is False
    assert result["containment_required"] is False
    assert (
        "[INFO] DNS query observed domain=google.com entropy=0.0 suspicious=False"
        in output
    )
    assert "risk_score=0 severity=Safe action=allow" in output
    assert "quarantined=False containment_required=False" in output


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
    assert "risk_score" in result
    assert "severity" in result
    assert "action" in result
    assert "quarantined" in result
    assert "containment_required" in result
    assert output.startswith(
        "[WARNING] Suspicious DNS query detected "
        "domain=dghpcy1sb29rcy1sawtllwjhc2u2nc1kyxrh.attacker.com"
    )
    assert "risk_score=" in output


def test_handle_dns_packet_passes_telemetry_and_reputation_to_scoring(monkeypatch) -> None:
    captured = {}

    def fake_score_domain(
        domain: str,
        threshold: float,
        telemetry_result: dict,
        reputation_result: dict,
    ) -> dict:
        captured["domain"] = domain
        captured["telemetry_result"] = telemetry_result
        captured["reputation_result"] = reputation_result
        return {
            "domain": domain,
            "risk_score": 45,
            "severity": "Suspicious",
            "action": "alert",
            "reasons": ["forced alert action for test"],
        }

    monkeypatch.setattr(sniffer, "score_domain", fake_score_domain)

    result = sniffer._handle_dns_packet(
        make_dns_query_packet(b"malicious-example.test.", qtype=16),
        DNS,
        DNSQR,
        UDP,
    )

    assert result is not None
    assert captured["domain"] == "malicious-example.test"
    assert captured["telemetry_result"]["record_types"] == {"TXT": 1}
    assert captured["telemetry_result"]["unusual_record_type"] is True
    assert captured["reputation_result"]["blacklisted"] is True
    assert result["risk_score"] == 45
    assert result["severity"] == "Suspicious"
    assert result["action"] == "alert"
    assert result["applied"] is True
    assert result["quarantined"] is False
    assert result["containment_required"] is False


def test_handle_dns_packet_notifies_result_callback(monkeypatch) -> None:
    results = []


    def fake_score_domain(
        domain: str,
        threshold: float,
        telemetry_result: dict,
        reputation_result: dict,
    ) -> dict:
        return {
            "domain": domain,
            "risk_score": 75,
            "severity": "Dangerous",
            "action": "quarantine",
            "reasons": ["forced quarantine action for test"],
        }

    monkeypatch.setattr(sniffer, "score_domain", fake_score_domain)

    result = sniffer._handle_dns_packet(
        make_dns_query_packet(b"quarantine.example.com."),
        DNS,
        DNSQR,
        UDP,
        result_callback=results.append,
    )

    assert result is not None
    assert result["quarantined"] is True
    assert result["containment_required"] is False
    assert len(results) == 1
    assert results[0]["domain"] == "quarantine.example.com"
    assert results[0]["quarantined"] is True


def test_handle_dns_packet_calls_apply_action(monkeypatch) -> None:
    captured = {}

    def fake_score_domain(
        domain: str,
        threshold: float,
        telemetry_result: dict,
        reputation_result: dict,
    ) -> dict:
        return {
            "domain": domain,
            "risk_score": 75,
            "severity": "Dangerous",
            "action": "quarantine",
            "reasons": ["forced quarantine action for test"],
        }

    def fake_apply_action(result: dict) -> dict:
        captured["result"] = dict(result)
        return {
            "domain": result["domain"],
            "action": result["action"],
            "applied": True,
            "quarantined": True,
            "containment_required": False,
            "message": "Logical quarantine applied.",
            "reasons": result["reasons"],
        }

    monkeypatch.setattr(sniffer, "score_domain", fake_score_domain)
    monkeypatch.setattr(sniffer, "apply_action", fake_apply_action)

    result = sniffer._handle_dns_packet(
        make_dns_query_packet(b"quarantine.example.com."),
        DNS,
        DNSQR,
        UDP,
    )

    assert result is not None
    assert captured["result"]["action"] == "quarantine"
    assert result["applied"] is True
    assert result["quarantined"] is True
    assert result["containment_required"] is False
    assert result["quarantine_message"] == "Logical quarantine applied."


def test_handle_dns_packet_does_not_send_discord_for_allow_or_log(monkeypatch) -> None:
    sent_alerts = []

    def fake_send_discord_alert(result: dict, webhook_url: str) -> bool:
        sent_alerts.append((result, webhook_url))
        return True

    def fake_score_domain(
        domain: str,
        threshold: float,
        telemetry_result: dict,
        reputation_result: dict,
    ) -> dict:
        action = "allow" if domain == "google.com" else "log"
        return {
            "domain": domain,
            "risk_score": 0 if action == "allow" else 25,
            "severity": "Safe" if action == "allow" else "Low Suspicious",
            "action": action,
            "reasons": [f"forced {action} action for test"],
        }

    monkeypatch.setattr(sniffer, "send_discord_alert", fake_send_discord_alert)
    monkeypatch.setattr(sniffer, "score_domain", fake_score_domain)

    sniffer._handle_dns_packet(
        make_dns_query_packet(b"google.com."),
        DNS,
        DNSQR,
        UDP,
        webhook_url=TEST_WEBHOOK_URL,
    )
    sniffer._handle_dns_packet(
        make_dns_query_packet("log-only.example.com."),
        DNS,
        DNSQR,
        UDP,
        webhook_url=TEST_WEBHOOK_URL,
    )

    assert sent_alerts == []


@pytest.mark.parametrize(
    "action",
    ["alert", "strong_alert", "quarantine", "quarantine_and_containment"],
)
def test_handle_dns_packet_sends_discord_for_alert_actions(monkeypatch, action) -> None:
    sent_alerts = []

    def fake_send_discord_alert(result: dict, webhook_url: str) -> bool:
        sent_alerts.append((result, webhook_url))
        return True

    def fake_score_domain(
        domain: str,
        threshold: float,
        telemetry_result: dict,
        reputation_result: dict,
        threshold_config: ThresholdConfig | None = None,
    ) -> dict:
        return {
            "domain": domain,
            "risk_score": 45,
            "severity": "Suspicious",
            "action": action,
            "reasons": [f"forced {action} action for test"],
        }

    monkeypatch.setattr(sniffer, "send_discord_alert", fake_send_discord_alert)
    monkeypatch.setattr(sniffer, "score_domain", fake_score_domain)

    result = sniffer._handle_dns_packet(
        make_dns_query_packet(b"alert.example.com."),
        DNS,
        DNSQR,
        UDP,
        webhook_url=TEST_WEBHOOK_URL,
    )

    assert result is not None
    assert result["action"] == action
    assert len(sent_alerts) == 1
    assert sent_alerts[0][0]["action"] == action
    assert sent_alerts[0][0]["applied"] is True
    assert sent_alerts[0][1] == TEST_WEBHOOK_URL

    if action == "quarantine":
        assert result["quarantined"] is True
        assert result["containment_required"] is False
    elif action == "quarantine_and_containment":
        assert result["quarantined"] is True
        assert result["containment_required"] is True
    else:
        assert result["quarantined"] is False
        assert result["containment_required"] is False


def test_start_dns_sniffer_uses_config_defaults(monkeypatch) -> None:
    calls = {}
    sent_alerts = []
    callback_results = []

    def fake_sniff(**kwargs: object) -> None:
        calls.update(kwargs)

    def fake_send_discord_alert(result: dict, webhook_url: str) -> bool:
        sent_alerts.append((result, webhook_url))
        return True

    def fake_score_domain(
        domain: str,
        threshold: float,
        telemetry_result: dict,
        reputation_result: dict,
        threshold_config: ThresholdConfig,
    ) -> dict:
        calls["threshold_config"] = threshold_config
        return {
            "domain": domain,
            "risk_score": 45,
            "severity": "Suspicious",
            "action": "alert",
            "reasons": ["forced alert action for test"],
        }

    monkeypatch.setattr(sniffer, "_load_scapy", lambda: (DNS, DNSQR, UDP, fake_sniff))
    monkeypatch.setattr(sniffer, "load_dns_interface", lambda: "Ethernet")
    monkeypatch.setattr(sniffer, "load_discord_webhook_url", lambda: TEST_WEBHOOK_URL)
    monkeypatch.setattr(sniffer, "load_dns_entropy_threshold", lambda: 4.0)
    monkeypatch.setattr(
        sniffer,
        "load_dns_risk_thresholds",
        lambda: ThresholdConfig(quarantine_threshold=80),
    )
    monkeypatch.setattr(sniffer, "load_dns_debug", lambda: False)
    monkeypatch.setattr(sniffer, "send_discord_alert", fake_send_discord_alert)
    monkeypatch.setattr(sniffer, "score_domain", fake_score_domain)

    sniffer.start_dns_sniffer()
    calls["prn"](
        make_dns_query_packet("dGhpcy1sb29rcy1saWtlLWJhc2U2NC1kYXRh.attacker.com.")
    )

    assert calls["iface"] == "Ethernet"
    assert calls["threshold_config"] == ThresholdConfig(quarantine_threshold=80)
    assert sent_alerts[0][0]["threshold"] == 4.0
    assert sent_alerts[0][1] == TEST_WEBHOOK_URL

    sniffer.start_dns_sniffer(result_callback=callback_results.append)
    calls["prn"](make_dns_query_packet("callback.example.com."))

    assert callback_results[0]["domain"] == "callback.example.com"


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
