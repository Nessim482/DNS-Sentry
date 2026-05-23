from dns_sentry import alerts
from dns_sentry.logging_config import setup_logging

TEST_WEBHOOK_URL = "https://example.test/webhook"


class FakeResponse:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


def suspicious_result() -> dict[str, str | float | bool]:
    return {
        "domain": "dghpcy1sb29rcy1sawtllwjhc2u2nc1kyxrh.attacker.com",
        "subdomain": "dghpcy1sb29rcy1sawtllwjhc2u2nc1kyxrh",
        "entropy": 4.2,
        "threshold": 3.5,
        "suspicious": True,
    }


def captured_payload(monkeypatch, result: dict[str, str | float | bool]) -> dict:
    alerts._RECENT_ALERTS.clear()
    calls = {}

    def fake_post(url: str, json: dict, timeout: float) -> FakeResponse:
        calls["url"] = url
        calls["json"] = json
        calls["timeout"] = timeout
        return FakeResponse(204)

    monkeypatch.setattr(alerts.requests, "post", fake_post)

    assert alerts.send_discord_alert(result, TEST_WEBHOOK_URL) is True
    assert calls["url"] == TEST_WEBHOOK_URL
    assert calls["timeout"] == 3.0

    return calls["json"]


def field_map(payload: dict) -> dict[str, str]:
    embed = payload["embeds"][0]

    return {field["name"]: field["value"] for field in embed["fields"]}


def test_send_discord_alert_posts_payload(monkeypatch) -> None:
    payload = captured_payload(monkeypatch, suspicious_result())
    embed = payload["embeds"][0]
    fields = field_map(payload)

    assert "content" not in payload
    assert embed["title"] == "DNS-Sentry Alert: Suspicious DNS Query"
    assert embed["description"] == (
        "A DNS query with high-entropy characteristics was detected."
    )
    assert embed["footer"]["text"] == "DNS-Sentry • Defensive DNS Monitoring"
    assert fields["Domain"] == "dghpcy1sb29rcy1sawtllwjhc2u2nc1kyxrh.attacker.com"
    assert fields["Subdomain"] == "dghpcy1sb29rcy1sawtllwjhc2u2nc1kyxrh"
    assert fields["Entropy"] == "4.20"
    assert fields["Threshold"] == "3.50"
    assert fields["Detection"] == "High"
    assert fields["Risk Score"] == "N/A"
    assert fields["Severity"] == "High"
    assert fields["Action"] == "alert"
    assert fields["Quarantine"] == "No"
    assert fields["Containment Required"] == "No"
    assert fields["Top Reasons"] == "N/A"
    assert fields["Timestamp UTC"].endswith("Z")
    assert TEST_WEBHOOK_URL not in str(payload)


def test_discord_payload_includes_scoring_fields(monkeypatch) -> None:
    result = suspicious_result()
    result.update(
        {
            "risk_score": 55,
            "severity": "Suspicious",
            "action": "alert",
            "quarantined": True,
            "containment_required": False,
            "reasons": [
                "Blacklist match adds 30 reputation points.",
                "Repeated queries add 10 behavior points.",
                f"webhook={TEST_WEBHOOK_URL}",
                "extra reason should not be included",
            ],
        }
    )

    payload = captured_payload(monkeypatch, result)
    fields = field_map(payload)

    assert fields["Risk Score"] == "55"
    assert fields["Severity"] == "Suspicious"
    assert fields["Action"] == "alert"
    assert fields["Quarantine"] == "Yes"
    assert fields["Containment Required"] == "No"
    assert "Blacklist match adds 30 reputation points." in fields["Top Reasons"]
    assert "Repeated queries add 10 behavior points." in fields["Top Reasons"]
    assert "webhook=[redacted]" in fields["Top Reasons"]
    assert "extra reason should not be included" not in fields["Top Reasons"]
    assert TEST_WEBHOOK_URL not in str(payload)


def test_discord_payload_includes_containment_required(monkeypatch) -> None:
    result = suspicious_result()
    result.update(
        {
            "risk_score": 95,
            "severity": "Critical",
            "action": "quarantine_and_containment",
            "quarantined": True,
            "containment_required": True,
            "reasons": ["Critical score requires containment."],
        }
    )

    payload = captured_payload(monkeypatch, result)
    fields = field_map(payload)

    assert fields["Action"] == "quarantine_and_containment"
    assert fields["Quarantine"] == "Yes"
    assert fields["Containment Required"] == "Yes"


def test_should_send_discord_alert_uses_scored_actions() -> None:
    assert alerts.should_send_discord_alert("allow") is False
    assert alerts.should_send_discord_alert("log") is False
    assert alerts.should_send_discord_alert("alert") is True
    assert alerts.should_send_discord_alert("strong_alert") is True
    assert alerts.should_send_discord_alert("quarantine") is True
    assert alerts.should_send_discord_alert("quarantine_and_containment") is True


def test_send_discord_alert_skips_allow_and_log_actions(monkeypatch) -> None:
    def fake_post(*args: object, **kwargs: object) -> FakeResponse:
        raise AssertionError("HTTP must not be called for allow/log actions")

    monkeypatch.setattr(alerts.requests, "post", fake_post)

    allow_result = suspicious_result()
    allow_result["action"] = "allow"
    log_result = suspicious_result()
    log_result["action"] = "log"

    assert alerts.send_discord_alert(allow_result, TEST_WEBHOOK_URL) is False
    assert alerts.send_discord_alert(log_result, TEST_WEBHOOK_URL) is False


def test_send_discord_alert_uses_medium_severity(monkeypatch) -> None:
    result = suspicious_result()
    result["entropy"] = 3.5
    payload = captured_payload(monkeypatch, result)

    assert field_map(payload)["Detection"] == "Medium"
    assert payload["embeds"][0]["color"] == 0xE67E22


def test_send_discord_alert_uses_high_severity(monkeypatch) -> None:
    result = suspicious_result()
    result["entropy"] = 4.2
    payload = captured_payload(monkeypatch, result)

    assert field_map(payload)["Detection"] == "High"
    assert payload["embeds"][0]["color"] == 0xE74C3C


def test_send_discord_alert_uses_critical_severity(monkeypatch) -> None:
    result = suspicious_result()
    result["entropy"] = 4.7
    payload = captured_payload(monkeypatch, result)

    assert field_map(payload)["Detection"] == "Critical"
    assert payload["embeds"][0]["color"] == 0xC0392B


def test_send_discord_alert_uses_config_webhook(monkeypatch) -> None:
    alerts._RECENT_ALERTS.clear()
    calls = {}

    def fake_post(url: str, json: dict, timeout: float) -> FakeResponse:
        calls["url"] = url
        calls["json"] = json
        return FakeResponse(204)

    monkeypatch.setattr(alerts, "load_discord_webhook_url", lambda: TEST_WEBHOOK_URL)
    monkeypatch.setattr(alerts.requests, "post", fake_post)

    assert alerts.send_discord_alert(suspicious_result()) is True
    assert calls["url"] == TEST_WEBHOOK_URL
    assert TEST_WEBHOOK_URL not in str(calls["json"])


def test_send_discord_alert_rejects_invalid_webhook(monkeypatch) -> None:
    alerts._RECENT_ALERTS.clear()

    def fake_post(*args: object, **kwargs: object) -> FakeResponse:
        raise AssertionError("HTTP must not be called for invalid webhooks")

    monkeypatch.setattr(alerts.requests, "post", fake_post)

    assert alerts.send_discord_alert(suspicious_result(), "not-a-url") is False


def test_send_discord_alert_handles_timeout(monkeypatch) -> None:
    alerts._RECENT_ALERTS.clear()

    def fake_post(*args: object, **kwargs: object) -> FakeResponse:
        raise alerts.requests.Timeout

    monkeypatch.setattr(alerts.requests, "post", fake_post)

    assert (
        alerts.send_discord_alert(
            suspicious_result(),
            TEST_WEBHOOK_URL,
        )
        is False
    )


def test_send_discord_alert_handles_network_error(monkeypatch) -> None:
    alerts._RECENT_ALERTS.clear()

    def fake_post(*args: object, **kwargs: object) -> FakeResponse:
        raise alerts.requests.RequestException

    monkeypatch.setattr(alerts.requests, "post", fake_post)

    assert (
        alerts.send_discord_alert(
            suspicious_result(),
            TEST_WEBHOOK_URL,
        )
        is False
    )


def test_send_discord_alert_handles_invalid_webhook_response(monkeypatch, capsys) -> None:
    alerts._RECENT_ALERTS.clear()
    setup_logging()

    def fake_post(*args: object, **kwargs: object) -> FakeResponse:
        return FakeResponse(404)

    monkeypatch.setattr(alerts.requests, "post", fake_post)

    assert (
        alerts.send_discord_alert(
            suspicious_result(),
            TEST_WEBHOOK_URL,
        )
        is False
    )
    output = capsys.readouterr().out

    assert "Discord alert failed: webhook returned status=404" in output
    assert TEST_WEBHOOK_URL not in output


def test_send_discord_alert_suppresses_duplicate_alerts(monkeypatch) -> None:
    alerts._RECENT_ALERTS.clear()
    calls = []

    def fake_post(*args: object, **kwargs: object) -> FakeResponse:
        calls.append((args, kwargs))
        return FakeResponse(204)

    monkeypatch.setattr(alerts.requests, "post", fake_post)
    monkeypatch.setattr(alerts, "monotonic", lambda: 100.0)

    assert alerts.send_discord_alert(suspicious_result(), TEST_WEBHOOK_URL) is True
    assert alerts.send_discord_alert(suspicious_result(), TEST_WEBHOOK_URL) is False
    assert len(calls) == 1
