from dns_sentry import alerts

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


def test_send_discord_alert_posts_payload(monkeypatch) -> None:
    alerts._RECENT_ALERTS.clear()
    calls = {}

    def fake_post(url: str, json: dict[str, str], timeout: float) -> FakeResponse:
        calls["url"] = url
        calls["json"] = json
        calls["timeout"] = timeout
        return FakeResponse(204)

    monkeypatch.setattr(alerts.requests, "post", fake_post)

    success = alerts.send_discord_alert(
        suspicious_result(),
        TEST_WEBHOOK_URL,
    )

    content = calls["json"]["content"]

    assert success is True
    assert calls["url"] == TEST_WEBHOOK_URL
    assert calls["timeout"] == 3.0
    assert "domain: dghpcy1sb29rcy1sawtllwjhc2u2nc1kyxrh.attacker.com" in content
    assert "entropy: 4.20" in content
    assert "threshold: 3.50" in content
    assert "suspicious: True" in content
    assert "timestamp:" in content


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


def test_send_discord_alert_handles_invalid_webhook_response(monkeypatch) -> None:
    alerts._RECENT_ALERTS.clear()

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
