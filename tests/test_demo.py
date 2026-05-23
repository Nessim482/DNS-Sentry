from dns_sentry import demo
from dns_sentry.logging_config import setup_logging

TEST_WEBHOOK_URL = "https://example.test/webhook"


def test_run_demo_analyzes_simulated_domains(monkeypatch) -> None:
    analyzed_domains = []

    def fake_analyze_domain(domain: str, threshold: float) -> dict[str, str | float | bool]:
        analyzed_domains.append((domain, threshold))
        return {
            "domain": domain,
            "subdomain": "",
            "entropy": 0.0,
            "threshold": threshold,
            "suspicious": False,
        }

    monkeypatch.setattr(demo, "analyze_domain", fake_analyze_domain)

    demo.run_demo(threshold=4.0)

    assert len(analyzed_domains) == len(demo._DEMO_DOMAINS)
    assert all(threshold == 4.0 for _, threshold in analyzed_domains)


def test_run_demo_sends_alerts_only_for_suspicious_domains(monkeypatch) -> None:
    sent_alerts = []

    def fake_analyze_domain(domain: str, threshold: float) -> dict[str, str | float | bool]:
        suspicious = domain.startswith("suspicious")
        return {
            "domain": domain,
            "subdomain": domain.split(".")[0],
            "entropy": 4.5 if suspicious else 1.0,
            "threshold": threshold,
            "suspicious": suspicious,
        }

    def fake_send_discord_alert(result: dict, webhook_url: str) -> bool:
        sent_alerts.append((result, webhook_url))
        return True

    monkeypatch.setattr(demo, "_DEMO_DOMAINS", ("normal.example.com", "suspicious.example.com"))
    monkeypatch.setattr(demo, "analyze_domain", fake_analyze_domain)
    monkeypatch.setattr(demo, "send_discord_alert", fake_send_discord_alert)

    demo.run_demo(webhook_url=TEST_WEBHOOK_URL)

    assert len(sent_alerts) == 1
    assert sent_alerts[0][0]["domain"] == "suspicious.example.com"
    assert sent_alerts[0][1] == TEST_WEBHOOK_URL


def test_run_demo_logs_info_and_alert_without_webhook(monkeypatch, capsys) -> None:
    setup_logging()

    def fake_analyze_domain(domain: str, threshold: float) -> dict[str, str | float | bool]:
        suspicious = domain.startswith("suspicious")
        return {
            "domain": domain,
            "subdomain": domain.split(".")[0],
            "entropy": 4.5 if suspicious else 1.0,
            "threshold": threshold,
            "suspicious": suspicious,
        }

    monkeypatch.setattr(demo, "_DEMO_DOMAINS", ("normal.example.com", "suspicious.example.com"))
    monkeypatch.setattr(demo, "analyze_domain", fake_analyze_domain)

    demo.run_demo(webhook_url=TEST_WEBHOOK_URL)
    output = capsys.readouterr().out

    assert "INFO demo DNS query domain=normal.example.com" in output
    assert "ALERT demo DNS query domain=suspicious.example.com" in output
    assert TEST_WEBHOOK_URL not in output
