from dns_sentry import demo
from dns_sentry.logging_config import setup_logging

TEST_WEBHOOK_URL = "https://example.test/webhook"


def test_run_demo_analyzes_simulated_domains(monkeypatch) -> None:
    analyzed_domains = []
    scored_domains = []

    def fake_analyze_domain(domain: str, threshold: float) -> dict[str, str | float | bool]:
        analyzed_domains.append((domain, threshold))
        return {
            "domain": domain,
            "subdomain": "",
            "entropy": 0.0,
            "threshold": threshold,
            "suspicious": False,
        }

    def fake_score_domain(
        domain: str,
        threshold: float,
        telemetry_result: dict,
        reputation_result: dict,
        context: dict,
    ) -> dict:
        scored_domains.append((domain, threshold, telemetry_result, reputation_result))
        return {
            "domain": domain,
            "risk_score": 0,
            "severity": "Safe",
            "action": "allow",
            "reasons": ["forced allow action for test"],
        }

    monkeypatch.setattr(demo, "analyze_domain", fake_analyze_domain)
    monkeypatch.setattr(demo, "score_domain", fake_score_domain)

    demo.run_demo(threshold=4.0)

    assert len(analyzed_domains) == len(demo._DEMO_DOMAINS)
    assert len(scored_domains) == len(demo._DEMO_DOMAINS)
    assert all(threshold == 4.0 for _, threshold in analyzed_domains)
    assert all(threshold == 4.0 for _, threshold, _, _ in scored_domains)


def test_run_demo_sends_alerts_only_for_alert_actions(monkeypatch) -> None:
    sent_alerts = []

    def fake_analyze_domain(domain: str, threshold: float) -> dict[str, str | float | bool]:
        return {
            "domain": domain,
            "subdomain": domain.split(".")[0],
            "entropy": 4.5 if domain.startswith("alert") else 1.0,
            "threshold": threshold,
            "suspicious": domain.startswith("suspicious"),
        }

    def fake_score_domain(
        domain: str,
        threshold: float,
        telemetry_result: dict,
        reputation_result: dict,
        context: dict,
    ) -> dict:
        action = "alert" if domain.startswith("alert") else "log"
        return {
            "domain": domain,
            "risk_score": 45 if action == "alert" else 25,
            "severity": "Suspicious" if action == "alert" else "Low Suspicious",
            "action": action,
            "reasons": [f"forced {action} action for test"],
        }

    def fake_send_discord_alert(result: dict, webhook_url: str) -> bool:
        sent_alerts.append((result, webhook_url))
        return True

    monkeypatch.setattr(
        demo,
        "_DEMO_DOMAINS",
        ("normal.example.com", "suspicious.example.com", "alert.example.com"),
    )
    monkeypatch.setattr(demo, "analyze_domain", fake_analyze_domain)
    monkeypatch.setattr(demo, "score_domain", fake_score_domain)
    monkeypatch.setattr(demo, "send_discord_alert", fake_send_discord_alert)

    demo.run_demo(webhook_url=TEST_WEBHOOK_URL)

    assert len(sent_alerts) == 1
    assert sent_alerts[0][0]["domain"] == "alert.example.com"
    assert sent_alerts[0][0]["action"] == "alert"
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

    def fake_score_domain(
        domain: str,
        threshold: float,
        telemetry_result: dict,
        reputation_result: dict,
        context: dict,
    ) -> dict:
        return {
            "domain": domain,
            "risk_score": 45 if domain.startswith("suspicious") else 0,
            "severity": "Suspicious" if domain.startswith("suspicious") else "Safe",
            "action": "alert" if domain.startswith("suspicious") else "allow",
            "reasons": ["forced scoring result for test"],
        }

    monkeypatch.setattr(demo, "_DEMO_DOMAINS", ("normal.example.com", "suspicious.example.com"))
    monkeypatch.setattr(demo, "analyze_domain", fake_analyze_domain)
    monkeypatch.setattr(demo, "score_domain", fake_score_domain)

    demo.run_demo(webhook_url=TEST_WEBHOOK_URL)
    output = capsys.readouterr().out

    assert "INFO demo DNS query domain=normal.example.com" in output
    assert "ALERT demo DNS query domain=suspicious.example.com" in output
    assert "risk_score=45 severity=Suspicious action=alert" in output
    assert "quarantined=False containment_required=False" in output
    assert TEST_WEBHOOK_URL not in output


def test_run_demo_notifies_result_callback(monkeypatch) -> None:
    callback_results = []

    def fake_analyze_domain(domain: str, threshold: float) -> dict[str, str | float | bool]:
        return {
            "domain": domain,
            "subdomain": domain.split(".")[0],
            "entropy": 4.5,
            "threshold": threshold,
            "suspicious": True,
        }

    def fake_score_domain(
        domain: str,
        threshold: float,
        telemetry_result: dict,
        reputation_result: dict,
        context: dict,
    ) -> dict:
        return {
            "domain": domain,
            "risk_score": 75,
            "severity": "Dangerous",
            "action": "quarantine",
            "reasons": ["forced quarantine action for test"],
        }

    monkeypatch.setattr(demo, "_DEMO_DOMAINS", ("quarantine.example.com",))
    monkeypatch.setattr(demo, "analyze_domain", fake_analyze_domain)
    monkeypatch.setattr(demo, "score_domain", fake_score_domain)

    demo.run_demo(result_callback=callback_results.append)

    assert len(callback_results) == 1
    assert callback_results[0]["domain"] == "quarantine.example.com"
    assert callback_results[0]["quarantined"] is True
    assert callback_results[0]["containment_required"] is False


def test_demo_examples_include_logical_quarantine_actions() -> None:
    quarantine_result = demo._enrich_demo_result(
        demo.analyze_domain("simulated-quarantine.malicious-example.test"),
        threshold=3.5,
    )
    containment_result = demo._enrich_demo_result(
        demo.analyze_domain("abcdefghijklmnopqrstuvwxyz1234.malicious-example.test"),
        threshold=3.5,
    )

    assert quarantine_result["action"] == "quarantine"
    assert quarantine_result["quarantined"] is True
    assert quarantine_result["containment_required"] is False
    assert containment_result["action"] == "quarantine_and_containment"
    assert containment_result["quarantined"] is True
    assert containment_result["containment_required"] is True
