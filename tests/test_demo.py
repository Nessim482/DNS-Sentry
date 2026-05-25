from dns_sentry import demo
from dns_sentry.logging_config import setup_logging
from dns_sentry.scoring import ThresholdConfig

TEST_WEBHOOK_URL = "https://example.test/webhook"


def test_run_demo_analyzes_simulated_domains(monkeypatch) -> None:
    analyzed_domains = []
    scored_domains = []
    action_domains = []

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

    def fake_apply_action(result: dict) -> dict:
        action_domains.append(result["domain"])
        return {
            "domain": result["domain"],
            "action": result["action"],
            "applied": True,
            "quarantined": False,
            "containment_required": False,
            "message": "Domain allowed by policy.",
            "reasons": result["reasons"],
        }

    monkeypatch.setattr(demo, "analyze_domain", fake_analyze_domain)
    monkeypatch.setattr(demo, "score_domain", fake_score_domain)
    monkeypatch.setattr(demo, "apply_action", fake_apply_action)

    demo.run_demo(threshold=4.0)

    assert len(analyzed_domains) == len(demo._DEMO_DOMAINS)
    assert len(scored_domains) == len(demo._DEMO_DOMAINS)
    assert len(action_domains) == len(demo._DEMO_DOMAINS)
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


def test_run_demo_passes_threshold_config_to_scoring(monkeypatch) -> None:
    captured = {}
    threshold_config = ThresholdConfig(quarantine_threshold=80)

    def fake_analyze_domain(domain: str, threshold: float) -> dict[str, str | float | bool]:
        return {
            "domain": domain,
            "subdomain": domain.split(".")[0],
            "entropy": 1.0,
            "threshold": threshold,
            "suspicious": False,
        }

    def fake_score_domain(
        domain: str,
        threshold: float,
        telemetry_result: dict,
        reputation_result: dict,
        context: dict,
        threshold_config: ThresholdConfig,
    ) -> dict:
        captured["threshold_config"] = threshold_config
        return {
            "domain": domain,
            "risk_score": 0,
            "severity": "Safe",
            "action": "allow",
            "reasons": ["forced allow action for test"],
        }

    monkeypatch.setattr(demo, "_DEMO_DOMAINS", ("normal.example.com",))
    monkeypatch.setattr(demo, "analyze_domain", fake_analyze_domain)
    monkeypatch.setattr(demo, "score_domain", fake_score_domain)

    demo.run_demo(threshold_config=threshold_config)

    assert captured["threshold_config"] == threshold_config


def test_run_demo_does_not_persist_when_disabled(monkeypatch, tmp_path) -> None:
    def fail_persistence(*args, **kwargs) -> None:
        raise AssertionError("persistence should be disabled")

    monkeypatch.setattr(demo, "_DEMO_DOMAINS", ("normal.example.com",))
    monkeypatch.setattr(demo, "save_dns_event", fail_persistence)
    monkeypatch.setattr(demo, "save_quarantine_event", fail_persistence)

    demo.run_demo(enable_persistence=False, database_path=str(tmp_path / "events.db"))

    assert not tmp_path.joinpath("events.db").exists()


def test_run_demo_persists_dns_and_quarantine_events(monkeypatch, tmp_path) -> None:
    saved_dns_events = []
    saved_quarantine_events = []

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

    def fake_save_dns_event(database_path: str, event: dict) -> int:
        saved_dns_events.append((database_path, event))
        return 1

    def fake_save_quarantine_event(database_path: str, result: dict) -> int:
        saved_quarantine_events.append((database_path, result))
        return 1

    database_path = str(tmp_path / "events.db")
    monkeypatch.setattr(demo, "_DEMO_DOMAINS", ("quarantine.example.com",))
    monkeypatch.setattr(demo, "analyze_domain", fake_analyze_domain)
    monkeypatch.setattr(demo, "score_domain", fake_score_domain)
    monkeypatch.setattr(demo, "save_dns_event", fake_save_dns_event)
    monkeypatch.setattr(demo, "save_quarantine_event", fake_save_quarantine_event)

    demo.run_demo(enable_persistence=True, database_path=database_path)

    assert saved_dns_events[0][0] == database_path
    assert saved_dns_events[0][1]["source"] == "demo"
    assert saved_dns_events[0][1]["record_type"] == "SIMULATED"
    assert saved_quarantine_events[0][0] == database_path
    assert saved_quarantine_events[0][1]["domain"] == "quarantine.example.com"


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
