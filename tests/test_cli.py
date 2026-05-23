from dns_sentry import cli
from dns_sentry.scoring import ThresholdConfig

TEST_WEBHOOK_URL = "https://example.test/webhook"


def clear_config_env(monkeypatch) -> None:
    for name in (
        "DISCORD_WEBHOOK_URL",
        "DNS_ENTROPY_THRESHOLD",
        "DNS_INTERFACE",
        "DNS_DEBUG",
        "DNS_LOW_SUSPICIOUS_THRESHOLD",
        "DNS_ALERT_THRESHOLD",
        "DNS_STRONG_ALERT_THRESHOLD",
        "DNS_QUARANTINE_THRESHOLD",
        "DNS_CONTAINMENT_THRESHOLD",
    ):
        monkeypatch.delenv(name, raising=False)


def test_main_starts_sniffer_with_cli_arguments(monkeypatch, tmp_path, capsys) -> None:
    clear_config_env(monkeypatch)
    monkeypatch.chdir(tmp_path)
    calls = {}

    def fake_start_dns_sniffer(**kwargs: object) -> None:
        calls.update(kwargs)

    monkeypatch.setattr(cli, "start_dns_sniffer", fake_start_dns_sniffer)

    exit_code = cli.main(
        [
            "--interface",
            "Ethernet",
            "--threshold",
            "4.2",
            "--debug",
            "--webhook",
            TEST_WEBHOOK_URL,
            "--low-suspicious-threshold",
            "20",
            "--alert-threshold",
            "40",
            "--strong-alert-threshold",
            "60",
            "--quarantine-threshold",
            "80",
            "--containment-threshold",
            "95",
        ]
    )
    output = capsys.readouterr().out

    assert exit_code == 0
    assert calls == {
        "interface": "Ethernet",
        "webhook_url": TEST_WEBHOOK_URL,
        "threshold": 4.2,
        "threshold_config": ThresholdConfig(
            low_suspicious_threshold=20,
            alert_threshold=40,
            strong_alert_threshold=60,
            quarantine_threshold=80,
            containment_threshold=95,
        ),
        "debug": True,
    }
    assert "DNS-Sentry" in output
    assert "interface=Ethernet" in output
    assert "threshold=4.2" in output
    assert "demo=False" in output
    assert "discord_webhook_configured=True" in output
    assert TEST_WEBHOOK_URL not in output


def test_main_loads_configuration_from_env_file(monkeypatch, tmp_path) -> None:
    clear_config_env(monkeypatch)
    monkeypatch.chdir(tmp_path)
    tmp_path.joinpath(".env").write_text(
        "\n".join(
            [
                f"DISCORD_WEBHOOK_URL={TEST_WEBHOOK_URL}",
                "DNS_ENTROPY_THRESHOLD=4.0",
                "DNS_INTERFACE=Wi-Fi",
                "DNS_DEBUG=true",
                "DNS_LOW_SUSPICIOUS_THRESHOLD=20",
                "DNS_ALERT_THRESHOLD=40",
                "DNS_STRONG_ALERT_THRESHOLD=60",
                "DNS_QUARANTINE_THRESHOLD=80",
                "DNS_CONTAINMENT_THRESHOLD=95",
            ]
        ),
        encoding="utf-8",
    )
    calls = {}

    def fake_start_dns_sniffer(**kwargs: object) -> None:
        calls.update(kwargs)

    monkeypatch.setattr(cli, "start_dns_sniffer", fake_start_dns_sniffer)

    assert cli.main([]) == 0
    assert calls == {
        "interface": "Wi-Fi",
        "webhook_url": TEST_WEBHOOK_URL,
        "threshold": 4.0,
        "threshold_config": ThresholdConfig(
            low_suspicious_threshold=20,
            alert_threshold=40,
            strong_alert_threshold=60,
            quarantine_threshold=80,
            containment_threshold=95,
        ),
        "debug": True,
    }


def test_main_cli_risk_thresholds_override_env_file(monkeypatch, tmp_path) -> None:
    clear_config_env(monkeypatch)
    monkeypatch.chdir(tmp_path)
    tmp_path.joinpath(".env").write_text(
        "DNS_QUARANTINE_THRESHOLD=80",
        encoding="utf-8",
    )
    calls = {}

    def fake_start_dns_sniffer(**kwargs: object) -> None:
        calls.update(kwargs)

    monkeypatch.setattr(cli, "start_dns_sniffer", fake_start_dns_sniffer)

    assert cli.main(["--quarantine-threshold", "85"]) == 0
    assert calls["threshold_config"] == ThresholdConfig(quarantine_threshold=85)


def test_main_handles_keyboard_interrupt(monkeypatch, tmp_path, capsys) -> None:
    clear_config_env(monkeypatch)
    monkeypatch.chdir(tmp_path)

    def fake_start_dns_sniffer(**kwargs: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "start_dns_sniffer", fake_start_dns_sniffer)

    assert cli.main([]) == 130
    assert "[INFO] Stopped by user" in capsys.readouterr().out


def test_main_handles_sniffer_error(monkeypatch, tmp_path, capsys) -> None:
    clear_config_env(monkeypatch)
    monkeypatch.chdir(tmp_path)

    def fake_start_dns_sniffer(**kwargs: object) -> None:
        raise RuntimeError("Scapy is required")

    monkeypatch.setattr(cli, "start_dns_sniffer", fake_start_dns_sniffer)

    assert cli.main([]) == 1
    assert "[ERROR] Scapy is required" in capsys.readouterr().out


def test_main_handles_empty_interface(monkeypatch, tmp_path, capsys) -> None:
    clear_config_env(monkeypatch)
    monkeypatch.chdir(tmp_path)

    assert cli.main(["--interface", ""]) == 1
    assert "[ERROR] interface cannot be empty" in capsys.readouterr().out


def test_main_runs_demo_without_starting_sniffer(monkeypatch, tmp_path) -> None:
    clear_config_env(monkeypatch)
    monkeypatch.chdir(tmp_path)
    calls = {}

    def fake_run_demo(**kwargs: object) -> None:
        calls["demo"] = kwargs

    def fake_start_dns_sniffer(**kwargs: object) -> None:
        calls["sniffer"] = kwargs

    monkeypatch.setattr(cli, "run_demo", fake_run_demo)
    monkeypatch.setattr(cli, "start_dns_sniffer", fake_start_dns_sniffer)

    assert cli.main(["--demo", "--threshold", "4.0", "--webhook", TEST_WEBHOOK_URL]) == 0
    assert calls == {
        "demo": {
            "threshold": 4.0,
            "webhook_url": TEST_WEBHOOK_URL,
            "threshold_config": ThresholdConfig(),
        }
    }


def test_main_runs_gui_without_starting_sniffer(monkeypatch, tmp_path) -> None:
    clear_config_env(monkeypatch)
    monkeypatch.chdir(tmp_path)
    calls = []

    def fake_run_gui(**kwargs: object) -> None:
        calls.append(kwargs)

    def fake_start_dns_sniffer(**kwargs: object) -> None:
        calls.append("sniffer")

    monkeypatch.setattr(cli, "run_gui", fake_run_gui)
    monkeypatch.setattr(cli, "start_dns_sniffer", fake_start_dns_sniffer)

    assert cli.main(["--gui"]) == 0
    assert calls == [{"threshold_config": ThresholdConfig()}]


def test_main_check_env_does_not_start_sniffer(monkeypatch, tmp_path) -> None:
    clear_config_env(monkeypatch)
    monkeypatch.chdir(tmp_path)
    calls = []

    monkeypatch.setattr(cli, "check_environment", lambda: True)
    monkeypatch.setattr(cli, "start_dns_sniffer", lambda **kwargs: calls.append(kwargs))

    assert cli.main(["--check-env"]) == 0
    assert calls == []


def test_check_environment_reports_missing_dependency(monkeypatch, tmp_path) -> None:
    clear_config_env(monkeypatch)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        cli,
        "_is_module_importable",
        lambda module_name: module_name != "scapy",
    )

    assert cli.check_environment() is False


def test_parser_rejects_invalid_threshold() -> None:
    parser = cli.build_parser()

    try:
        parser.parse_args(["--threshold", "not-a-float"])
    except SystemExit as error:
        assert error.code == 2
    else:
        raise AssertionError("invalid threshold should exit")


def test_parser_rejects_invalid_risk_threshold() -> None:
    parser = cli.build_parser()

    try:
        parser.parse_args(["--alert-threshold", "101"])
    except SystemExit as error:
        assert error.code == 2
    else:
        raise AssertionError("invalid risk threshold should exit")
