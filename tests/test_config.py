import pytest

from dns_sentry import config
from dns_sentry.scoring import ThresholdConfig


def clear_config_env(monkeypatch) -> None:
    for name in (
        "DISCORD_WEBHOOK_URL",
        "DNS_ENTROPY_THRESHOLD",
        "DNS_INTERFACE",
        "DNS_DEBUG",
        "DATABASE_PATH",
        "RISK_PROFILE",
        "DNS_LOW_SUSPICIOUS_THRESHOLD",
        "DNS_ALERT_THRESHOLD",
        "DNS_STRONG_ALERT_THRESHOLD",
        "DNS_QUARANTINE_THRESHOLD",
        "DNS_CONTAINMENT_THRESHOLD",
    ):
        monkeypatch.delenv(name, raising=False)


def test_config_defaults_when_values_are_absent(monkeypatch, tmp_path) -> None:
    clear_config_env(monkeypatch)
    monkeypatch.chdir(tmp_path)

    assert config.load_discord_webhook_url() is None
    assert config.load_dns_entropy_threshold() == 3.5
    assert config.load_dns_interface() is None
    assert config.load_risk_profile() == "balanced"
    assert config.load_dns_risk_thresholds() == ThresholdConfig()
    assert config.load_dns_debug() is False
    assert config.load_database_path() == "./dns_sentry.db"


def test_config_loads_values_from_env_file(monkeypatch, tmp_path) -> None:
    clear_config_env(monkeypatch)
    monkeypatch.chdir(tmp_path)
    tmp_path.joinpath(".env").write_text(
        "\n".join(
            [
                "DISCORD_WEBHOOK_URL=https://example.test/webhook",
                "DNS_ENTROPY_THRESHOLD=4.25",
                "DNS_INTERFACE=Ethernet",
                "DNS_DEBUG=true",
                "DATABASE_PATH=./events.db",
                "RISK_PROFILE=enterprise",
                "DNS_LOW_SUSPICIOUS_THRESHOLD=20",
                "DNS_ALERT_THRESHOLD=40",
                "DNS_STRONG_ALERT_THRESHOLD=60",
                "DNS_QUARANTINE_THRESHOLD=80",
                "DNS_CONTAINMENT_THRESHOLD=95",
            ]
        ),
        encoding="utf-8",
    )

    assert config.load_discord_webhook_url() == "https://example.test/webhook"
    assert config.load_dns_entropy_threshold() == 4.25
    assert config.load_dns_interface() == "Ethernet"
    assert config.load_risk_profile() == "enterprise"
    assert config.load_dns_risk_thresholds() == ThresholdConfig(
        low_suspicious_threshold=20,
        alert_threshold=40,
        strong_alert_threshold=60,
        quarantine_threshold=80,
        containment_threshold=95,
    )
    assert config.load_dns_debug() is True
    assert config.load_database_path() == "./events.db"


def test_environment_variables_override_env_file(monkeypatch, tmp_path) -> None:
    clear_config_env(monkeypatch)
    monkeypatch.chdir(tmp_path)
    tmp_path.joinpath(".env").write_text(
        "DNS_ENTROPY_THRESHOLD=4.25",
        encoding="utf-8",
    )
    monkeypatch.setenv("DNS_ENTROPY_THRESHOLD", "5.0")

    assert config.load_dns_entropy_threshold() == 5.0


def test_environment_variables_override_risk_threshold_env_file(
    monkeypatch,
    tmp_path,
) -> None:
    clear_config_env(monkeypatch)
    monkeypatch.chdir(tmp_path)
    tmp_path.joinpath(".env").write_text(
        "DNS_QUARANTINE_THRESHOLD=80",
        encoding="utf-8",
    )
    monkeypatch.setenv("DNS_QUARANTINE_THRESHOLD", "85")

    assert config.load_dns_risk_thresholds().quarantine_threshold == 85


def test_environment_variables_override_database_path_env_file(
    monkeypatch,
    tmp_path,
) -> None:
    clear_config_env(monkeypatch)
    monkeypatch.chdir(tmp_path)
    tmp_path.joinpath(".env").write_text(
        "DATABASE_PATH=./from-file.db",
        encoding="utf-8",
    )
    monkeypatch.setenv("DATABASE_PATH", "./from-env.db")

    assert config.load_database_path() == "./from-env.db"


def test_risk_profile_env_file_sets_threshold_base(monkeypatch, tmp_path) -> None:
    clear_config_env(monkeypatch)
    monkeypatch.chdir(tmp_path)
    tmp_path.joinpath(".env").write_text(
        "RISK_PROFILE=paranoid",
        encoding="utf-8",
    )

    assert config.load_risk_profile() == "paranoid"
    assert config.load_dns_risk_thresholds() == ThresholdConfig(
        low_suspicious_threshold=15,
        alert_threshold=30,
        strong_alert_threshold=45,
        quarantine_threshold=60,
        containment_threshold=80,
    )


def test_risk_threshold_env_overrides_profile_base(monkeypatch, tmp_path) -> None:
    clear_config_env(monkeypatch)
    monkeypatch.chdir(tmp_path)
    tmp_path.joinpath(".env").write_text(
        "\n".join(
            [
                "RISK_PROFILE=enterprise",
                "DNS_QUARANTINE_THRESHOLD=88",
            ]
        ),
        encoding="utf-8",
    )

    assert config.load_dns_risk_thresholds() == ThresholdConfig(
        low_suspicious_threshold=30,
        alert_threshold=50,
        strong_alert_threshold=70,
        quarantine_threshold=88,
        containment_threshold=95,
    )


def test_unknown_risk_profile_env_raises_value_error(monkeypatch, tmp_path) -> None:
    clear_config_env(monkeypatch)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("RISK_PROFILE", "unknown")

    with pytest.raises(ValueError, match="unknown risk profile"):
        config.load_risk_profile()


def test_invalid_risk_threshold_env_raises_value_error(monkeypatch, tmp_path) -> None:
    clear_config_env(monkeypatch)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DNS_ALERT_THRESHOLD", "not-an-int")

    with pytest.raises(ValueError, match="DNS_ALERT_THRESHOLD must be an integer"):
        config.load_dns_risk_thresholds()


def test_invalid_risk_threshold_order_raises_value_error(
    monkeypatch,
    tmp_path,
) -> None:
    clear_config_env(monkeypatch)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DNS_QUARANTINE_THRESHOLD", "40")

    with pytest.raises(ValueError, match="invalid threshold order"):
        config.load_dns_risk_thresholds()


def test_invalid_threshold_falls_back_to_default(monkeypatch, tmp_path) -> None:
    clear_config_env(monkeypatch)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DNS_ENTROPY_THRESHOLD", "not-a-float")

    assert config.load_dns_entropy_threshold() == 3.5


def test_negative_threshold_falls_back_to_default(monkeypatch, tmp_path) -> None:
    clear_config_env(monkeypatch)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DNS_ENTROPY_THRESHOLD", "-1")

    assert config.load_dns_entropy_threshold() == 3.5


def test_boolean_values_are_parsed(monkeypatch, tmp_path) -> None:
    clear_config_env(monkeypatch)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DNS_DEBUG", "yes")

    assert config.load_dns_debug() is True

    monkeypatch.setenv("DNS_DEBUG", "off")

    assert config.load_dns_debug() is False


def test_invalid_boolean_falls_back_to_default(monkeypatch, tmp_path) -> None:
    clear_config_env(monkeypatch)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DNS_DEBUG", "maybe")

    assert config.load_dns_debug(default=True) is True


def test_invalid_env_file_lines_are_ignored(monkeypatch, tmp_path) -> None:
    clear_config_env(monkeypatch)
    monkeypatch.chdir(tmp_path)
    tmp_path.joinpath(".env").write_text(
        "\n".join(
            [
                "INVALID_LINE",
                "# comment",
                "DNS_INTERFACE='Wi-Fi'",
            ]
        ),
        encoding="utf-8",
    )

    assert config.load_dns_interface() == "Wi-Fi"
