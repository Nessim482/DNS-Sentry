from dns_sentry import config


def clear_config_env(monkeypatch) -> None:
    for name in (
        "DISCORD_WEBHOOK_URL",
        "DNS_ENTROPY_THRESHOLD",
        "DNS_INTERFACE",
        "DNS_DEBUG",
    ):
        monkeypatch.delenv(name, raising=False)


def test_config_defaults_when_values_are_absent(monkeypatch, tmp_path) -> None:
    clear_config_env(monkeypatch)
    monkeypatch.chdir(tmp_path)

    assert config.load_discord_webhook_url() is None
    assert config.load_dns_entropy_threshold() == 3.5
    assert config.load_dns_interface() is None
    assert config.load_dns_debug() is False


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
            ]
        ),
        encoding="utf-8",
    )

    assert config.load_discord_webhook_url() == "https://example.test/webhook"
    assert config.load_dns_entropy_threshold() == 4.25
    assert config.load_dns_interface() == "Ethernet"
    assert config.load_dns_debug() is True


def test_environment_variables_override_env_file(monkeypatch, tmp_path) -> None:
    clear_config_env(monkeypatch)
    monkeypatch.chdir(tmp_path)
    tmp_path.joinpath(".env").write_text(
        "DNS_ENTROPY_THRESHOLD=4.25",
        encoding="utf-8",
    )
    monkeypatch.setenv("DNS_ENTROPY_THRESHOLD", "5.0")

    assert config.load_dns_entropy_threshold() == 5.0


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
