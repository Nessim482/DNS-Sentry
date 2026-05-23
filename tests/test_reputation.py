import socket

from dns_sentry.reputation import check_reputation, load_domain_list


def test_load_domain_list_ignores_comments_and_blank_lines(tmp_path) -> None:
    path = tmp_path / "domains.txt"
    path.write_text(
        "\n".join(
            [
                "# One domain per line",
                "",
                "example.com",
                "  ",
                "# another comment",
                "openai.com",
            ]
        ),
        encoding="utf-8",
    )

    assert load_domain_list(str(path)) == {"example.com", "openai.com"}


def test_load_domain_list_normalizes_lowercase_and_trailing_dot(tmp_path) -> None:
    path = tmp_path / "domains.txt"
    path.write_text("Example.COM.\nSub.Example.TEST.\n", encoding="utf-8")

    assert load_domain_list(str(path)) == {"example.com", "sub.example.test"}


def test_check_reputation_normalizes_domain() -> None:
    result = check_reputation("Example.COM.")

    assert result["domain"] == "example.com"


def test_whitelist_exact_match() -> None:
    result = check_reputation("openai.com", whitelist={"openai.com"})

    assert result["whitelisted"] is True
    assert result["unknown_domain"] is False
    assert "whitelist" in result["reasons"]


def test_whitelist_parent_domain_match() -> None:
    result = check_reputation("api.openai.com", whitelist={"openai.com"})

    assert result["whitelisted"] is True
    assert result["unknown_domain"] is False


def test_blacklist_match() -> None:
    result = check_reputation("login.malicious-example.test", blacklist={"malicious-example.test"})

    assert result["blacklisted"] is True
    assert result["unknown_domain"] is False
    assert "blacklist" in result["reasons"]


def test_ioc_match() -> None:
    result = check_reputation("exfil.exfil-example.test", iocs={"exfil-example.test"})

    assert result["ioc_match"] is True
    assert result["unknown_domain"] is False
    assert "ioc" in result["reasons"]


def test_known_legitimate_match() -> None:
    result = check_reputation(
        "static.microsoft.com",
        known_legitimate={"microsoft.com"},
    )

    assert result["known_legitimate"] is True
    assert result["unknown_domain"] is False
    assert "known_legitimate" in result["reasons"]


def test_suspicious_tld_detected() -> None:
    result = check_reputation("download.example.zip")

    assert result["suspicious_tld"] is True
    assert "suspicious_tld" in result["reasons"]


def test_unknown_domain_detected() -> None:
    result = check_reputation("unseen.example.test")

    assert result["unknown_domain"] is True
    assert "unknown_domain" in result["reasons"]


def test_whitelist_has_priority_over_blacklist_and_ioc() -> None:
    result = check_reputation(
        "api.example.com",
        whitelist={"example.com"},
        blacklist={"api.example.com", "example.com"},
        iocs={"api.example.com", "example.com"},
    )

    assert result["whitelisted"] is True
    assert result["blacklisted"] is False
    assert result["ioc_match"] is False
    assert result["unknown_domain"] is False
    assert result["reasons"] == ["whitelist"]


def test_check_reputation_does_not_use_network(monkeypatch) -> None:
    def fail_network(*args, **kwargs):
        raise AssertionError("network calls are not allowed")

    monkeypatch.setattr(socket, "create_connection", fail_network)
    monkeypatch.setattr(socket, "socket", fail_network)

    result = check_reputation(
        "api.openai.com",
        whitelist={"openai.com"},
        blacklist={"malicious-example.test"},
        iocs={"exfil-example.test"},
    )

    assert result["whitelisted"] is True
