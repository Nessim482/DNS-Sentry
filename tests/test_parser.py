from dns_sentry.parser import analyze_log_line, parse_dns_query


def test_parse_dns_query_extracts_supported_formats() -> None:
    assert parse_dns_query("2026-05-23 QUERY google.com") == "google.com"
    assert (
        parse_dns_query("CLIENT 192.168.1.10 requested api.github.com")
        == "api.github.com"
    )
    assert (
        parse_dns_query("DNS_REQ suspicious.xxxxx.attacker.com")
        == "suspicious.xxxxx.attacker.com"
    )


def test_parse_dns_query_returns_none_for_invalid_line() -> None:
    assert parse_dns_query("no dns domain here") is None


def test_analyze_log_line_normal_domain_is_not_suspicious() -> None:
    result = analyze_log_line("2026-05-23 QUERY google.com")

    assert result is not None
    assert result["domain"] == "google.com"
    assert result["suspicious"] is False


def test_analyze_log_line_random_subdomain_is_suspicious() -> None:
    result = analyze_log_line(
        "DNS_REQ dGhpcy1sb29rcy1saWtlLWJhc2U2NC1kYXRh.attacker.com"
    )

    assert result is not None
    assert result["subdomain"] == "dghpcy1sb29rcy1sawtllwjhc2u2nc1kyxrh"
    assert result["suspicious"] is True
