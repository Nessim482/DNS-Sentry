from dns_sentry.analyzer import analyze_domain, extract_subdomain


def test_extract_subdomain_from_domain() -> None:
    assert extract_subdomain("www.example.com") == "www"


def test_normal_domain_is_not_suspicious() -> None:
    result = analyze_domain("www.example.com")

    assert result["domain"] == "www.example.com"
    assert result["subdomain"] == "www"
    assert result["suspicious"] is False


def test_random_subdomain_is_suspicious() -> None:
    subdomain = "dGhpcy1sb29rcy1saWtlLWJhc2U2NC1kYXRh"
    result = analyze_domain(f"{subdomain}.example.com")

    assert result["subdomain"] == subdomain.lower()
    assert result["entropy"] >= result["threshold"]
    assert result["suspicious"] is True
