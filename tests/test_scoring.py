import socket

import pytest

from dns_sentry.scoring import score_domain


def test_normal_domain_gets_low_score() -> None:
    result = score_domain("www.example.com", telemetry_result={})

    assert result["risk_score"] == 0
    assert result["severity"] == "Safe"
    assert result["action"] == "allow"


def test_high_entropy_domain_adds_10_points() -> None:
    result = score_domain("abcdefghijklmnopqrstuvwxyz.example.com", telemetry_result={})

    assert result["risk_score"] == 10
    assert "High Shannon entropy adds 10 structure points." in result["reasons"]


def test_long_domain_adds_5_points() -> None:
    result = score_domain(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaag.example.com",
        telemetry_result={},
    )

    assert result["risk_score"] == 5
    assert "Long domain or subdomain adds 5 structure points." in result["reasons"]


def test_high_digit_symbol_ratio_adds_4_points() -> None:
    result = score_domain("1-2-3-4.example.com", telemetry_result={})

    assert result["risk_score"] == 4
    assert "High digit/symbol ratio adds 4 structure points." in result["reasons"]


def test_low_vowel_readability_adds_3_points() -> None:
    result = score_domain("bcdfghjkl.example.com", telemetry_result={})

    assert result["risk_score"] == 3
    assert "Low vowel/readability ratio adds 3 structure points." in result["reasons"]


def test_base64_base32_hex_like_pattern_adds_3_points() -> None:
    result = score_domain("deadbeefdeadbeef.example.com", telemetry_result={})

    assert result["risk_score"] == 3
    assert (
        "Possible base64/base32/hex pattern adds 3 structure points."
        in result["reasons"]
    )


def test_blacklist_adds_30_points() -> None:
    result = score_domain(
        "malicious-example.test",
        telemetry_result={},
        reputation_result={"blacklisted": True},
    )

    assert result["risk_score"] == 30
    assert "Blacklist match adds 30 reputation points." in result["reasons"]


def test_ioc_adds_25_points() -> None:
    result = score_domain(
        "exfil-example.test",
        telemetry_result={},
        reputation_result={"ioc_match": True},
    )

    assert result["risk_score"] == 25
    assert "Imported IOC match adds 25 reputation points." in result["reasons"]


def test_suspicious_tld_adds_5_points() -> None:
    result = score_domain(
        "download.example.zip",
        telemetry_result={},
        reputation_result={"suspicious_tld": True},
    )

    assert result["risk_score"] == 5
    assert "Suspicious TLD adds 5 reputation points." in result["reasons"]


def test_unknown_domain_adds_5_points() -> None:
    result = score_domain(
        "unknown.example.test",
        telemetry_result={},
        reputation_result={"unknown_domain": True},
    )

    assert result["risk_score"] == 5
    assert "Unknown domain adds 5 reputation points." in result["reasons"]


def test_known_legitimate_reduces_20_points() -> None:
    result = score_domain(
        "known.example.com",
        telemetry_result={},
        reputation_result={"blacklisted": True, "known_legitimate": True},
    )

    assert result["risk_score"] == 10
    assert "Known legitimate domain subtracts 20 reputation points." in result["reasons"]


def test_previously_quarantined_adds_20_points_from_context() -> None:
    result = score_domain(
        "previous.example.com",
        telemetry_result={},
        context={"previously_quarantined": True},
    )

    assert result["risk_score"] == 20
    assert "Previously quarantined domain adds 20 reputation points." in result["reasons"]


def test_whitelist_forces_score_zero() -> None:
    result = score_domain(
        "trusted.example.com",
        telemetry_result={"repeated_queries": True},
        reputation_result={
            "whitelisted": True,
            "blacklisted": True,
            "ioc_match": True,
            "suspicious_tld": True,
        },
        context={"previously_quarantined": True, "sensitive_host": True},
    )

    assert result == {
        "domain": "trusted.example.com",
        "risk_score": 0,
        "severity": "Safe",
        "action": "allow",
        "reasons": ["Whitelist match forces risk score to 0 and action allow."],
    }


def test_repeated_queries_adds_10_points() -> None:
    result = score_domain(
        "api.example.com",
        telemetry_result={"repeated_queries": True},
    )

    assert result["risk_score"] == 10
    assert "Repeated queries add 10 behavior points." in result["reasons"]


def test_many_unique_subdomains_adds_8_points() -> None:
    result = score_domain(
        "api.example.com",
        telemetry_result={"many_unique_subdomains": True},
    )

    assert result["risk_score"] == 8
    assert "Many unique subdomains add 8 behavior points." in result["reasons"]


def test_high_nxdomain_ratio_adds_7_points() -> None:
    result = score_domain(
        "api.example.com",
        telemetry_result={"high_nxdomain_ratio": True},
    )

    assert result["risk_score"] == 7
    assert "High NXDOMAIN ratio adds 7 behavior points." in result["reasons"]


def test_possible_beaconing_adds_5_points() -> None:
    result = score_domain(
        "api.example.com",
        telemetry_result={"possible_beaconing": True},
    )

    assert result["risk_score"] == 5
    assert "Possible beaconing adds 5 behavior points." in result["reasons"]


def test_unusual_record_type_adds_5_points() -> None:
    result = score_domain(
        "api.example.com",
        telemetry_result={"record_types": {"TXT": 1}},
    )

    assert result["risk_score"] == 5
    assert "Unusual DNS record type adds 5 behavior points." in result["reasons"]


def test_sensitive_host_adds_5_points() -> None:
    result = score_domain(
        "api.example.com",
        telemetry_result={},
        context={"sensitive_host": True},
    )

    assert result["risk_score"] == 5
    assert "Sensitive host adds 5 context points." in result["reasons"]


def test_unusual_activity_time_adds_5_points() -> None:
    result = score_domain(
        "api.example.com",
        telemetry_result={},
        context={"unusual_activity_time": True},
    )

    assert result["risk_score"] == 5
    assert "Unusual activity time adds 5 context points." in result["reasons"]


def test_frequently_seen_benign_removes_10_points() -> None:
    result = score_domain(
        "api.example.com",
        telemetry_result={},
        reputation_result={"blacklisted": True},
        context={"frequently_seen_benign": True},
    )

    assert result["risk_score"] == 20
    assert (
        "Frequently seen benign domain subtracts 10 context points."
        in result["reasons"]
    )


def test_score_is_clamped_between_0_and_100() -> None:
    low_result = score_domain(
        "known.example.com",
        telemetry_result={},
        reputation_result={"known_legitimate": True},
        context={"frequently_seen_benign": True},
    )
    high_result = score_domain(
        "bcdfghjklmnpqrstvwxyz1234567890.example.com",
        telemetry_result={
            "repeated_queries": True,
            "many_unique_subdomains": True,
            "high_nxdomain_ratio": True,
            "possible_beaconing": True,
            "unusual_record_type": True,
        },
        reputation_result={
            "blacklisted": True,
            "ioc_match": True,
            "suspicious_tld": True,
            "unknown_domain": True,
        },
        context={
            "previously_quarantined": True,
            "sensitive_host": True,
            "unusual_activity_time": True,
        },
    )

    assert low_result["risk_score"] == 0
    assert high_result["risk_score"] == 100


@pytest.mark.parametrize(
    ("expected_score", "expected_severity", "expected_action", "kwargs"),
    [
        (0, "Safe", "allow", {"telemetry_result": {}}),
        (25, "Low Suspicious", "log", {"telemetry_result": {}, "reputation_result": {"ioc_match": True}}),
        (
            45,
            "Suspicious",
            "alert",
            {
                "telemetry_result": {"repeated_queries": True},
                "reputation_result": {"blacklisted": True},
                "context": {"sensitive_host": True},
            },
        ),
        (
            65,
            "High Risk",
            "strong_alert",
            {
                "telemetry_result": {
                    "repeated_queries": True,
                    "many_unique_subdomains": True,
                    "high_nxdomain_ratio": True,
                    "possible_beaconing": True,
                    "unusual_record_type": True,
                },
                "reputation_result": {"blacklisted": True},
            },
        ),
        (
            75,
            "Dangerous",
            "quarantine",
            {
                "telemetry_result": {
                    "repeated_queries": True,
                    "many_unique_subdomains": True,
                    "high_nxdomain_ratio": True,
                    "possible_beaconing": True,
                    "unusual_record_type": True,
                },
                "reputation_result": {"blacklisted": True},
                "context": {"sensitive_host": True, "unusual_activity_time": True},
            },
        ),
        (
            90,
            "Critical",
            "quarantine_and_containment",
            {
                "domain": "bcdfghjklmnpqrstvwxyz1234567890.example.com",
                "telemetry_result": {
                    "repeated_queries": True,
                    "many_unique_subdomains": True,
                    "high_nxdomain_ratio": True,
                    "possible_beaconing": True,
                    "unusual_record_type": True,
                },
                "reputation_result": {"blacklisted": True},
            },
        ),
    ],
)
def test_severity_and_action_for_each_range(
    expected_score,
    expected_severity,
    expected_action,
    kwargs,
) -> None:
    domain = kwargs.pop("domain", "api.example.com")
    result = score_domain(domain, **kwargs)

    assert result["risk_score"] == expected_score
    assert result["severity"] == expected_severity
    assert result["action"] == expected_action


def test_reasons_explain_applied_rules() -> None:
    result = score_domain(
        "abcdefghijklmnopqrstuvwxyz.example.com",
        telemetry_result={"repeated_queries": True},
        reputation_result={"blacklisted": True},
        context={"sensitive_host": True},
    )

    assert "Blacklist match adds 30 reputation points." in result["reasons"]
    assert "High Shannon entropy adds 10 structure points." in result["reasons"]
    assert "Repeated queries add 10 behavior points." in result["reasons"]
    assert "Sensitive host adds 5 context points." in result["reasons"]


def test_missing_behavior_context_adds_informative_reason() -> None:
    result = score_domain("api.example.com")

    assert (
        "DNS behavior context was not provided; no behavior points applied."
        in result["reasons"]
    )


def test_score_domain_does_not_use_network(monkeypatch) -> None:
    def fail_network(*args, **kwargs):
        raise AssertionError("network calls are not allowed")

    monkeypatch.setattr(socket, "create_connection", fail_network)
    monkeypatch.setattr(socket, "socket", fail_network)

    result = score_domain(
        "api.example.com",
        telemetry_result={"repeated_queries": True},
        reputation_result={"unknown_domain": True},
    )

    assert result["risk_score"] == 15
