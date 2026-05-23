from dns_sentry import telemetry
from dns_sentry.telemetry import DNSTelemetryState


def test_record_query_records_domain() -> None:
    state = DNSTelemetryState()

    state.record_query("Api.Example.com.", timestamp=100.0)

    stats = state.get_domain_stats("api.example.com")
    assert stats["domain"] == "api.example.com"
    assert stats["parent_domain"] == "example.com"
    assert stats["total_queries"] == 1
    assert stats["timestamps"] == [100.0]
    assert stats["record_types"] == {"A": 1}


def test_domain_stats_include_counts_timestamps_and_record_types() -> None:
    state = DNSTelemetryState()

    state.record_query("api.example.com", record_type="AAAA", timestamp=10.0)
    state.record_query("api.example.com", record_type="a", timestamp=12.5)

    stats = state.get_domain_stats("api.example.com")
    assert stats["total_queries"] == 2
    assert stats["timestamps"] == [10.0, 12.5]
    assert stats["record_types"] == {"AAAA": 1, "A": 1}


def test_parent_domain_stats_include_parent_counts_and_unique_subdomains() -> None:
    state = DNSTelemetryState()

    state.record_query("api.example.com", record_type="A", timestamp=1.0)
    state.record_query("cdn.example.com", record_type="TXT", timestamp=2.0)
    state.record_query("example.com", record_type="MX", timestamp=3.0)

    stats = state.get_parent_domain_stats("example.com")
    assert stats["parent_domain"] == "example.com"
    assert stats["total_queries"] == 3
    assert stats["unique_subdomains"] == ["api", "cdn"]
    assert stats["unique_subdomain_count"] == 2
    assert stats["timestamps"] == [1.0, 2.0, 3.0]
    assert stats["record_types"] == {"A": 1, "TXT": 1, "MX": 1}


def test_repeated_queries_detected_after_multiple_close_queries() -> None:
    state = DNSTelemetryState()

    state.record_query("api.example.com", timestamp=100.0)
    state.record_query("api.example.com", timestamp=104.0)
    state.record_query("api.example.com", timestamp=109.0)

    behavior = state.analyze_behavior("api.example.com")
    assert behavior["repeated_queries"] is True
    assert behavior["many_unique_subdomains"] is False
    assert behavior["possible_beaconing"] is False
    assert behavior["reasons"] == [
        "Repeated queries for the same domain in a short window"
    ]


def test_many_unique_subdomains_detected_for_same_parent_domain() -> None:
    state = DNSTelemetryState()

    for index in range(5):
        state.record_query(f"sub{index}.example.com", timestamp=float(index))

    behavior = state.analyze_behavior("sub0.example.com")
    assert behavior["repeated_queries"] is False
    assert behavior["many_unique_subdomains"] is True
    assert behavior["possible_beaconing"] is False
    assert (
        "Many unique subdomains observed for the parent domain"
        in behavior["reasons"]
    )


def test_possible_beaconing_detected_on_simple_regular_intervals() -> None:
    state = DNSTelemetryState()

    for timestamp in (100.0, 110.0, 120.0, 130.0):
        state.record_query("beacon.example.com", timestamp=timestamp)

    behavior = state.analyze_behavior("beacon.example.com")
    assert behavior["repeated_queries"] is False
    assert behavior["many_unique_subdomains"] is False
    assert behavior["possible_beaconing"] is True
    assert "Regular query intervals suggest possible beaconing" in behavior["reasons"]


def test_default_module_api_records_in_memory() -> None:
    telemetry.reset_telemetry()

    telemetry.record_query("module.example.com", record_type="TXT", timestamp=50.0)

    assert telemetry.get_domain_stats("module.example.com")["total_queries"] == 1
    assert telemetry.get_parent_domain_stats("example.com")["record_types"] == {
        "TXT": 1
    }
    assert telemetry.analyze_behavior("module.example.com") == {
        "repeated_queries": False,
        "many_unique_subdomains": False,
        "possible_beaconing": False,
        "reasons": [],
    }


def test_no_persistent_state_is_created_on_disk(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    state = DNSTelemetryState()

    state.record_query("api.example.com", timestamp=1.0)
    state.get_domain_stats("api.example.com")
    state.get_parent_domain_stats("example.com")
    state.analyze_behavior("api.example.com")

    assert list(tmp_path.iterdir()) == []
