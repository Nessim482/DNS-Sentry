import sqlite3

from dns_sentry.storage.sqlite import (
    clear_events,
    clear_quarantine,
    init_db,
    list_dns_events,
    list_quarantine_events,
    save_dns_event,
    save_quarantine_event,
)

TEST_WEBHOOK_URL = "https://example.test/webhook"


def test_init_db_creates_tables(tmp_path) -> None:
    database_path = str(tmp_path / "events.db")

    init_db(database_path)

    with sqlite3.connect(database_path) as connection:
        table_names = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }

    assert {"dns_events", "quarantine"} <= table_names


def test_save_dns_event_inserts_and_lists_event(tmp_path) -> None:
    database_path = str(tmp_path / "events.db")

    row_id = save_dns_event(
        database_path,
        {
            "timestamp": 123.5,
            "domain": "example.com",
            "subdomain": "www",
            "entropy": 2.5,
            "threshold": 4.0,
            "risk_score": 45,
            "severity": "Suspicious",
            "action": "alert",
            "reasons": ["Blacklist match", "Repeated queries"],
            "interface": "Ethernet",
            "record_type": "TXT",
            "source": "test",
            "quarantined": False,
            "containment_required": False,
        },
    )

    events = list_dns_events(database_path)

    assert row_id == 1
    assert len(events) == 1
    assert events[0]["domain"] == "example.com"
    assert events[0]["reasons"] == ["Blacklist match", "Repeated queries"]
    assert events[0]["quarantined"] is False
    assert events[0]["containment_required"] is False


def test_save_quarantine_event_inserts_and_lists_event(tmp_path) -> None:
    database_path = str(tmp_path / "events.db")

    row_id = save_quarantine_event(
        database_path,
        {
            "timestamp": 123.5,
            "domain": "danger.example.com",
            "risk_score": 90,
            "severity": "Critical",
            "action": "quarantine_and_containment",
            "reasons": ["Critical score"],
            "containment_required": True,
        },
    )

    events = list_quarantine_events(database_path)

    assert row_id == 1
    assert len(events) == 1
    assert events[0]["domain"] == "danger.example.com"
    assert events[0]["reasons"] == ["Critical score"]
    assert events[0]["containment_required"] is True


def test_list_dns_events_filters_severity_and_action(tmp_path) -> None:
    database_path = str(tmp_path / "events.db")
    save_dns_event(
        database_path,
        {"domain": "critical.example.com", "severity": "Critical", "action": "alert"},
    )
    save_dns_event(
        database_path,
        {"domain": "safe.example.com", "severity": "Safe", "action": "allow"},
    )

    severity_results = list_dns_events(database_path, severity="Critical")
    action_results = list_dns_events(database_path, action="allow")

    assert [event["domain"] for event in severity_results] == ["critical.example.com"]
    assert [event["domain"] for event in action_results] == ["safe.example.com"]


def test_clear_events_empties_dns_events_only(tmp_path) -> None:
    database_path = str(tmp_path / "events.db")
    save_dns_event(database_path, {"domain": "example.com"})
    save_quarantine_event(database_path, {"domain": "danger.example.com"})

    clear_events(database_path)

    assert list_dns_events(database_path) == []
    assert len(list_quarantine_events(database_path)) == 1


def test_clear_quarantine_empties_quarantine_only(tmp_path) -> None:
    database_path = str(tmp_path / "events.db")
    save_dns_event(database_path, {"domain": "example.com"})
    save_quarantine_event(database_path, {"domain": "danger.example.com"})

    clear_quarantine(database_path)

    assert len(list_dns_events(database_path)) == 1
    assert list_quarantine_events(database_path) == []


def test_secret_fields_are_not_stored(tmp_path) -> None:
    database_path = str(tmp_path / "events.db")

    save_dns_event(
        database_path,
        {
            "domain": "example.com",
            "webhook_url": TEST_WEBHOOK_URL,
            "token": "secret-token",
            "reasons": ["safe reason"],
        },
    )

    events = list_dns_events(database_path)
    raw_database = tmp_path.joinpath("events.db").read_bytes()

    assert "webhook_url" not in events[0]
    assert "token" not in events[0]
    assert TEST_WEBHOOK_URL.encode() not in raw_database
    assert b"secret-token" not in raw_database


def test_list_limit_returns_newest_events_first(tmp_path) -> None:
    database_path = str(tmp_path / "events.db")

    save_dns_event(database_path, {"domain": "first.example.com"})
    save_dns_event(database_path, {"domain": "second.example.com"})

    events = list_dns_events(database_path, limit=1)

    assert [event["domain"] for event in events] == ["second.example.com"]
