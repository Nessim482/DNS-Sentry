import csv
import json

import pytest

from dns_sentry.export import export_events_to_csv, export_events_to_json

TEST_WEBHOOK_URL = "https://example.test/webhook"


def sample_events() -> list[dict]:
    return [
        {
            "id": 1,
            "timestamp": 10.5,
            "domain": "danger.example.com",
            "subdomain": "danger",
            "entropy": 4.5,
            "threshold": 4.0,
            "risk_score": 90,
            "severity": "Critical",
            "action": "quarantine_and_containment",
            "reasons": ["Critical score", TEST_WEBHOOK_URL],
            "interface": "Ethernet",
            "record_type": "TXT",
            "source": "test",
            "quarantined": True,
            "containment_required": True,
            "webhook_url": TEST_WEBHOOK_URL,
            "token": "secret-token",
        }
    ]


def test_export_events_to_json_creates_valid_file_without_secrets(tmp_path) -> None:
    output_path = tmp_path / "events.json"

    export_events_to_json(sample_events(), str(output_path))

    exported_events = json.loads(output_path.read_text(encoding="utf-8"))
    raw_output = output_path.read_text(encoding="utf-8")

    assert exported_events[0]["domain"] == "danger.example.com"
    assert exported_events[0]["severity"] == "Critical"
    assert exported_events[0]["action"] == "quarantine_and_containment"
    assert "webhook_url" not in exported_events[0]
    assert "token" not in exported_events[0]
    assert TEST_WEBHOOK_URL not in raw_output
    assert "secret-token" not in raw_output


def test_export_events_to_csv_creates_valid_file_without_secrets(tmp_path) -> None:
    output_path = tmp_path / "events.csv"

    export_events_to_csv(sample_events(), str(output_path))

    with output_path.open(encoding="utf-8", newline="") as input_file:
        rows = list(csv.DictReader(input_file))

    raw_output = output_path.read_text(encoding="utf-8")

    assert rows[0]["domain"] == "danger.example.com"
    assert rows[0]["severity"] == "Critical"
    assert rows[0]["action"] == "quarantine_and_containment"
    assert "webhook_url" not in rows[0]
    assert "token" not in rows[0]
    assert TEST_WEBHOOK_URL not in raw_output
    assert "secret-token" not in raw_output


@pytest.mark.parametrize(
    "filename",
    [".env", "capture.pcap", "capture.pcapng", "events.db", "events.sqlite"],
)
def test_export_rejects_sensitive_output_paths(tmp_path, filename) -> None:
    with pytest.raises(ValueError):
        export_events_to_json(sample_events(), str(tmp_path / filename))
