from pathlib import Path

import pytest

from dns_sentry.report import generate_html_report

TEST_WEBHOOK_URL = "https://example.test/webhook"


def _sample_events() -> list[dict]:
    return [
        {
            "domain": "safe.example.com",
            "risk_score": 0,
            "severity": "Safe",
            "action": "allow",
            "reasons": [],
        },
        {
            "domain": "danger.example.zip",
            "risk_score": 90,
            "severity": "Critical",
            "action": "quarantine_and_containment",
            "reasons": [
                "Blacklist match adds 30 reputation points.",
                "Repeated queries add 10 behavior points.",
            ],
            "webhook_url": TEST_WEBHOOK_URL,
        },
        {
            "domain": "alert.example.top",
            "risk_score": 55,
            "severity": "Suspicious",
            "action": "alert",
            "reasons": ["Repeated queries add 10 behavior points."],
        },
    ]


def _sample_quarantine_events() -> list[dict]:
    return [
        {
            "domain": "danger.example.zip",
            "risk_score": 90,
            "severity": "Critical",
            "action": "quarantine_and_containment",
            "containment_required": True,
            "reasons": ["Logical quarantine and containment required."],
        }
    ]


def test_generate_html_report_creates_expected_sections(tmp_path: Path) -> None:
    output_path = tmp_path / "report.html"

    generate_html_report(
        _sample_events(),
        _sample_quarantine_events(),
        str(output_path),
        config_summary={
            "risk_profile": "demo",
            "thresholds": {"alert_threshold": 35},
            "persistence_enabled": True,
            "database_path": "./dns_sentry.db",
            "webhook_url": TEST_WEBHOOK_URL,
            "api_token": "secret-token",
        },
    )

    html = output_path.read_text(encoding="utf-8")

    assert output_path.is_file()
    assert "DNS-Sentry Security Report" in html
    assert "Summary" in html
    assert "Alert-level events" in html
    assert "Top Suspicious Domains" in html
    assert "danger.example.zip" in html
    assert "Top Suspicious TLDs" in html
    assert "<td>zip</td>" in html
    assert "Quarantined Events" in html
    assert "Containment Required" in html
    assert "Frequent Reasons" in html
    assert "Repeated queries add 10 behavior points." in html
    assert "DNS-Sentry is a defensive DNS monitoring tool." in html
    assert TEST_WEBHOOK_URL not in html
    assert "secret-token" not in html
    assert "api_token" not in html
    assert "webhook_url" not in html


def test_generate_empty_html_report_is_clear(tmp_path: Path) -> None:
    output_path = tmp_path / "empty-report.html"

    generate_html_report([], [], str(output_path))

    html = output_path.read_text(encoding="utf-8")

    assert "DNS-Sentry Security Report" in html
    assert "No data available" in html
    assert "Total events" in html
    assert "<td>0</td>" in html


@pytest.mark.parametrize(
    "dangerous_name",
    [".env", "report.db", "report.sqlite", "capture.pcap", "capture.pcapng"],
)
def test_generate_html_report_refuses_dangerous_output_paths(
    tmp_path: Path,
    dangerous_name: str,
) -> None:
    with pytest.raises(ValueError, match="dangerous output path"):
        generate_html_report([], [], str(tmp_path / dangerous_name))


def test_generate_html_report_masks_sensitive_values(tmp_path: Path) -> None:
    output_path = tmp_path / "masked.html"

    generate_html_report(
        [
            {
                "domain": "danger.example.test",
                "risk_score": 80,
                "severity": "Dangerous",
                "action": "quarantine",
                "reasons": [f"webhook={TEST_WEBHOOK_URL}", "token=secret-token"],
            }
        ],
        [],
        str(output_path),
        config_summary={"secret": "secret-token", "risk_profile": "balanced"},
    )

    html = output_path.read_text(encoding="utf-8")

    assert TEST_WEBHOOK_URL not in html
    assert "secret-token" not in html
    assert "webhook" not in html.lower()
    assert "token" not in html.lower()
