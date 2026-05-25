"""Local HTML report generation for DNS-Sentry events."""

from __future__ import annotations

from collections import Counter
import html
import json
from pathlib import Path
from typing import Iterable

from .logging_config import mask_sensitive_text

ALERT_ACTIONS = {
    "alert",
    "strong_alert",
    "quarantine",
    "quarantine_and_containment",
}
DANGEROUS_OUTPUT_NAMES = {".env"}
DANGEROUS_OUTPUT_SUFFIXES = {".env", ".db", ".sqlite", ".pcap", ".pcapng"}
SENSITIVE_KEY_PARTS = ("webhook", "token", "secret", "password")
REPORT_TITLE = "DNS-Sentry Security Report"


def _escape(value: object) -> str:
    if value is None:
        return "N/A"

    text = str(value)
    if any(part in text.lower() for part in SENSITIVE_KEY_PARTS):
        return "[redacted]"

    return html.escape(mask_sensitive_text(text), quote=True)


def _risk_score(event: dict) -> int:
    try:
        return int(event.get("risk_score") or 0)
    except (TypeError, ValueError):
        return 0


def _is_alert_action(event: dict) -> bool:
    return str(event.get("action", "")).strip() in ALERT_ACTIONS


def _domain_tld(domain: object) -> str:
    labels = [label for label in str(domain or "").strip(".").lower().split(".") if label]
    if not labels:
        return "unknown"

    return labels[-1]


def _normalize_reasons(value: object) -> list[str]:
    if value is None:
        return []

    if isinstance(value, list):
        return [str(reason) for reason in value if str(reason).strip()]

    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            decoded = value

        if isinstance(decoded, list):
            return [str(reason) for reason in decoded if str(reason).strip()]

    return [str(value)]


def _safe_config_summary(config_summary: dict | None) -> dict[str, object]:
    if not config_summary:
        return {}

    safe_summary = {}
    for key, value in config_summary.items():
        normalized_key = str(key).lower()
        if any(part in normalized_key for part in SENSITIVE_KEY_PARTS):
            continue

        safe_summary[str(key)] = value

    return safe_summary


def _validate_output_path(output_path: str) -> Path:
    path = Path(output_path)
    name = path.name.lower()
    suffix = path.suffix.lower()

    if name in DANGEROUS_OUTPUT_NAMES or suffix in DANGEROUS_OUTPUT_SUFFIXES:
        raise ValueError("refusing to write HTML report to a dangerous output path")

    if path.parent != Path("."):
        path.parent.mkdir(parents=True, exist_ok=True)

    return path


def _summary(events: list[dict], quarantine_events: list[dict]) -> dict[str, int]:
    return {
        "total_events": len(events),
        "alert_events": sum(1 for event in events if _is_alert_action(event)),
        "quarantined_domains": len(
            {str(event.get("domain", "")).lower() for event in quarantine_events}
        ),
        "max_score": max((_risk_score(event) for event in events), default=0),
    }


def _top_suspicious_domains(events: list[dict], limit: int = 10) -> list[dict]:
    suspicious_events = [
        event for event in events if _is_alert_action(event) or _risk_score(event) > 0
    ]
    return sorted(
        suspicious_events,
        key=lambda event: (_risk_score(event), str(event.get("domain", ""))),
        reverse=True,
    )[:limit]


def _top_suspicious_tlds(events: list[dict], limit: int = 10) -> list[tuple[str, int]]:
    suspicious_events = [
        event for event in events if _is_alert_action(event) or _risk_score(event) > 0
    ]
    counts = Counter(_domain_tld(event.get("domain")) for event in suspicious_events)
    return counts.most_common(limit)


def _frequent_reasons(events: Iterable[dict], limit: int = 10) -> list[tuple[str, int]]:
    counts: Counter[str] = Counter()

    for event in events:
        counts.update(_normalize_reasons(event.get("reasons")))

    return counts.most_common(limit)


def _table(headers: tuple[str, ...], rows: list[tuple[object, ...]]) -> str:
    header_html = "".join(f"<th>{_escape(header)}</th>" for header in headers)

    if not rows:
        body_html = (
            f"<tr><td colspan=\"{len(headers)}\" class=\"empty\">No data available</td></tr>"
        )
    else:
        body_html = "".join(
            "<tr>"
            + "".join(f"<td>{_escape(value)}</td>" for value in row)
            + "</tr>"
            for row in rows
        )

    return f"<table><thead><tr>{header_html}</tr></thead><tbody>{body_html}</tbody></table>"


def generate_html_report(
    events: list[dict],
    quarantine_events: list[dict],
    output_path: str,
    config_summary: dict | None = None,
) -> None:
    """Generate a standalone local HTML security report."""
    path = _validate_output_path(output_path)
    safe_config = _safe_config_summary(config_summary)
    summary = _summary(events, quarantine_events)

    summary_rows = [
        ("Total events", summary["total_events"]),
        ("Alert-level events", summary["alert_events"]),
        ("Quarantined domains", summary["quarantined_domains"]),
        ("Maximum risk score", summary["max_score"]),
    ]
    if "risk_profile" in safe_config:
        summary_rows.append(("Risk profile", safe_config["risk_profile"]))
    if "database_path" in safe_config:
        summary_rows.append(("Database path", safe_config["database_path"]))

    domain_rows = [
        (
            event.get("domain"),
            _risk_score(event),
            event.get("severity"),
            event.get("action"),
        )
        for event in _top_suspicious_domains(events)
    ]
    tld_rows = _top_suspicious_tlds(events)
    quarantine_rows = [
        (
            event.get("domain"),
            _risk_score(event),
            event.get("severity"),
            event.get("action"),
            event.get("containment_required"),
        )
        for event in quarantine_events
    ]
    reason_rows = _frequent_reasons([*events, *quarantine_events])
    config_rows = sorted(safe_config.items())

    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{REPORT_TITLE}</title>
  <style>
    body {{
      color: #17202a;
      font-family: Arial, sans-serif;
      line-height: 1.45;
      margin: 32px;
    }}
    h1, h2 {{
      color: #102033;
    }}
    section {{
      margin: 28px 0;
    }}
    table {{
      border-collapse: collapse;
      width: 100%;
    }}
    th, td {{
      border: 1px solid #d6dde6;
      padding: 8px 10px;
      text-align: left;
    }}
    th {{
      background: #edf2f7;
    }}
    .empty {{
      color: #5f6f83;
      font-style: italic;
    }}
    .disclaimer {{
      background: #f6f8fb;
      border-left: 4px solid #516b8f;
      padding: 12px 14px;
    }}
  </style>
</head>
<body>
  <h1>{REPORT_TITLE}</h1>

  <section>
    <h2>Summary</h2>
    {_table(("Metric", "Value"), summary_rows)}
  </section>

  <section>
    <h2>Top Suspicious Domains</h2>
    {_table(("Domain", "Risk Score", "Severity", "Action"), domain_rows)}
  </section>

  <section>
    <h2>Top Suspicious TLDs</h2>
    {_table(("TLD", "Count"), tld_rows)}
  </section>

  <section>
    <h2>Quarantined Events</h2>
    {_table(("Domain", "Risk Score", "Severity", "Action", "Containment Required"), quarantine_rows)}
  </section>

  <section>
    <h2>Frequent Reasons</h2>
    {_table(("Reason", "Count"), reason_rows)}
  </section>

  <section>
    <h2>Active Configuration</h2>
    {_table(("Setting", "Value"), config_rows)}
  </section>

  <section class="disclaimer">
    <h2>Disclaimer</h2>
    <p>DNS-Sentry is a defensive DNS monitoring tool.</p>
    <p>It detects, scores, alerts, and logically quarantines suspicious DNS domains.</p>
    <p>It does not perform network-level blocking by default.</p>
    <p>Results may include false positives and should be reviewed by an analyst.</p>
  </section>
</body>
</html>
"""

    path.write_text(document, encoding="utf-8")
