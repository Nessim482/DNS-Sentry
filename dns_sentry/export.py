"""Event export helpers for DNS-Sentry."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from .logging_config import mask_sensitive_text

EXPORT_FIELDS = (
    "id",
    "timestamp",
    "domain",
    "subdomain",
    "entropy",
    "threshold",
    "risk_score",
    "severity",
    "action",
    "reasons",
    "interface",
    "record_type",
    "source",
    "quarantined",
    "containment_required",
)

_SENSITIVE_KEY_PARTS = (
    "webhook",
    "token",
    "secret",
    "password",
    "api_key",
    "apikey",
    "credential",
)
_BLOCKED_OUTPUT_SUFFIXES = {".db", ".sqlite", ".pcap", ".pcapng"}


def _is_sensitive_key(key: str) -> bool:
    normalized_key = key.lower()
    return any(part in normalized_key for part in _SENSITIVE_KEY_PARTS)


def _sanitize_value(value: object) -> object:
    if isinstance(value, str):
        return mask_sensitive_text(value)

    if isinstance(value, list):
        return [_sanitize_value(item) for item in value]

    if isinstance(value, dict):
        return _sanitize_event(value)

    return value


def _sanitize_event(event: dict) -> dict:
    sanitized = {}

    for key, value in event.items():
        if _is_sensitive_key(str(key)):
            continue

        sanitized[str(key)] = _sanitize_value(value)

    return sanitized


def _filtered_event(event: dict) -> dict:
    sanitized = _sanitize_event(event)
    return {field: sanitized.get(field) for field in EXPORT_FIELDS if field in sanitized}


def _validate_output_path(output_path: str) -> Path:
    path = Path(output_path)

    if not str(output_path).strip():
        raise ValueError("output path must not be empty")

    if path.name.lower().startswith(".env"):
        raise ValueError("refusing to export to .env files")

    if path.suffix.lower() in _BLOCKED_OUTPUT_SUFFIXES:
        raise ValueError("refusing to export to sensitive or capture file types")

    if path.exists() and path.is_dir():
        raise ValueError("output path must be a file")

    if path.parent != Path("."):
        path.parent.mkdir(parents=True, exist_ok=True)

    return path


def _csv_value(value: Any) -> Any:
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False)

    if value is None:
        return ""

    return value


def export_events_to_json(events: list[dict], output_path: str) -> None:
    """Export DNS events to a JSON file."""
    path = _validate_output_path(output_path)
    sanitized_events = [_filtered_event(event) for event in events]
    path.write_text(
        json.dumps(sanitized_events, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def export_events_to_csv(events: list[dict], output_path: str) -> None:
    """Export DNS events to a CSV file."""
    path = _validate_output_path(output_path)
    sanitized_events = [_filtered_event(event) for event in events]

    with path.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=list(EXPORT_FIELDS))
        writer.writeheader()

        for event in sanitized_events:
            writer.writerow({field: _csv_value(event.get(field)) for field in EXPORT_FIELDS})
