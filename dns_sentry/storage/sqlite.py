"""SQLite persistence helpers for DNS-Sentry."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import time
from typing import Any


def _connect(database_path: str) -> sqlite3.Connection:
    path = Path(database_path)
    if path.parent != Path("."):
        path.parent.mkdir(parents=True, exist_ok=True)

    return sqlite3.connect(path)


def _serialize_reasons(value: object) -> str:
    if value is None:
        reasons: list[str] = []
    elif isinstance(value, list):
        reasons = [str(reason) for reason in value]
    else:
        reasons = [str(value)]

    return json.dumps(reasons)


def _deserialize_reasons(value: object) -> list[str]:
    if value is None:
        return []

    try:
        decoded = json.loads(str(value))
    except json.JSONDecodeError:
        return [str(value)]

    if isinstance(decoded, list):
        return [str(reason) for reason in decoded]

    return [str(decoded)]


def _optional_float(value: object) -> float | None:
    if value is None:
        return None

    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _optional_int(value: object) -> int | None:
    if value is None:
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _text(value: object, default: str = "") -> str:
    if value is None:
        return default

    return str(value)


def _bool_int(value: object) -> int:
    return 1 if bool(value) else 0


def _bounded_limit(limit: int) -> int:
    try:
        parsed_limit = int(limit)
    except (TypeError, ValueError):
        return 100

    return max(0, parsed_limit)


def init_db(database_path: str) -> None:
    """Create DNS-Sentry SQLite tables if they do not already exist."""
    with _connect(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS dns_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                domain TEXT NOT NULL,
                subdomain TEXT NOT NULL,
                entropy REAL,
                threshold REAL,
                risk_score INTEGER,
                severity TEXT,
                action TEXT,
                reasons TEXT NOT NULL,
                interface TEXT,
                record_type TEXT,
                source TEXT,
                quarantined INTEGER NOT NULL DEFAULT 0,
                containment_required INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS quarantine (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                domain TEXT NOT NULL,
                risk_score INTEGER,
                severity TEXT,
                action TEXT,
                reasons TEXT NOT NULL,
                containment_required INTEGER NOT NULL DEFAULT 0
            )
            """
        )


def save_dns_event(database_path: str, event: dict) -> int:
    """Persist one DNS event and return the inserted row id."""
    init_db(database_path)
    timestamp = _optional_float(event.get("timestamp"))
    values = {
        "timestamp": timestamp if timestamp is not None else time.time(),
        "domain": _text(event.get("domain")),
        "subdomain": _text(event.get("subdomain")),
        "entropy": _optional_float(event.get("entropy")),
        "threshold": _optional_float(event.get("threshold")),
        "risk_score": _optional_int(event.get("risk_score")),
        "severity": _text(event.get("severity")),
        "action": _text(event.get("action")),
        "reasons": _serialize_reasons(event.get("reasons")),
        "interface": _text(event.get("interface")),
        "record_type": _text(event.get("record_type")),
        "source": _text(event.get("source"), default="runtime"),
        "quarantined": _bool_int(event.get("quarantined")),
        "containment_required": _bool_int(event.get("containment_required")),
    }

    with _connect(database_path) as connection:
        cursor = connection.execute(
            """
            INSERT INTO dns_events (
                timestamp,
                domain,
                subdomain,
                entropy,
                threshold,
                risk_score,
                severity,
                action,
                reasons,
                interface,
                record_type,
                source,
                quarantined,
                containment_required
            )
            VALUES (
                :timestamp,
                :domain,
                :subdomain,
                :entropy,
                :threshold,
                :risk_score,
                :severity,
                :action,
                :reasons,
                :interface,
                :record_type,
                :source,
                :quarantined,
                :containment_required
            )
            """,
            values,
        )
        return int(cursor.lastrowid)


def save_quarantine_event(database_path: str, result: dict) -> int:
    """Persist one logical quarantine event and return the inserted row id."""
    init_db(database_path)
    timestamp = _optional_float(result.get("timestamp"))
    values = {
        "timestamp": timestamp if timestamp is not None else time.time(),
        "domain": _text(result.get("domain")),
        "risk_score": _optional_int(result.get("risk_score")),
        "severity": _text(result.get("severity")),
        "action": _text(result.get("action")),
        "reasons": _serialize_reasons(result.get("reasons")),
        "containment_required": _bool_int(result.get("containment_required")),
    }

    with _connect(database_path) as connection:
        cursor = connection.execute(
            """
            INSERT INTO quarantine (
                timestamp,
                domain,
                risk_score,
                severity,
                action,
                reasons,
                containment_required
            )
            VALUES (
                :timestamp,
                :domain,
                :risk_score,
                :severity,
                :action,
                :reasons,
                :containment_required
            )
            """,
            values,
        )
        return int(cursor.lastrowid)


def _row_to_dict(row: sqlite3.Row, boolean_fields: set[str]) -> dict[str, Any]:
    result = dict(row)
    result["reasons"] = _deserialize_reasons(result.get("reasons"))

    for field_name in boolean_fields:
        result[field_name] = bool(result.get(field_name))

    return result


def list_dns_events(
    database_path: str,
    limit: int = 100,
    severity: str | None = None,
    action: str | None = None,
) -> list[dict]:
    """List DNS events newest first, optionally filtered by severity/action."""
    init_db(database_path)
    clauses = []
    params: list[object] = []

    if severity:
        clauses.append("severity = ?")
        params.append(severity)

    if action:
        clauses.append("action = ?")
        params.append(action)

    where_clause = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(_bounded_limit(limit))

    with _connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            f"""
            SELECT
                id,
                timestamp,
                domain,
                subdomain,
                entropy,
                threshold,
                risk_score,
                severity,
                action,
                reasons,
                interface,
                record_type,
                source,
                quarantined,
                containment_required
            FROM dns_events
            {where_clause}
            ORDER BY id DESC
            LIMIT ?
            """,
            params,
        ).fetchall()

    return [
        _row_to_dict(row, {"quarantined", "containment_required"})
        for row in rows
    ]


def list_quarantine_events(database_path: str, limit: int = 100) -> list[dict]:
    """List logical quarantine events newest first."""
    init_db(database_path)

    with _connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT
                id,
                timestamp,
                domain,
                risk_score,
                severity,
                action,
                reasons,
                containment_required
            FROM quarantine
            ORDER BY id DESC
            LIMIT ?
            """,
            (_bounded_limit(limit),),
        ).fetchall()

    return [_row_to_dict(row, {"containment_required"}) for row in rows]


def clear_events(database_path: str) -> None:
    """Delete all persisted DNS events."""
    init_db(database_path)

    with _connect(database_path) as connection:
        connection.execute("DELETE FROM dns_events")


def clear_quarantine(database_path: str) -> None:
    """Delete all persisted logical quarantine events."""
    init_db(database_path)

    with _connect(database_path) as connection:
        connection.execute("DELETE FROM quarantine")
