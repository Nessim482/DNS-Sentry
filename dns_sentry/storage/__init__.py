"""Local persistence backends for DNS-Sentry."""

from .sqlite import (
    clear_events,
    clear_quarantine,
    init_db,
    list_dns_events,
    list_quarantine_events,
    save_dns_event,
    save_quarantine_event,
)

__all__ = [
    "clear_events",
    "clear_quarantine",
    "init_db",
    "list_dns_events",
    "list_quarantine_events",
    "save_dns_event",
    "save_quarantine_event",
]
