"""Simple DNS log parsing helpers for DNS-Sentry."""

import re

from .analyzer import analyze_domain

_DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\b",
    re.IGNORECASE,
)


def parse_dns_query(log_line: str) -> str | None:
    """Extract the first domain found in a simple DNS log line."""
    match = _DOMAIN_PATTERN.search(log_line.strip())

    if match is None:
        return None

    return match.group(0).lower()


def analyze_log_line(log_line: str) -> dict[str, str | float | bool] | None:
    """Analyze the domain found in a simple DNS log line."""
    domain = parse_dns_query(log_line)

    if domain is None:
        return None

    return analyze_domain(domain)

