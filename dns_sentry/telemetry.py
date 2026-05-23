"""In-memory DNS telemetry helpers for behavior analysis."""

from __future__ import annotations

from collections import Counter, defaultdict
from time import time

REPEATED_QUERY_COUNT = 3
REPEATED_QUERY_WINDOW_SECONDS = 10.0
MANY_UNIQUE_SUBDOMAIN_THRESHOLD = 5
BEACONING_MIN_QUERIES = 4
BEACONING_MAX_DEVIATION_SECONDS = 1.0
BEACONING_MAX_DEVIATION_RATIO = 0.2


def _normalize_domain(domain: str) -> str:
    cleaned_domain = domain.strip().rstrip(".").lower()

    if not cleaned_domain:
        raise ValueError("domain cannot be empty")

    return cleaned_domain


def _normalize_record_type(record_type: str) -> str:
    cleaned_record_type = record_type.strip().upper()
    return cleaned_record_type or "UNKNOWN"


def _domain_labels(domain: str) -> list[str]:
    return [label for label in domain.split(".") if label]


def _parent_domain(domain: str) -> str:
    labels = _domain_labels(domain)

    if len(labels) <= 2:
        return ".".join(labels)

    return ".".join(labels[-2:])


def _subdomain(domain: str) -> str:
    labels = _domain_labels(domain)

    if len(labels) <= 2:
        return ""

    return ".".join(labels[:-2])


def _has_repeated_queries(timestamps: list[float]) -> bool:
    if len(timestamps) < REPEATED_QUERY_COUNT:
        return False

    sorted_timestamps = sorted(timestamps)

    for index in range(len(sorted_timestamps) - REPEATED_QUERY_COUNT + 1):
        window_end_index = index + REPEATED_QUERY_COUNT - 1

        if (
            sorted_timestamps[window_end_index] - sorted_timestamps[index]
            <= REPEATED_QUERY_WINDOW_SECONDS
        ):
            return True

    return False


def _has_possible_beaconing(timestamps: list[float]) -> bool:
    if len(timestamps) < BEACONING_MIN_QUERIES:
        return False

    sorted_timestamps = sorted(timestamps)
    intervals = [
        current - previous
        for previous, current in zip(sorted_timestamps, sorted_timestamps[1:])
    ]

    if not intervals or any(interval <= 0 for interval in intervals):
        return False

    average_interval = sum(intervals) / len(intervals)
    max_deviation = max(
        BEACONING_MAX_DEVIATION_SECONDS,
        average_interval * BEACONING_MAX_DEVIATION_RATIO,
    )

    return all(
        abs(interval - average_interval) <= max_deviation for interval in intervals
    )


class DNSTelemetryState:
    """Track DNS query behavior in memory only."""

    def __init__(self) -> None:
        self._domain_query_counts: Counter[str] = Counter()
        self._domain_timestamps: defaultdict[str, list[float]] = defaultdict(list)
        self._domain_record_types: defaultdict[str, Counter[str]] = defaultdict(Counter)
        self._parent_query_counts: Counter[str] = Counter()
        self._parent_timestamps: defaultdict[str, list[float]] = defaultdict(list)
        self._parent_record_types: defaultdict[str, Counter[str]] = defaultdict(Counter)
        self._parent_unique_subdomains: defaultdict[str, set[str]] = defaultdict(set)

    def record_query(
        self,
        domain: str,
        record_type: str = "A",
        timestamp: float | None = None,
    ) -> None:
        """Record one observed DNS query."""
        normalized_domain = _normalize_domain(domain)
        normalized_record_type = _normalize_record_type(record_type)
        query_timestamp = time() if timestamp is None else float(timestamp)
        parent_domain = _parent_domain(normalized_domain)
        subdomain = _subdomain(normalized_domain)

        self._domain_query_counts[normalized_domain] += 1
        self._domain_timestamps[normalized_domain].append(query_timestamp)
        self._domain_record_types[normalized_domain][normalized_record_type] += 1

        self._parent_query_counts[parent_domain] += 1
        self._parent_timestamps[parent_domain].append(query_timestamp)
        self._parent_record_types[parent_domain][normalized_record_type] += 1

        if subdomain:
            self._parent_unique_subdomains[parent_domain].add(subdomain)

    def get_domain_stats(self, domain: str) -> dict:
        """Return query statistics for one domain."""
        normalized_domain = _normalize_domain(domain)

        return {
            "domain": normalized_domain,
            "parent_domain": _parent_domain(normalized_domain),
            "total_queries": self._domain_query_counts[normalized_domain],
            "timestamps": list(self._domain_timestamps[normalized_domain]),
            "record_types": dict(self._domain_record_types[normalized_domain]),
        }

    def get_parent_domain_stats(self, parent_domain: str) -> dict:
        """Return query statistics grouped by parent domain."""
        normalized_parent_domain = _normalize_domain(parent_domain)
        unique_subdomains = sorted(
            self._parent_unique_subdomains[normalized_parent_domain]
        )

        return {
            "parent_domain": normalized_parent_domain,
            "total_queries": self._parent_query_counts[normalized_parent_domain],
            "unique_subdomains": unique_subdomains,
            "unique_subdomain_count": len(unique_subdomains),
            "timestamps": list(self._parent_timestamps[normalized_parent_domain]),
            "record_types": dict(self._parent_record_types[normalized_parent_domain]),
        }

    def analyze_behavior(self, domain: str) -> dict:
        """Analyze simple behavior signals for a recorded domain."""
        normalized_domain = _normalize_domain(domain)
        domain_stats = self.get_domain_stats(normalized_domain)
        parent_stats = self.get_parent_domain_stats(domain_stats["parent_domain"])
        repeated_queries = _has_repeated_queries(domain_stats["timestamps"])
        many_unique_subdomains = (
            parent_stats["unique_subdomain_count"]
            >= MANY_UNIQUE_SUBDOMAIN_THRESHOLD
        )
        possible_beaconing = _has_possible_beaconing(domain_stats["timestamps"])
        reasons: list[str] = []

        if repeated_queries:
            reasons.append("Repeated queries for the same domain in a short window")

        if many_unique_subdomains:
            reasons.append("Many unique subdomains observed for the parent domain")

        if possible_beaconing:
            reasons.append("Regular query intervals suggest possible beaconing")

        return {
            "repeated_queries": repeated_queries,
            "many_unique_subdomains": many_unique_subdomains,
            "possible_beaconing": possible_beaconing,
            "reasons": reasons,
        }


_DEFAULT_STATE = DNSTelemetryState()


def record_query(
    domain: str,
    record_type: str = "A",
    timestamp: float | None = None,
) -> None:
    """Record one observed DNS query in the default in-memory state."""
    _DEFAULT_STATE.record_query(domain, record_type=record_type, timestamp=timestamp)


def get_domain_stats(domain: str) -> dict:
    """Return domain statistics from the default in-memory state."""
    return _DEFAULT_STATE.get_domain_stats(domain)


def get_parent_domain_stats(parent_domain: str) -> dict:
    """Return parent domain statistics from the default in-memory state."""
    return _DEFAULT_STATE.get_parent_domain_stats(parent_domain)


def analyze_behavior(domain: str) -> dict:
    """Analyze behavior signals from the default in-memory state."""
    return _DEFAULT_STATE.analyze_behavior(domain)


def reset_telemetry() -> None:
    """Reset the default in-memory state."""
    global _DEFAULT_STATE
    _DEFAULT_STATE = DNSTelemetryState()
