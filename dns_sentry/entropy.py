"""Entropy utilities for DNS-Sentry."""

from collections import Counter
from math import log2


def shannon_entropy(value: str) -> float:
    """Return the Shannon entropy of a string."""
    if not value:
        return 0.0

    length = len(value)
    entropy = -sum(
        (count / length) * log2(count / length)
        for count in Counter(value).values()
    )

    return 0.0 if entropy == 0.0 else entropy
