"""Domain analysis helpers for DNS-Sentry."""

from .entropy import shannon_entropy


def extract_subdomain(domain: str) -> str:
    """Extract labels before the final two domain labels."""
    cleaned_domain = domain.strip().rstrip(".").lower()
    labels = [label for label in cleaned_domain.split(".") if label]

    if len(labels) <= 2:
        return ""

    return ".".join(labels[:-2])


def analyze_domain(domain: str, threshold: float = 3.5) -> dict[str, str | float | bool]:
    """Analyze a domain and flag suspicious high-entropy subdomains."""
    cleaned_domain = domain.strip().rstrip(".").lower()
    subdomain = extract_subdomain(cleaned_domain)
    entropy = shannon_entropy(subdomain)

    return {
        "domain": cleaned_domain,
        "subdomain": subdomain,
        "entropy": entropy,
        "threshold": threshold,
        "suspicious": entropy >= threshold,
    }

