"""Local DNS reputation list helpers."""

SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "link"}


def _normalize_domain(domain: str) -> str:
    return domain.strip().rstrip(".").lower()


def _normalize_domains(domains: set[str] | None) -> set[str]:
    if domains is None:
        return set()

    return {
        normalized
        for domain in domains
        if (normalized := _normalize_domain(domain))
    }


def _domain_candidates(domain: str) -> tuple[str, ...]:
    labels = [label for label in domain.split(".") if label]
    if not labels:
        return ()

    candidates = []
    for index in range(len(labels)):
        candidate = ".".join(labels[index:])
        if "." in candidate or index == 0:
            candidates.append(candidate)

    return tuple(candidates)


def _matches_domain_or_parent(domain: str, domains: set[str] | None) -> bool:
    normalized_domains = _normalize_domains(domains)
    if not normalized_domains:
        return False

    return any(candidate in normalized_domains for candidate in _domain_candidates(domain))


def load_domain_list(path: str) -> set[str]:
    """Load a local domain list, ignoring blank lines and full-line comments."""
    domains = set()

    with open(path, encoding="utf-8") as domain_list:
        for line in domain_list:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            domain = _normalize_domain(stripped)
            if domain:
                domains.add(domain)

    return domains


def check_reputation(
    domain: str,
    whitelist: set[str] | None = None,
    blacklist: set[str] | None = None,
    iocs: set[str] | None = None,
    known_legitimate: set[str] | None = None,
) -> dict:
    """Check a domain against local reputation signals."""
    normalized_domain = _normalize_domain(domain)

    whitelisted = _matches_domain_or_parent(normalized_domain, whitelist)
    blacklisted = False
    ioc_match = False

    if not whitelisted:
        blacklisted = _matches_domain_or_parent(normalized_domain, blacklist)
        ioc_match = _matches_domain_or_parent(normalized_domain, iocs)

    known_legitimate_match = _matches_domain_or_parent(
        normalized_domain,
        known_legitimate,
    )
    labels = [label for label in normalized_domain.split(".") if label]
    suspicious_tld = bool(labels and labels[-1] in SUSPICIOUS_TLDS)
    unknown_domain = not any(
        [
            whitelisted,
            blacklisted,
            ioc_match,
            known_legitimate_match,
        ]
    )

    reasons = []
    if whitelisted:
        reasons.append("whitelist")
    if blacklisted:
        reasons.append("blacklist")
    if ioc_match:
        reasons.append("ioc")
    if known_legitimate_match:
        reasons.append("known_legitimate")
    if suspicious_tld:
        reasons.append("suspicious_tld")
    if unknown_domain:
        reasons.append("unknown_domain")

    return {
        "domain": normalized_domain,
        "whitelisted": whitelisted,
        "blacklisted": blacklisted,
        "ioc_match": ioc_match,
        "known_legitimate": known_legitimate_match,
        "suspicious_tld": suspicious_tld,
        "unknown_domain": unknown_domain,
        "reasons": reasons,
    }
