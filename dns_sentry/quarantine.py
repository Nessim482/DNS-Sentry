"""Logical in-memory quarantine decisions for DNS-Sentry."""

from __future__ import annotations

from time import time


_ACTION_DECISIONS = {
    "allow": {
        "applied": True,
        "quarantined": False,
        "containment_required": False,
        "message": "Domain allowed by policy.",
    },
    "log": {
        "applied": True,
        "quarantined": False,
        "containment_required": False,
        "message": "Domain logged for monitoring.",
    },
    "alert": {
        "applied": True,
        "quarantined": False,
        "containment_required": False,
        "message": "DNS alert required.",
    },
    "strong_alert": {
        "applied": True,
        "quarantined": False,
        "containment_required": False,
        "message": "Strong DNS alert required.",
    },
    "quarantine": {
        "applied": True,
        "quarantined": True,
        "containment_required": False,
        "message": "Logical quarantine applied.",
    },
    "quarantine_and_containment": {
        "applied": True,
        "quarantined": True,
        "containment_required": True,
        "message": "Logical quarantine and containment required.",
    },
}


def _normalize_domain(domain: object) -> str:
    return str(domain).strip().rstrip(".").lower()


def _normalize_action(action: object) -> str:
    return str(action).strip().lower()


def _copy_reasons(reasons: object) -> list[str]:
    if reasons is None:
        return []

    if isinstance(reasons, list):
        return [str(reason) for reason in reasons]

    return [str(reasons)]


def apply_action(result: dict) -> dict:
    """Apply a logical decision from a scored DNS result."""
    domain = _normalize_domain(result["domain"])
    action = _normalize_action(result.get("action", ""))
    reasons = _copy_reasons(result.get("reasons"))
    decision = _ACTION_DECISIONS.get(action)

    if decision is None:
        return {
            "domain": domain,
            "action": action,
            "applied": False,
            "quarantined": False,
            "containment_required": False,
            "message": "Unknown action; no logical quarantine applied.",
            "reasons": reasons,
        }

    return {
        "domain": domain,
        "action": action,
        "applied": decision["applied"],
        "quarantined": decision["quarantined"],
        "containment_required": decision["containment_required"],
        "message": decision["message"],
        "reasons": reasons,
    }


class QuarantineState:
    """Keep logical quarantine entries in memory only."""

    def __init__(self) -> None:
        self._quarantined_domains: dict[str, dict] = {}

    def add(self, result: dict) -> None:
        """Store a domain only when its action means logical quarantine."""
        decision = apply_action(result)

        if not decision["quarantined"]:
            return

        domain = decision["domain"]
        self._quarantined_domains[domain] = {
            "domain": domain,
            "timestamp": time(),
            "risk_score": result.get("risk_score"),
            "severity": result.get("severity"),
            "action": decision["action"],
            "reasons": list(decision["reasons"]),
        }

    def is_quarantined(self, domain: str) -> bool:
        """Return whether a normalized domain is logically quarantined."""
        return _normalize_domain(domain) in self._quarantined_domains

    def list_quarantined(self) -> list[dict]:
        """Return stable copies of logical quarantine entries."""
        return [
            dict(self._quarantined_domains[domain])
            for domain in sorted(self._quarantined_domains)
        ]

    def clear(self) -> None:
        """Clear all in-memory logical quarantine entries."""
        self._quarantined_domains.clear()
