"""Explainable DNS risk scoring helpers."""

from __future__ import annotations

import re
from collections.abc import Iterable

from .entropy import shannon_entropy

REPUTATION_MAX_SCORE = 30
STRUCTURE_MAX_SCORE = 25
BEHAVIOR_MAX_SCORE = 35
CONTEXT_MAX_SCORE = 10

HEX_PATTERN = re.compile(r"^[a-f0-9]{16,}$")
BASE32_PATTERN = re.compile(r"^[a-z2-7]{16,}$")
BASE64URL_PATTERN = re.compile(r"^[a-z0-9_-]{20,}$")


def _normalize_domain(domain: str) -> str:
    return domain.strip().rstrip(".").lower()


def _clamp(value: int, minimum: int, maximum: int) -> int:
    return max(minimum, min(maximum, value))


def _domain_labels(domain: str) -> list[str]:
    return [label for label in domain.split(".") if label]


def _scored_labels(domain: str) -> list[str]:
    labels = _domain_labels(domain)
    if len(labels) <= 1:
        return labels

    return labels[:-1]


def _severity_and_action(score: int) -> tuple[str, str]:
    if score <= 24:
        return "Safe", "allow"
    if score <= 44:
        return "Low Suspicious", "log"
    if score <= 64:
        return "Suspicious", "alert"
    if score <= 74:
        return "High Risk", "strong_alert"
    if score <= 89:
        return "Dangerous", "quarantine"

    return "Critical", "quarantine_and_containment"


def _has_high_digit_symbol_ratio(labels: Iterable[str]) -> bool:
    for label in labels:
        if len(label) < 6:
            continue

        digit_symbol_count = sum(
            1 for character in label if character.isdigit() or not character.isalpha()
        )

        if digit_symbol_count / len(label) >= 0.30:
            return True

    return False


def _has_low_vowel_ratio(labels: Iterable[str]) -> bool:
    vowels = set("aeiou")

    for label in labels:
        letters = [character for character in label if character.isalpha()]
        if len(letters) < 8:
            continue

        vowel_count = sum(1 for character in letters if character in vowels)
        if vowel_count / len(letters) <= 0.18:
            return True

    return False


def _has_encoded_pattern(labels: Iterable[str]) -> bool:
    for label in labels:
        compact_label = label.replace("-", "")
        if len(compact_label) < 16:
            continue

        unique_count = len(set(compact_label))
        has_digit = any(character.isdigit() for character in compact_label)
        has_base32_digit = any(character in "234567" for character in compact_label)
        has_urlsafe_symbol = "-" in label or "_" in label

        if HEX_PATTERN.fullmatch(compact_label) and unique_count >= 4:
            return True

        if (
            BASE32_PATTERN.fullmatch(compact_label)
            and unique_count >= 8
            and has_base32_digit
        ):
            return True

        if (
            BASE64URL_PATTERN.fullmatch(label)
            and unique_count >= 8
            and (has_digit or has_urlsafe_symbol)
        ):
            return True

    return False


def _score_reputation(
    reputation_result: dict | None,
    context: dict,
    reasons: list[str],
) -> int:
    reputation_data = reputation_result or {}

    if reputation_result is None:
        reasons.append("No reputation context provided; no reputation points applied.")

    reputation_score = 0

    if reputation_data.get("blacklisted"):
        reputation_score += 30
        reasons.append("Blacklist match adds 30 reputation points.")

    if reputation_data.get("ioc_match"):
        reputation_score += 25
        reasons.append("Imported IOC match adds 25 reputation points.")

    if context.get("previously_quarantined"):
        reputation_score += 20
        reasons.append("Previously quarantined domain adds 20 reputation points.")

    if reputation_data.get("suspicious_tld"):
        reputation_score += 5
        reasons.append("Suspicious TLD adds 5 reputation points.")

    if reputation_data.get("unknown_domain"):
        reputation_score += 5
        reasons.append("Unknown domain adds 5 reputation points.")

    if reputation_data.get("known_legitimate"):
        reputation_score -= 20
        reasons.append("Known legitimate domain subtracts 20 reputation points.")

    capped_score = min(reputation_score, REPUTATION_MAX_SCORE)
    if capped_score != reputation_score:
        reasons.append("Reputation score capped at 30 points.")

    return capped_score


def _score_structure(domain: str, threshold: float, reasons: list[str]) -> int:
    labels = _scored_labels(domain)
    structure_score = 0

    highest_entropy = max((shannon_entropy(label) for label in labels), default=0.0)
    if highest_entropy >= threshold:
        structure_score += 10
        reasons.append("High Shannon entropy adds 10 structure points.")

    subdomain = ".".join(labels[:-1]) if len(labels) > 1 else ""
    if (
        len(domain) >= 60
        or len(subdomain) >= 40
        or any(len(label) >= 30 for label in labels)
    ):
        structure_score += 5
        reasons.append("Long domain or subdomain adds 5 structure points.")

    if _has_high_digit_symbol_ratio(labels):
        structure_score += 4
        reasons.append("High digit/symbol ratio adds 4 structure points.")

    if _has_low_vowel_ratio(labels):
        structure_score += 3
        reasons.append("Low vowel/readability ratio adds 3 structure points.")

    if _has_encoded_pattern(labels):
        structure_score += 3
        reasons.append("Possible base64/base32/hex pattern adds 3 structure points.")

    return min(structure_score, STRUCTURE_MAX_SCORE)


def _has_unusual_record_type(telemetry_result: dict) -> bool:
    if telemetry_result.get("unusual_record_type"):
        return True

    if telemetry_result.get("excessive_cname"):
        return True

    unusual_types = telemetry_result.get("unusual_record_types", [])
    if isinstance(unusual_types, str):
        unusual_types = [unusual_types]

    normalized_unusual_types = {
        str(record_type).strip().upper() for record_type in unusual_types
    }
    if {"TXT", "NULL", "CNAME"} & normalized_unusual_types:
        return True

    record_types = telemetry_result.get("record_types", {})
    if not isinstance(record_types, dict):
        return False

    normalized_record_types = {
        str(record_type).strip().upper(): count
        for record_type, count in record_types.items()
    }

    return any(normalized_record_types.get(record_type, 0) for record_type in ("TXT", "NULL"))


def _score_behavior(telemetry_result: dict | None, reasons: list[str]) -> int:
    if telemetry_result is None:
        reasons.append(
            "DNS behavior context was not provided; no behavior points applied."
        )
        return 0

    behavior_score = 0

    if telemetry_result.get("repeated_queries"):
        behavior_score += 10
        reasons.append("Repeated queries add 10 behavior points.")

    if telemetry_result.get("many_unique_subdomains"):
        behavior_score += 8
        reasons.append("Many unique subdomains add 8 behavior points.")

    if telemetry_result.get("high_nxdomain_ratio"):
        behavior_score += 7
        reasons.append("High NXDOMAIN ratio adds 7 behavior points.")

    if telemetry_result.get("possible_beaconing"):
        behavior_score += 5
        reasons.append("Possible beaconing adds 5 behavior points.")

    if _has_unusual_record_type(telemetry_result):
        behavior_score += 5
        reasons.append("Unusual DNS record type adds 5 behavior points.")

    return min(behavior_score, BEHAVIOR_MAX_SCORE)


def _score_context(context: dict, reasons: list[str]) -> int:
    context_score = 0

    if context.get("sensitive_host"):
        context_score += 5
        reasons.append("Sensitive host adds 5 context points.")

    if context.get("unusual_activity_time"):
        context_score += 5
        reasons.append("Unusual activity time adds 5 context points.")

    if context.get("frequently_seen_benign"):
        context_score -= 10
        reasons.append("Frequently seen benign domain subtracts 10 context points.")

    return _clamp(context_score, -10, CONTEXT_MAX_SCORE)


def score_domain(
    domain: str,
    threshold: float = 4.0,
    telemetry_result: dict | None = None,
    reputation_result: dict | None = None,
    context: dict | None = None,
) -> dict:
    """Score one domain from local, already-collected DNS signals."""
    normalized_domain = _normalize_domain(domain)
    reasons: list[str] = []
    context_data = context or {}

    if reputation_result and reputation_result.get("whitelisted"):
        return {
            "domain": normalized_domain,
            "risk_score": 0,
            "severity": "Safe",
            "action": "allow",
            "reasons": [
                "Whitelist match forces risk score to 0 and action allow.",
            ],
        }

    reputation_score = _score_reputation(reputation_result, context_data, reasons)
    structure_score = _score_structure(normalized_domain, threshold, reasons)
    behavior_score = _score_behavior(telemetry_result, reasons)
    context_score = _score_context(context_data, reasons)

    raw_score = reputation_score + structure_score + behavior_score + context_score
    risk_score = _clamp(raw_score, 0, 100)
    if risk_score != raw_score:
        reasons.append(f"Final score clamped from {raw_score} to {risk_score}.")

    severity, action = _severity_and_action(risk_score)

    return {
        "domain": normalized_domain,
        "risk_score": risk_score,
        "severity": severity,
        "action": action,
        "reasons": reasons,
    }
