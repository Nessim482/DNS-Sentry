"""Simple environment-based configuration for DNS-Sentry."""

import os
from pathlib import Path

from dotenv import load_dotenv

from .scoring import ThresholdConfig, validate_thresholds

DEFAULT_DNS_ENTROPY_THRESHOLD = 3.5
DEFAULT_DNS_INTERFACE: str | None = None
DEFAULT_DNS_DEBUG = False
DEFAULT_DNS_RISK_THRESHOLDS = ThresholdConfig()
DEFAULT_ENABLE_PERSISTENCE = False
DEFAULT_DATABASE_PATH = "./dns_sentry.db"

_ENV_FILE = ".env"
_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}
_RISK_THRESHOLD_ENV_NAMES = {
    "low_suspicious_threshold": "DNS_LOW_SUSPICIOUS_THRESHOLD",
    "alert_threshold": "DNS_ALERT_THRESHOLD",
    "strong_alert_threshold": "DNS_STRONG_ALERT_THRESHOLD",
    "quarantine_threshold": "DNS_QUARANTINE_THRESHOLD",
    "containment_threshold": "DNS_CONTAINMENT_THRESHOLD",
}


def load_env_file(path: str | Path = _ENV_FILE) -> None:
    """Load environment values from a .env file without overriding env vars."""
    env_path = Path(path)

    if not env_path.exists():
        return

    try:
        load_dotenv(dotenv_path=env_path, override=False)
    except OSError:
        return


def load_discord_webhook_url(default: str | None = None) -> str | None:
    """Load the Discord webhook URL, if configured."""
    load_env_file()
    value = os.getenv("DISCORD_WEBHOOK_URL")

    if value is None:
        return default

    cleaned_value = value.strip()
    return cleaned_value or default


def load_dns_entropy_threshold(default: float = DEFAULT_DNS_ENTROPY_THRESHOLD) -> float:
    """Load a non-negative entropy threshold."""
    load_env_file()
    value = os.getenv("DNS_ENTROPY_THRESHOLD")

    if value is None or not value.strip():
        return default

    try:
        threshold = float(value)
    except ValueError:
        return default

    if threshold < 0:
        return default

    return threshold


def _load_int_env(name: str, default: int) -> int:
    value = os.getenv(name)

    if value is None or not value.strip():
        return default

    try:
        return int(value)
    except ValueError as error:
        raise ValueError(f"{name} must be an integer") from error


def _load_threshold_value(
    field_name: str,
    default: int,
    overrides: dict[str, int],
) -> int:
    if field_name in overrides:
        return overrides[field_name]

    return _load_int_env(_RISK_THRESHOLD_ENV_NAMES[field_name], default)


def load_dns_risk_thresholds(
    default: ThresholdConfig = DEFAULT_DNS_RISK_THRESHOLDS,
    overrides: dict[str, int] | None = None,
) -> ThresholdConfig:
    """Load validated risk decision thresholds from environment values."""
    load_env_file()
    threshold_overrides = overrides or {}
    threshold_config = ThresholdConfig(
        low_suspicious_threshold=_load_threshold_value(
            "low_suspicious_threshold",
            default.low_suspicious_threshold,
            threshold_overrides,
        ),
        alert_threshold=_load_threshold_value(
            "alert_threshold",
            default.alert_threshold,
            threshold_overrides,
        ),
        strong_alert_threshold=_load_threshold_value(
            "strong_alert_threshold",
            default.strong_alert_threshold,
            threshold_overrides,
        ),
        quarantine_threshold=_load_threshold_value(
            "quarantine_threshold",
            default.quarantine_threshold,
            threshold_overrides,
        ),
        containment_threshold=_load_threshold_value(
            "containment_threshold",
            default.containment_threshold,
            threshold_overrides,
        ),
    )
    validate_thresholds(threshold_config)

    return threshold_config


def load_dns_interface(default: str | None = DEFAULT_DNS_INTERFACE) -> str | None:
    """Load the optional network interface name."""
    load_env_file()
    value = os.getenv("DNS_INTERFACE")

    if value is None:
        return default

    cleaned_value = value.strip()
    return cleaned_value or default


def load_dns_debug(default: bool = DEFAULT_DNS_DEBUG) -> bool:
    """Load a boolean debug flag."""
    load_env_file()
    value = os.getenv("DNS_DEBUG")

    if value is None:
        return default

    normalized_value = value.strip().lower()

    if normalized_value in _TRUE_VALUES:
        return True

    if normalized_value in _FALSE_VALUES:
        return False

    return default


def load_enable_persistence(default: bool = DEFAULT_ENABLE_PERSISTENCE) -> bool:
    """Load whether SQLite persistence should be enabled."""
    load_env_file()
    value = os.getenv("ENABLE_PERSISTENCE")

    if value is None:
        return default

    normalized_value = value.strip().lower()

    if normalized_value in _TRUE_VALUES:
        return True

    if normalized_value in _FALSE_VALUES:
        return False

    return default


def load_database_path(default: str = DEFAULT_DATABASE_PATH) -> str:
    """Load the SQLite database path."""
    load_env_file()
    value = os.getenv("DATABASE_PATH")

    if value is None:
        return default

    cleaned_value = value.strip()
    return cleaned_value or default

