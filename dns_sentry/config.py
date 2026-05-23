"""Simple environment-based configuration for DNS-Sentry."""

import os
from pathlib import Path

DEFAULT_DNS_ENTROPY_THRESHOLD = 3.5
DEFAULT_DNS_INTERFACE: str | None = None
DEFAULT_DNS_DEBUG = False

_ENV_FILE = ".env"
_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}


def load_env_file(path: str | Path = _ENV_FILE) -> None:
    """Load simple KEY=value pairs from a .env file without overriding env vars."""
    env_path = Path(path)

    if not env_path.exists():
        return

    try:
        lines = env_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return

    for line in lines:
        stripped_line = line.strip()

        if not stripped_line or stripped_line.startswith("#"):
            continue

        if "=" not in stripped_line:
            continue

        key, value = stripped_line.split("=", 1)
        key = key.strip()

        if not key or key in os.environ:
            continue

        os.environ[key] = _clean_env_value(value.strip())


def _clean_env_value(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]

    return value


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

