"""Minimal logging setup for DNS-Sentry."""

import logging
import re
import sys

LOGGER_NAME = "dns_sentry"

_SENSITIVE_WORDS = (
    "webhook",
    "token",
    "secret",
    "password",
    "api_key",
    "apikey",
    "credential",
)
_URL_PATTERN = re.compile(r"https?://[^\s]+", re.IGNORECASE)
_SENSITIVE_ASSIGNMENT_PATTERN = re.compile(
    r"\b("
    r"DISCORD_WEBHOOK_URL|WEBHOOK|TOKEN|SECRET|PASSWORD|API_KEY|APIKEY|CREDENTIAL"
    r")\s*[:=]\s*[^,\s]+",
    re.IGNORECASE,
)


def _has_sensitive_context(value: str) -> bool:
    lowered_value = value.lower()
    return any(word in lowered_value for word in _SENSITIVE_WORDS)


def mask_sensitive_text(value: str) -> str:
    """Mask obvious secret-like values from log messages."""
    masked_value = _SENSITIVE_ASSIGNMENT_PATTERN.sub(r"\1=[redacted]", value)

    if _has_sensitive_context(masked_value):
        masked_value = _URL_PATTERN.sub("[redacted]", masked_value)

    return masked_value


class _SensitiveDataFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except (TypeError, ValueError):
            message = str(record.msg)

        record.msg = mask_sensitive_text(message)
        record.args = ()

        return True


def setup_logging(debug: bool = False) -> logging.Logger:
    """Configure and return the DNS-Sentry logger."""
    level = logging.DEBUG if debug else logging.INFO
    logger = logging.getLogger(LOGGER_NAME)
    formatter = logging.Formatter("[%(levelname)s] %(message)s")
    handler = logging.StreamHandler(sys.stdout)

    handler.setLevel(level)
    handler.setFormatter(formatter)
    handler.addFilter(_SensitiveDataFilter())

    logger.handlers.clear()
    logger.filters.clear()
    logger.setLevel(level)
    logger.addHandler(handler)
    logger.addFilter(_SensitiveDataFilter())
    logger.propagate = False

    return logger
