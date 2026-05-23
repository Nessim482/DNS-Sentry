from dns_sentry.logging_config import setup_logging

TEST_WEBHOOK_URL = "https://example.test/webhook/demo-value"


def test_setup_logging_uses_info_by_default(capsys) -> None:
    logger = setup_logging()

    logger.debug("hidden debug message")
    logger.info("visible info message")
    output = capsys.readouterr().out

    assert "visible info message" in output
    assert "hidden debug message" not in output


def test_setup_logging_enables_debug(capsys) -> None:
    logger = setup_logging(debug=True)

    logger.debug("visible debug message")
    output = capsys.readouterr().out

    assert "[DEBUG] visible debug message" in output


def test_setup_logging_masks_webhook_values(capsys) -> None:
    logger = setup_logging(debug=True)

    logger.info("webhook=%s", TEST_WEBHOOK_URL)
    output = capsys.readouterr().out

    assert TEST_WEBHOOK_URL not in output
    assert "webhook=[redacted]" in output


def test_setup_logging_keeps_readable_format(capsys) -> None:
    logger = setup_logging()

    logger.info("DNS-Sentry starting")
    output = capsys.readouterr().out

    assert "[INFO] DNS-Sentry starting" in output
