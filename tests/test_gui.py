import logging

from dns_sentry import gui

TEST_WEBHOOK_URL = "https://example.test/webhook"


def test_gui_module_imports_without_running_window() -> None:
    assert callable(gui.run_gui)


def test_gui_log_handler_masks_webhook_values() -> None:
    log_queue: gui.Queue[str] = gui.Queue()
    handler = gui._GuiLogHandler(log_queue)
    record = logging.LogRecord(
        name="dns_sentry",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="webhook=%s",
        args=(TEST_WEBHOOK_URL,),
        exc_info=None,
    )

    handler.emit(record)

    output = log_queue.get_nowait()

    assert TEST_WEBHOOK_URL not in output
    assert "webhook=[redacted]" in output


def test_parse_threshold_rejects_invalid_value() -> None:
    try:
        gui._parse_threshold("-1")
    except ValueError:
        pass
    else:
        raise AssertionError("negative threshold should fail")

