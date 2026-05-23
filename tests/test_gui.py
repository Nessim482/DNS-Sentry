import logging
from pathlib import Path

from dns_sentry import gui

TEST_WEBHOOK_URL = "https://example.test/webhook"


def test_gui_module_imports_without_running_window() -> None:
    assert callable(gui.run_gui)


def test_gui_default_threshold_is_four() -> None:
    assert gui.DEFAULT_GUI_THRESHOLD == 4.0


def test_gui_resolve_icon_path_when_icon_exists(
    monkeypatch, tmp_path: Path
) -> None:
    icon_path = tmp_path / "assets" / "dns-sentry.ico"
    icon_path.parent.mkdir()
    icon_path.write_bytes(b"icon")
    monkeypatch.setattr(gui, "_project_root", lambda: tmp_path)

    assert gui.resolve_icon_path() == icon_path


def test_gui_resolve_icon_path_when_icon_is_missing(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(gui, "_project_root", lambda: tmp_path)

    assert gui.resolve_icon_path() is None


def test_gui_missing_icon_does_not_call_tk_iconbitmap(
    monkeypatch, tmp_path: Path
) -> None:
    class FakeRoot:
        def iconbitmap(self, default: str) -> None:
            raise AssertionError("iconbitmap should not be called without icon")

    monkeypatch.setattr(gui, "_project_root", lambda: tmp_path)

    gui._apply_window_icon(FakeRoot())


def test_gui_taskbar_icon_helper_is_safe_outside_windows(monkeypatch) -> None:
    monkeypatch.setattr(gui.sys, "platform", "linux")

    gui._configure_windows_taskbar_icon()


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


def test_gui_log_handler_keeps_scoring_fields_and_masks_webhook() -> None:
    log_queue: gui.Queue[str] = gui.Queue()
    handler = gui._GuiLogHandler(log_queue)
    record = logging.LogRecord(
        name="dns_sentry",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg=(
            "risk_score=%s severity=%s action=%s quarantined=%s "
            "containment_required=%s webhook=%s"
        ),
        args=(55, "Suspicious", "alert", True, False, TEST_WEBHOOK_URL),
        exc_info=None,
    )

    handler.emit(record)

    output = log_queue.get_nowait()

    assert "risk_score=55 severity=Suspicious action=alert" in output
    assert "quarantined=True containment_required=False" in output
    assert TEST_WEBHOOK_URL not in output
    assert "webhook=[redacted]" in output


def test_parse_threshold_rejects_invalid_value() -> None:
    try:
        gui._parse_threshold("-1")
    except ValueError:
        pass
    else:
        raise AssertionError("negative threshold should fail")

